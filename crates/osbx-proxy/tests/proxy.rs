//! End-to-end proxy tests with local upstreams (no external network).

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use osbx_policy::{Action, HttpMatch, Origin, PolicySet, Preset, Rule};
use osbx_proxy::{Ca, ConnectFuture, Credentials, NoCredentials, ProxyConfig, Upstream, serve};
use osbx_secrets::InjectRule;
use rustls::pki_types::ServerName;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HOST: &str = "api.example.test";
const REAL: &str = "ghp_REALSECRET";

/// Sends every connection to one local address and counts them.
struct Fixed(SocketAddr, Arc<AtomicUsize>);
impl Upstream for Fixed {
    fn connect<'a>(&'a self, _h: &'a str, _p: u16) -> ConnectFuture<'a> {
        self.1.fetch_add(1, Ordering::SeqCst);
        let addr = self.0;
        Box::pin(async move { TcpStream::connect(addr).await })
    }
}

struct OneCred;
impl Credentials for OneCred {
    fn for_host(&self, host: &str) -> Option<(Vec<InjectRule>, String)> {
        (host == HOST).then(|| {
            (
                vec![InjectRule {
                    domain: HOST.into(),
                    header: "Authorization".into(),
                    format: "Bearer %s".into(),
                    basic_user: None,
                }],
                REAL.to_owned(),
            )
        })
    }
}

async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// HTTP service that reports what it received.
async fn report(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let h = |n: &str| {
        req.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none")
            .to_owned()
    };
    let msg = format!(
        "auth={};host={};path={};method={}",
        h("authorization"),
        h("host"),
        req.uri(),
        req.method()
    );
    Ok(Response::new(Full::new(Bytes::from(msg))))
}

async fn https_upstream(ca: &Ca, host: &str) -> SocketAddr {
    let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(host).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service_fn(report))
                        .await;
                }
            });
        }
    });
    addr
}

async fn http_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(report))
                    .await;
            });
        }
    });
    addr
}

fn client_trusting(ca: &Ca) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

struct Harness {
    proxy: SocketAddr,
    proxy_ca: Arc<Ca>,
    policy: Arc<RwLock<PolicySet>>,
    upstream_hits: Arc<AtomicUsize>,
}

async fn start(
    policy: PolicySet,
    upstream: SocketAddr,
    creds: Arc<dyn Credentials>,
    trust_upstream: Option<&Ca>,
) -> Harness {
    let proxy_ca = Arc::new(Ca::generate("osbx proxy test CA").unwrap());
    let policy = Arc::new(RwLock::new(policy));
    let hits = Arc::new(AtomicUsize::new(0));
    let client_tls = match trust_upstream {
        Some(ca) => client_trusting(ca),
        None => osbx_proxy::web_pki_client_config(),
    };
    let cfg = Arc::new(ProxyConfig {
        sandbox: "sb".into(),
        policy: policy.clone(),
        credentials: creds,
        upstream: Arc::new(Fixed(upstream, hits.clone())),
        ca: proxy_ca.clone(),
        client_tls,
        approve: None,
        events: None,
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = l.local_addr().unwrap();
    tokio::spawn(serve(l, cfg));
    Harness {
        proxy,
        proxy_ca,
        policy,
        upstream_hits: hits,
    }
}

/// Send CONNECT and return (status line, remaining stream).
async fn connect_via(proxy: SocketAddr, target: &str) -> (String, TcpStream) {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connect_via_inner(proxy, target),
    )
    .await
    .expect("CONNECT timed out")
}

async fn connect_via_inner(proxy: SocketAddr, target: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    let text = String::from_utf8(head).unwrap();
    (text.lines().next().unwrap().to_owned(), s)
}

/// Do one HTTPS request through an intercepted tunnel; returns (status, body).
async fn https_get(
    h: &Harness,
    host: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    host_header: &str,
) -> (u16, String) {
    let (status, s) = connect_via(h.proxy, &format!("{host}:443")).await;
    assert!(status.contains("200"), "CONNECT failed: {status}");
    let tls = tokio_rustls::TlsConnector::from(client_trusting(&h.proxy_ca))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), s)
        .await
        .expect("sandbox must trust the proxy CA");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host_header);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = sender
        .send_request(req.body(Empty::<Bytes>::new()).unwrap())
        .await
        .unwrap();
    let code = resp.status().as_u16();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (code, body)
}

fn rule(a: Action, d: &str) -> Rule {
    Rule::new(a, d, Origin::Local).unwrap()
}

#[tokio::test]
async fn allowed_destination_is_a_blind_tunnel() {
    let echo = echo_server().await;
    let h = start(
        PolicySet::new(Preset::AllowAll),
        echo,
        Arc::new(NoCredentials),
        None,
    )
    .await;
    let (status, mut s) = connect_via(h.proxy, "anything.example:5432").await;
    assert!(status.contains("200"), "{status}");
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn denied_destination_never_reaches_upstream() {
    let echo = echo_server().await;
    let mut p = PolicySet::new(Preset::AllowAll);
    p.rules.push(rule(Action::Deny, "evil.example"));
    let h = start(p, echo, Arc::new(NoCredentials), None).await;
    let (status, mut s) = connect_via(h.proxy, "evil.example:443").await;
    assert!(status.contains("403"), "{status}");
    // the 403 keeps the connection alive, so read exactly the body instead of to EOF
    let want = "Blocked by network policy\n";
    let mut rest = vec![0u8; want.len()];
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut rest))
        .await
        .expect("body")
        .unwrap();
    assert_eq!(String::from_utf8(rest).unwrap(), want);
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deny_by_default_and_live_policy_updates() {
    let echo = echo_server().await;
    let h = start(
        PolicySet::new(Preset::DenyAll),
        echo,
        Arc::new(NoCredentials),
        None,
    )
    .await;
    let (status, _) = connect_via(h.proxy, "ok.example:443").await;
    assert!(status.contains("403"), "deny-all must refuse: {status}"); // NeedsApproval without a handler
    h.policy
        .write()
        .unwrap()
        .rules
        .push(rule(Action::Allow, "ok.example"));
    let (status, _) = connect_via(h.proxy, "ok.example:443").await;
    assert!(status.contains("200"), "{status}");
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn intercept_replaces_sentinel_with_real_credential() {
    let up_ca = Ca::generate("upstream CA").unwrap();
    let up = https_upstream(&up_ca, HOST).await;
    let h = start(
        PolicySet::new(Preset::AllowAll),
        up,
        Arc::new(OneCred),
        Some(&up_ca),
    )
    .await;
    let (code, body) = https_get(
        &h,
        HOST,
        "GET",
        "/user",
        &[("authorization", "Bearer proxy-managed")],
        HOST,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert!(
        body.contains(&format!("auth=Bearer {REAL}")),
        "upstream must see the real credential: {body}"
    );
    assert!(!body.contains("proxy-managed"), "{body}");
    assert!(body.contains("path=/user"), "{body}");
}

#[tokio::test]
async fn http_level_rules_apply_per_request() {
    let up_ca = Ca::generate("upstream CA").unwrap();
    let up = https_upstream(&up_ca, HOST).await;
    let mut p = PolicySet::new(Preset::DenyAll);
    let mut r = rule(Action::Allow, HOST);
    r.http = Some(HttpMatch {
        methods: vec!["GET".into()],
        path: Some("/v1/*".into()),
        query: vec![],
    });
    p.rules.push(r);
    let h = start(p, up, Arc::new(NoCredentials), Some(&up_ca)).await;
    // CONNECT to a host whose only rule is HTTP-constrained is allowed to proceed to inspection
    let (code, _) = https_get(&h, HOST, "GET", "/v1/models", &[], HOST).await;
    assert_eq!(code, 200);
    let (code, body) = https_get(&h, HOST, "POST", "/v1/models", &[], HOST).await;
    assert_eq!(code, 403, "{body}"); // method not allowed
    let (code, _) = https_get(&h, HOST, "GET", "/v2/models", &[], HOST).await;
    assert_eq!(code, 403); // path not allowed
}

#[tokio::test]
async fn host_header_cannot_borrow_another_hosts_credential() {
    let up_ca = Ca::generate("upstream CA").unwrap();
    let up = https_upstream(&up_ca, HOST).await;
    let h = start(
        PolicySet::new(Preset::AllowAll),
        up,
        Arc::new(OneCred),
        Some(&up_ca),
    )
    .await;
    let (code, body) = https_get(&h, HOST, "GET", "/", &[], "other.example").await;
    assert_eq!(code, 421, "{body}");
    assert!(!body.contains(REAL));
}

#[tokio::test]
async fn untrusted_upstream_certificate_is_refused() {
    let up_ca = Ca::generate("upstream CA").unwrap();
    let up = https_upstream(&up_ca, HOST).await;
    // proxy trusts only the public web PKI, so the test upstream's cert must be rejected
    let h = start(
        PolicySet::new(Preset::AllowAll),
        up,
        Arc::new(OneCred),
        None,
    )
    .await;
    let (code, body) = https_get(
        &h,
        HOST,
        "GET",
        "/",
        &[("authorization", "Bearer proxy-managed")],
        HOST,
    )
    .await;
    assert_eq!(code, 502, "{body}");
    assert!(!body.contains(REAL));
}

#[tokio::test]
async fn plaintext_http_is_policed_but_never_receives_credentials() {
    let up = http_upstream().await;
    let h = start(
        PolicySet::new(Preset::AllowAll),
        up,
        Arc::new(OneCred),
        None,
    )
    .await;
    let mut s = TcpStream::connect(h.proxy).await.unwrap();
    let req = format!(
        "GET http://{HOST}/x HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer proxy-managed\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.contains("200"), "{out}");
    assert!(
        out.contains("auth=Bearer proxy-managed"),
        "sentinel passes through untouched: {out}"
    );
    assert!(
        !out.contains(REAL),
        "a secret must never be sent over plaintext HTTP: {out}"
    );
}

#[tokio::test]
async fn approval_callback_and_events() {
    let echo = echo_server().await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let proxy_ca = Arc::new(Ca::generate("ca").unwrap());
    let cfg = Arc::new(ProxyConfig {
        sandbox: "sb".into(),
        policy: Arc::new(RwLock::new(PolicySet::new(Preset::DenyAll))),
        credentials: Arc::new(NoCredentials),
        upstream: Arc::new(Fixed(echo, Arc::new(AtomicUsize::new(0)))),
        ca: proxy_ca,
        client_tls: osbx_proxy::web_pki_client_config(),
        approve: Some(Arc::new(|host, _| host == "approved.example")),
        events: Some(tx),
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = l.local_addr().unwrap();
    tokio::spawn(serve(l, cfg));
    let (ok, _) = connect_via(proxy, "approved.example:443").await;
    let (no, _) = connect_via(proxy, "refused.example:443").await;
    assert!(ok.contains("200") && no.contains("403"), "{ok} / {no}");
    let e1 = rx.recv().await.unwrap();
    assert_eq!(
        (e1.host.as_str(), e1.decision),
        ("approved.example", osbx_policy::Decision::NeedsApproval)
    );
    assert_eq!(rx.recv().await.unwrap().host, "refused.example");
}

// ---- OAuth (credential@1 oauth): the guest only ever holds placeholders ----------------------

use osbx_proxy::{OAuthSpec, OAuthTokens};
use std::sync::Mutex;

const OAUTH_HOST: &str = "auth.example.test";
const AS: &str = "sk-ant-oat01-proxy-managed";
const RS: &str = "sk-ant-ort01-proxy-managed";

struct OAuthCreds(Mutex<Option<OAuthTokens>>);
impl Credentials for OAuthCreds {
    fn for_host(&self, _: &str) -> Option<(Vec<InjectRule>, String)> {
        None
    }
    fn oauth_for_host(&self, host: &str) -> Option<OAuthSpec> {
        (host == OAUTH_HOST).then(|| OAuthSpec {
            service: "anthropic".into(),
            token_host: OAUTH_HOST.into(),
            token_path: "/v1/oauth/token".into(),
            resource_hosts: vec![OAUTH_HOST.into()],
            access_sentinel: AS.into(),
            refresh_sentinel: RS.into(),
        })
    }
    fn oauth_tokens(&self, _: &str) -> Option<OAuthTokens> {
        self.0.lock().unwrap().clone()
    }
    fn oauth_save(&self, _: &str, t: &OAuthTokens) {
        *self.0.lock().unwrap() = Some(t.clone());
    }
}

/// A fake authorization server: issues REAL-ACCESS-n / REAL-REFRESH-n and reports bearers.
async fn oauth_provider(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none")
        .to_owned();
    let path = req.uri().path().to_owned();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let reply = if path == "/v1/oauth/token" {
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        match v["grant_type"].as_str() {
            Some("authorization_code") => r#"{"access_token":"REAL-ACCESS-1","refresh_token":"REAL-REFRESH-1","expires_in":3600,"scope":"user:inference user:profile","account":{"uuid":"a1"}}"#.to_owned(),
            Some("refresh_token") if v["refresh_token"] == "REAL-REFRESH-1" => r#"{"access_token":"REAL-ACCESS-2","refresh_token":"REAL-REFRESH-2","expires_in":3600}"#.to_owned(),
            _ => format!(r#"{{"error":"invalid_grant","got":{}}}"#, v["refresh_token"]),
        }
    } else {
        format!("bearer={auth}")
    };
    Ok(Response::new(Full::new(Bytes::from(reply))))
}

async fn https_server(ca: &Ca, host: &str) -> SocketAddr {
    let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(host).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service_fn(oauth_provider))
                        .await;
                }
            });
        }
    });
    addr
}

async fn https_req(
    h: &Harness,
    method: &str,
    path: &str,
    auth: Option<&str>,
    json: Option<&str>,
) -> (u16, String) {
    let (status, s) = connect_via(h.proxy, &format!("{OAUTH_HOST}:443")).await;
    assert!(status.contains("200"), "{status}");
    let tls = tokio_rustls::TlsConnector::from(client_trusting(&h.proxy_ca))
        .connect(ServerName::try_from(OAUTH_HOST.to_owned()).unwrap(), s)
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", OAUTH_HOST);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let body = match json {
        Some(j) => {
            b = b.header("content-type", "application/json");
            Full::new(Bytes::from(j.to_owned()))
        }
        None => Full::new(Bytes::new()),
    };
    let resp = sender.send_request(b.body(body).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    (
        code,
        String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn oauth_tokens_stay_on_the_host() {
    let up_ca = Ca::generate("oauth upstream CA").unwrap();
    let up = https_server(&up_ca, OAUTH_HOST).await;
    let creds = Arc::new(OAuthCreds(Mutex::new(None)));
    let h = start(
        PolicySet::new(Preset::AllowAll),
        up,
        creds.clone(),
        Some(&up_ca),
    )
    .await;

    // first login: the guest exchanges a code and receives only placeholders
    let (code, body) = https_req(
        &h,
        "POST",
        "/v1/oauth/token",
        None,
        Some(r#"{"grant_type":"authorization_code","code":"abc"}"#),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (v["access_token"].as_str(), v["refresh_token"].as_str()),
        (Some(AS), Some(RS))
    );
    assert_eq!(
        v["account"]["uuid"], "a1",
        "the rest of the response passes through"
    );
    assert!(!body.contains("REAL-"), "{body}");
    let stored = creds
        .0
        .lock()
        .unwrap()
        .clone()
        .expect("tokens captured on the host");
    assert_eq!(
        (
            stored.access_token.as_str(),
            stored.refresh_token.as_deref()
        ),
        ("REAL-ACCESS-1", Some("REAL-REFRESH-1"))
    );
    assert_eq!(stored.scopes, ["user:inference", "user:profile"]);
    assert!(stored.expires_at_ms.is_some());

    // using the placeholder bearer: the upstream sees the real token
    let (_, body) = https_req(&h, "GET", "/v1/me", Some(&format!("Bearer {AS}")), None).await;
    assert_eq!(body, "bearer=Bearer REAL-ACCESS-1");

    // refresh with the placeholder refresh token: the upstream gets the real one
    let (code, body) = https_req(
        &h,
        "POST",
        "/v1/oauth/token",
        None,
        Some(&format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{RS}"}}"#
        )),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(AS) && !body.contains("REAL-"), "{body}");
    assert_eq!(
        creds.0.lock().unwrap().as_ref().unwrap().access_token,
        "REAL-ACCESS-2"
    );
    let (_, body) = https_req(&h, "GET", "/v1/me", Some(&format!("Bearer {AS}")), None).await;
    assert_eq!(body, "bearer=Bearer REAL-ACCESS-2");
}
