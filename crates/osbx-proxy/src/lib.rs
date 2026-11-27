//! Policy-enforcing egress proxy.
//!
//! The sandbox's only route out is this proxy. For each `CONNECT host:port`:
//! 1. the destination is checked against the [`PolicySet`] (deny wins, deny-by-default);
//! 2. if nothing needs to look inside the connection, it becomes a blind tunnel;
//! 3. if the host has credentials to inject or HTTP-level rules, TLS is terminated with a
//!    per-sandbox CA ([`Ca`]), every request is re-checked with method/path/query, the real
//!    credential replaces the sandbox's placeholder, and the request is forwarded upstream
//!    over verified TLS.
//!
//! Security properties enforced here: the CONNECT target (not the inner `Host` header)
//! decides policy and credentials; secrets are injected only over TLS, never into
//! plaintext HTTP; upgrade requests are refused on intercepted connections.

mod ca;

pub use ca::Ca;
pub use rustls::ClientConfig;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{HOST, HeaderName, HeaderValue};
use hyper::server::conn::http1 as server1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use osbx_policy::{Decision, HttpRequest, PolicySet, Request as NetRequest};
use osbx_secrets::{InjectRule, inject};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

/// Body type used for every response.
pub type Body = BoxBody<Bytes, hyper::Error>;

/// Credentials the proxy may inject, per destination host.
pub trait Credentials: Send + Sync {
    /// Injection rules and the real secret for `host`, if a credential is bound to it.
    fn for_host(&self, host: &str) -> Option<(Vec<InjectRule>, String)>;

    /// OAuth handled by the proxy for `host` (its token endpoint or one of its resource hosts).
    fn oauth_for_host(&self, _host: &str) -> Option<OAuthSpec> {
        None
    }
    /// The real tokens stored on the host for an OAuth service.
    fn oauth_tokens(&self, _service: &str) -> Option<OAuthTokens> {
        None
    }
    /// Store tokens captured from a token-endpoint response.
    fn oauth_save(&self, _service: &str, _tokens: &OAuthTokens) {}
}

/// A `credential@1` OAuth presentation: the guest only ever sees the sentinels; the proxy
/// captures real tokens at the token endpoint and swaps them back in on resource hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSpec {
    /// Credential-store service.
    pub service: String,
    /// Token endpoint host.
    pub token_host: String,
    /// Token endpoint path.
    pub token_path: String,
    /// Hosts where the bearer token is used.
    pub resource_hosts: Vec<String>,
    /// Placeholder access token shown to the guest.
    pub access_sentinel: String,
    /// Placeholder refresh token shown to the guest.
    pub refresh_sentinel: String,
}

/// Real OAuth tokens (host side only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthTokens {
    /// Access token.
    pub access_token: String,
    /// Refresh token.
    pub refresh_token: Option<String>,
    /// Expiry, Unix milliseconds.
    pub expires_at_ms: Option<u64>,
    /// Granted scopes.
    pub scopes: Vec<String>,
}

/// No credentials.
pub struct NoCredentials;
impl Credentials for NoCredentials {
    fn for_host(&self, _host: &str) -> Option<(Vec<InjectRule>, String)> {
        None
    }
}

/// Future returned by [`Upstream::connect`].
pub type ConnectFuture<'a> = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>>;

/// Opens upstream TCP connections (replaceable for tests and for host-network quirks).
pub trait Upstream: Send + Sync {
    /// Connect to `host:port`.
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> ConnectFuture<'a>;
}

/// Resolves names itself and refuses addresses that a policy *deny* rule covers, so a
/// name that resolves into a denied CIDR (e.g. link-local metadata) cannot be reached.
pub struct DirectUpstream {
    /// Policy consulted for IP-based denies.
    pub policy: Arc<RwLock<PolicySet>>,
    /// Sandbox name (for sandbox-scoped rules).
    pub sandbox: String,
    /// Give up on a connection attempt after this long (docs: 30 s default).
    pub timeout: Duration,
}

impl Upstream for DirectUpstream {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> ConnectFuture<'a> {
        Box::pin(async move {
            let addrs: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
            let mut last = io::Error::new(io::ErrorKind::NotFound, "no addresses");
            for a in addrs {
                let denied = {
                    let p = self.policy.read().unwrap();
                    let req = NetRequest {
                        host,
                        ip: Some(a.ip()),
                        port,
                        http: None,
                    };
                    matches!(p.evaluate(&self.sandbox, &req), Decision::Deny(_))
                };
                if denied {
                    last = io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("{} is denied by policy", a.ip()),
                    );
                    continue;
                }
                match tokio::time::timeout(self.timeout, TcpStream::connect(a)).await {
                    Ok(Ok(s)) => return Ok(s),
                    Ok(Err(e)) => last = e,
                    Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
                }
            }
            Err(last)
        })
    }
}

/// One policy decision, for logs and UIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Destination host.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// HTTP method and path when the request was inspected.
    pub http: Option<(String, String)>,
    /// What was decided.
    pub decision: Decision,
}

/// Callback asked when a destination needs interactive approval. Returns `true` to allow
/// this connection.
pub type ApprovalFn = dyn Fn(&str, u16) -> bool + Send + Sync;

/// Everything a proxy instance needs.
pub struct ProxyConfig {
    /// Sandbox this proxy serves.
    pub sandbox: String,
    /// Live policy (writers may update it while the proxy runs).
    pub policy: Arc<RwLock<PolicySet>>,
    /// Credential source.
    pub credentials: Arc<dyn Credentials>,
    /// Upstream connector.
    pub upstream: Arc<dyn Upstream>,
    /// CA for TLS interception.
    pub ca: Arc<Ca>,
    /// TLS client config used to reach upstream servers (must verify certificates).
    pub client_tls: Arc<rustls::ClientConfig>,
    /// Interactive approval, if any. Without it, `NeedsApproval` is refused.
    pub approve: Option<Arc<ApprovalFn>>,
    /// Decision events.
    pub events: Option<mpsc::UnboundedSender<Event>>,
}

/// A TLS client config trusting the public web PKI (system-independent).
pub fn web_pki_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    Arc::new(cfg)
}

fn body(msg: impl Into<Bytes>) -> Body {
    Full::new(msg.into())
        .map_err(|never| match never {})
        .boxed()
}
fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
fn reply(status: StatusCode, msg: &str) -> Response<Body> {
    let mut r = Response::new(body(format!("{msg}\n")));
    *r.status_mut() = status;
    r.headers_mut()
        .insert("x-osbx-policy", HeaderValue::from_static("blocked"));
    r
}

enum Verdict {
    Allow,
    Block(String),
}

impl ProxyConfig {
    fn emit(&self, host: &str, port: u16, http: Option<(String, String)>, decision: &Decision) {
        if let Some(tx) = &self.events {
            let _ = tx.send(Event {
                host: host.to_owned(),
                port,
                http,
                decision: decision.clone(),
            });
        }
    }

    /// Decision at CONNECT time, before any HTTP is visible. A host whose rules include
    /// HTTP-level constraints cannot be judged yet: unless something explicitly denies it,
    /// let it proceed to inspection, where every request is decided on its own.
    fn decide_connect(&self, host: &str, port: u16) -> Verdict {
        let defer = {
            let p = self.policy.read().unwrap();
            let d = p.evaluate(
                &self.sandbox,
                &NetRequest {
                    host,
                    ip: host.parse().ok(),
                    port,
                    http: None,
                },
            );
            let undecided = matches!(
                d,
                Decision::NeedsApproval | Decision::Deny(osbx_policy::Reason::OrgPolicy)
            );
            undecided && p.needs_http_inspection(&self.sandbox, host, port)
        };
        if defer {
            Verdict::Allow
        } else {
            self.decide(host, port, None)
        }
    }

    /// Evaluate and, for `NeedsApproval`, consult the approval callback.
    fn decide(&self, host: &str, port: u16, http: Option<HttpRequest<'_>>) -> Verdict {
        let label = http
            .as_ref()
            .map(|h| (h.method.to_owned(), h.path.to_owned()));
        let (decision, msg) = {
            let p = self.policy.read().unwrap();
            let d = p.evaluate(
                &self.sandbox,
                &NetRequest {
                    host,
                    ip: host.parse().ok(),
                    port,
                    http,
                },
            );
            let m = p.block_message(&d);
            (d, m)
        };
        self.emit(host, port, label, &decision);
        match decision {
            Decision::Allow(_) => Verdict::Allow,
            Decision::NeedsApproval if self.approve.as_ref().is_some_and(|f| f(host, port)) => {
                Verdict::Allow
            }
            _ => Verdict::Block(msg.unwrap_or_else(|| "Blocked by network policy".into())),
        }
    }

    fn must_intercept(&self, host: &str, port: u16) -> bool {
        self.credentials.for_host(host).is_some()
            || self.credentials.oauth_for_host(host).is_some()
            || self
                .policy
                .read()
                .unwrap()
                .needs_http_inspection(&self.sandbox, host, port)
    }
}

/// Serve the proxy protocol on one already-connected stream (a TCP socket, or a vsock stream
/// bridged from a guest). Returns when the connection ends.
pub async fn serve_stream<I>(io: I, cfg: Arc<ProxyConfig>) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let cfg = cfg.clone();
        async move { Ok::<_, Infallible>(handle(cfg, req).await) }
    });
    server1::Builder::new()
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades()
        .await
}

/// Accept connections on `listener` forever, serving the proxy protocol.
pub async fn serve(listener: tokio::net::TcpListener, cfg: Arc<ProxyConfig>) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let _ = serve_stream(stream, cfg).await;
        });
    }
}

async fn handle(cfg: Arc<ProxyConfig>, req: Request<Incoming>) -> Response<Body> {
    if req.method() == Method::CONNECT {
        return connect(cfg, req).await;
    }
    // Plain HTTP via absolute-form URI. Never injects credentials (no TLS).
    let Some(auth) = req.uri().authority().cloned() else {
        return reply(
            StatusCode::BAD_REQUEST,
            "proxy requests need CONNECT or an absolute URI",
        );
    };
    if req.uri().scheme_str() != Some("http") {
        return reply(
            StatusCode::BAD_REQUEST,
            "only http:// absolute URIs are proxied; use CONNECT for https",
        );
    }
    let (host, port) = (auth.host().to_owned(), auth.port_u16().unwrap_or(80));
    if let Verdict::Block(m) = cfg.decide(&host, port, Some(http_view(&req))) {
        return reply(StatusCode::FORBIDDEN, &m);
    }
    forward(
        &cfg,
        &host,
        port,
        false,
        req.map(BodyExt::boxed),
        Vec::new(),
    )
    .await
}

async fn connect(cfg: Arc<ProxyConfig>, req: Request<Incoming>) -> Response<Body> {
    let Some(auth) = req.uri().authority().cloned() else {
        return reply(StatusCode::BAD_REQUEST, "CONNECT needs host:port");
    };
    let (host, port) = (
        auth.host().trim_matches(['[', ']']).to_ascii_lowercase(),
        auth.port_u16().unwrap_or(443),
    );
    if let Verdict::Block(m) = cfg.decide_connect(&host, port) {
        return reply(StatusCode::FORBIDDEN, &m);
    }
    if cfg.must_intercept(&host, port) {
        tokio::spawn(async move {
            if let Ok(up) = hyper::upgrade::on(req).await {
                let _ = intercept(cfg, TokioIo::new(up), host, port).await;
            }
        });
    } else {
        // Connect first so a dead upstream is a clean 502, not a hung tunnel.
        let mut upstream = match cfg.upstream.connect(&host, port).await {
            Ok(s) => s,
            Err(e) => {
                return reply(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream connect failed: {e}"),
                );
            }
        };
        tokio::spawn(async move {
            if let Ok(up) = hyper::upgrade::on(req).await {
                let mut io = TokioIo::new(up);
                let _ = tokio::io::copy_bidirectional(&mut io, &mut upstream).await;
            }
        });
    }
    Response::new(empty())
}

async fn intercept<I>(cfg: Arc<ProxyConfig>, io: I, host: String, port: u16) -> Result<(), String>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let acceptor = TlsAcceptor::from(cfg.ca.server_config(&host)?);
    let tls = acceptor.accept(io).await.map_err(|e| e.to_string())?;
    let svc = service_fn(move |req| {
        let (cfg, host) = (cfg.clone(), host.clone());
        async move { Ok::<_, Infallible>(inspected(cfg, host, port, req).await) }
    });
    server1::Builder::new()
        .serve_connection(TokioIo::new(tls), svc)
        .await
        .map_err(|e| e.to_string())
}

/// One request on an intercepted connection.
async fn inspected(
    cfg: Arc<ProxyConfig>,
    host: String,
    port: u16,
    req: Request<Incoming>,
) -> Response<Body> {
    // The CONNECT target decides policy and credentials. A different inner Host header is
    // an attempt to borrow another host's allowance or credential.
    let inner = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            h.rsplit_once(':')
                .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
                .map_or(h, |(n, _)| n)
                .to_ascii_lowercase()
        });
    if inner.as_deref() != Some(host.as_str()) {
        return reply(
            StatusCode::MISDIRECTED_REQUEST,
            "Host header does not match the CONNECT target",
        );
    }
    if req.headers().contains_key(hyper::header::UPGRADE) {
        return reply(
            StatusCode::NOT_IMPLEMENTED,
            "upgrade requests are not supported on intercepted connections",
        );
    }
    if let Verdict::Block(m) = cfg.decide(&host, port, Some(http_view(&req))) {
        return reply(StatusCode::FORBIDDEN, &m);
    }
    let mut headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(n, v)| {
            v.to_str()
                .ok()
                .map(|v| (n.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    if let Some((rules, secret)) = cfg.credentials.for_host(&host) {
        inject(&rules, &host, &secret, &mut headers);
    }
    if let Some(spec) = cfg.credentials.oauth_for_host(&host) {
        if host == spec.token_host
            && req.method() == Method::POST
            && req.uri().path() == spec.token_path
        {
            return oauth_token_exchange(&cfg, &host, port, &spec, req, headers).await;
        }
        // a resource host: the guest's placeholder bearer becomes the real access token
        if let Some(t) = cfg.credentials.oauth_tokens(&spec.service) {
            let placeholder = format!("Bearer {}", spec.access_sentinel);
            for (n, v) in &mut headers {
                if n.eq_ignore_ascii_case("authorization") && *v == placeholder {
                    *v = format!("Bearer {}", t.access_token);
                }
            }
        }
    }
    forward(&cfg, &host, port, true, req.map(BodyExt::boxed), headers).await
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The token endpoint: swap the guest's refresh-token placeholder for the real one on the way
/// out, capture the real tokens from the response and hand the guest placeholders instead.
async fn oauth_token_exchange(
    cfg: &ProxyConfig,
    host: &str,
    port: u16,
    spec: &OAuthSpec,
    req: Request<Incoming>,
    mut headers: Vec<(String, String)>,
) -> Response<Body> {
    let (parts, req_body) = req.into_parts();
    let Ok(collected) = http_body_util::Limited::new(req_body, 1 << 20)
        .collect()
        .await
    else {
        return reply(StatusCode::PAYLOAD_TOO_LARGE, "token request too large");
    };
    let raw = collected.to_bytes();
    let stored = cfg.credentials.oauth_tokens(&spec.service);
    let real_refresh = stored.as_ref().and_then(|t| t.refresh_token.clone());
    let is_json = headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("json"));
    let out_body: Vec<u8> = if is_json {
        match serde_json::from_slice::<serde_json::Value>(&raw) {
            Ok(mut v) => {
                if v.get("refresh_token").and_then(|r| r.as_str())
                    == Some(spec.refresh_sentinel.as_str())
                {
                    match &real_refresh {
                        Some(r) => v["refresh_token"] = serde_json::Value::String(r.clone()),
                        None => {
                            return reply(
                                StatusCode::UNAUTHORIZED,
                                "no stored login on the host: log in again",
                            );
                        }
                    }
                }
                serde_json::to_vec(&v).unwrap_or_else(|_| raw.to_vec())
            }
            Err(_) => raw.to_vec(),
        }
    } else {
        let text = String::from_utf8_lossy(&raw);
        let sentinel_pair = format!("refresh_token={}", spec.refresh_sentinel);
        if text.split('&').any(|p| p == sentinel_pair) {
            let Some(r) = &real_refresh else {
                return reply(
                    StatusCode::UNAUTHORIZED,
                    "no stored login on the host: log in again",
                );
            };
            text.split('&')
                .map(|p| {
                    if p == sentinel_pair {
                        format!("refresh_token={}", form_encode(r))
                    } else {
                        p.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
                .into_bytes()
        } else {
            raw.to_vec()
        }
    };
    // a plain-text response is needed to read and rewrite the tokens
    headers.retain(|(n, _)| {
        !n.eq_ignore_ascii_case("content-length") && !n.eq_ignore_ascii_case("accept-encoding")
    });
    headers.push(("content-length".into(), out_body.len().to_string()));
    let out = Request::from_parts(
        parts,
        Full::new(Bytes::from(out_body))
            .map_err(|never| match never {})
            .boxed(),
    );
    let resp = forward(cfg, host, port, true, out, headers).await;

    let (mut rparts, rbody) = resp.into_parts();
    let Ok(rcollected) = http_body_util::Limited::new(rbody, 1 << 20).collect().await else {
        return reply(
            StatusCode::BAD_GATEWAY,
            "token response too large or broken",
        );
    };
    let rbytes = rcollected.to_bytes();
    let mut new_body = rbytes.to_vec();
    if rparts.status.is_success()
        && let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&rbytes)
        && let Some(access) = v
            .get("access_token")
            .and_then(|a| a.as_str())
            .map(str::to_owned)
    {
        let refresh = v
            .get("refresh_token")
            .and_then(|r| r.as_str())
            .map(str::to_owned)
            .or(real_refresh);
        let expires_at_ms = v
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .map(|s| now_ms() + s * 1000);
        let scopes = v
            .get("scope")
            .and_then(|s| s.as_str())
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        cfg.credentials.oauth_save(
            &spec.service,
            &OAuthTokens {
                access_token: access,
                refresh_token: refresh,
                expires_at_ms,
                scopes,
            },
        );
        v["access_token"] = serde_json::Value::String(spec.access_sentinel.clone());
        if v.get("refresh_token").is_some() {
            v["refresh_token"] = serde_json::Value::String(spec.refresh_sentinel.clone());
        }
        new_body = serde_json::to_vec(&v).unwrap_or(new_body);
    }
    rparts.headers.remove(hyper::header::CONTENT_LENGTH);
    rparts.headers.remove(hyper::header::TRANSFER_ENCODING);
    if let Ok(len) = HeaderValue::from_str(&new_body.len().to_string()) {
        rparts.headers.insert(hyper::header::CONTENT_LENGTH, len);
    }
    Response::from_parts(rparts, body(new_body))
}

fn form_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn http_view<'a>(req: &'a Request<Incoming>) -> HttpRequest<'a> {
    let query = req
        .uri()
        .query()
        .map(|q| {
            q.split('&')
                .filter(|p| !p.is_empty())
                .map(|p| p.split_once('=').unwrap_or((p, "")))
                .collect()
        })
        .unwrap_or_default();
    HttpRequest {
        method: req.method().as_str(),
        path: req.uri().path(),
        query,
    }
}

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Send `req` upstream. When `rewritten` is non-empty it replaces the request headers
/// (so credential injection is what reaches the server).
async fn forward(
    cfg: &ProxyConfig,
    host: &str,
    port: u16,
    tls: bool,
    req: Request<Body>,
    rewritten: Vec<(String, String)>,
) -> Response<Body> {
    let (parts, incoming) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let mut b = Request::builder().method(parts.method).uri(path);
    let source: Vec<(String, String)> = if rewritten.is_empty() {
        parts
            .headers
            .iter()
            .filter_map(|(n, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (n.as_str().to_owned(), v.to_owned()))
            })
            .collect()
    } else {
        rewritten
    };
    for (n, v) in source {
        let lname = n.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) || lname == "host" {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(n.as_bytes()),
            HeaderValue::from_str(&v),
        ) {
            b = b.header(n, v);
        }
    }
    let host_hdr = if (tls && port == 443) || (!tls && port == 80) {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let out = match b.header(HOST, host_hdr).body(incoming) {
        Ok(r) => r,
        Err(e) => return reply(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };

    let tcp = match cfg.upstream.connect(host, port).await {
        Ok(s) => s,
        Err(e) => {
            return reply(
                StatusCode::BAD_GATEWAY,
                &format!("upstream connect failed: {e}"),
            );
        }
    };
    let result = if tls {
        let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_owned()) else {
            return reply(StatusCode::BAD_GATEWAY, "invalid upstream name");
        };
        match tokio_rustls::TlsConnector::from(cfg.client_tls.clone())
            .connect(name, tcp)
            .await
        {
            Ok(s) => send(TokioIo::new(s), out).await,
            Err(e) => {
                return reply(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream TLS failed: {e}"),
                );
            }
        }
    } else {
        send(TokioIo::new(tcp), out).await
    };
    match result {
        Ok(resp) => {
            let (mut parts, inc) = resp.into_parts();
            for h in HOP_BY_HOP {
                parts.headers.remove(h);
            }
            Response::from_parts(parts, inc.boxed())
        }
        Err(e) => reply(StatusCode::BAD_GATEWAY, &format!("upstream error: {e}")),
    }
}

async fn send<I>(io: I, req: Request<Body>) -> Result<Response<Incoming>, hyper::Error>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender.send_request(req).await
}
