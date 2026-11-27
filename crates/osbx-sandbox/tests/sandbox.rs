//! A whole sandbox: microVM + guest agent + policy proxy. Needs /dev/kvm and `guest/build-assets.sh
//! --with-osbx`; skips with a note otherwise.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use osbx_policy::{Action, Decision, Origin, PolicySet, Preset, Rule};
use osbx_proxy::{Ca, ConnectFuture, NoCredentials, Upstream, web_pki_client_config};
use osbx_sandbox::{Sandbox, SandboxConfig};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

fn assets() -> Option<(PathBuf, PathBuf)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest/assets");
    let (k, i) = (dir.join("vmlinuz"), dir.join("initramfs.cpio.gz"));
    if !k.exists() || !i.exists() {
        eprintln!("guest assets missing: run guest/build-assets.sh --with-osbx; skipping");
        return None;
    }
    if !osbx_vmm::probe().grantable() {
        eprintln!("no usable /dev/kvm: skipping");
        return None;
    }
    Some((k, i))
}

/// Removes a directory when dropped, including when a test assertion panics.
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sends every upstream connection to one local address.
struct Fixed(SocketAddr);
impl Upstream for Fixed {
    fn connect<'a>(&'a self, _h: &'a str, _p: u16) -> ConnectFuture<'a> {
        let a = self.0;
        Box::pin(async move { tokio::net::TcpStream::connect(a).await })
    }
}

async fn serve_hello(
    _: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from(
        "hello-from-host-server\n",
    ))))
}

fn http_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(l).unwrap();
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(s), service_fn(serve_hello))
                        .await;
                });
            }
        });
    });
    addr
}

struct Fixture {
    sb: Sandbox,
    events: tokio::sync::mpsc::UnboundedReceiver<osbx_proxy::Event>,
    policy: Arc<RwLock<PolicySet>>,
}

fn start(upstream: Option<SocketAddr>) -> Option<Fixture> {
    let (kernel, initrd) = assets()?;
    let policy = Arc::new(RwLock::new(PolicySet::new(Preset::DenyAll)));
    let (tx, events) = tokio::sync::mpsc::unbounded_channel();
    let sb = Sandbox::start(SandboxConfig {
        name: "t".into(),
        kernel,
        initrd,
        disks: vec![],
        extra_cmdline: String::new(),
        shares: vec![],
        mem_mib: 256,
        cpus: 2,
        policy: policy.clone(),
        credentials: Arc::new(NoCredentials),
        ca: Arc::new(Ca::generate("osbx test").unwrap()),
        env: BTreeMap::new(),
        upstream: upstream.map(|a| Arc::new(Fixed(a)) as Arc<dyn Upstream>),
        client_tls: Some(web_pki_client_config()),
        events: Some(tx),
    })
    .expect("start");
    sb.wait_ready(Duration::from_secs(60)).expect("agent ready");
    Some(Fixture { sb, events, policy })
}

#[test]
fn exec_runs_in_the_guest() {
    let Some(f) = start(None) else { return };
    // a terminal: the command sees a tty of the requested size, and stderr is merged into it
    let tty =
        f.sb.exec_request(
            osbx_proto::ExecRequest {
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "tty; stty size; echo to-stderr >&2".into(),
                ],
                tty: true,
                rows: 40,
                cols: 120,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    let text = tty.stdout_str().replace('\r', "");
    assert!(text.starts_with("/dev/pts/"), "{text:?}");
    assert!(
        text.contains("40 120\n") && text.contains("to-stderr"),
        "{text:?}"
    );
    let out =
        f.sb.exec(&["/bin/sh", "-c", "uname -s; echo $http_proxy"], None)
            .unwrap();
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout_str(), "Linux\nhttp://127.0.0.1:3128\n");
    assert_eq!(
        f.sb.shutdown(Duration::from_secs(15)),
        osbx_vmm::ExitReason::GuestReset
    );
}

#[test]
fn egress_is_policy_controlled() {
    let server = http_server();
    let Some(mut f) = start(Some(server)) else {
        return;
    };

    // deny-by-default: a request to an unlisted host is refused by the proxy and reported
    let blocked =
        f.sb.exec(&["/bin/wget", "-qO-", "http://blocked.example/"], None)
            .unwrap();
    assert_ne!(blocked.code, 0, "stdout: {}", blocked.stdout_str());
    let ev = loop {
        let e = f.events.blocking_recv().expect("an event");
        if e.host == "blocked.example" {
            break e;
        }
    };
    assert_eq!(ev.decision, Decision::NeedsApproval);

    // same request after the policy is changed live (no restart)
    f.policy
        .write()
        .unwrap()
        .rules
        .push(Rule::new(Action::Allow, "allowed.example", Origin::Local).unwrap());
    let ok =
        f.sb.exec(&["/bin/wget", "-qO-", "http://allowed.example/"], None)
            .unwrap();
    assert_eq!(
        ok.code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(ok.stdout_str(), "hello-from-host-server\n");

    // an explicit deny wins even over the allow rule
    f.policy
        .write()
        .unwrap()
        .rules
        .push(Rule::new(Action::Deny, "allowed.example", Origin::Local).unwrap());
    let denied =
        f.sb.exec(&["/bin/wget", "-qO-", "http://allowed.example/"], None)
            .unwrap();
    assert_ne!(denied.code, 0);

    // CONNECT to a blocked host gets a 403 from the proxy
    let c = f
        .sb
        .exec(&["/bin/sh", "-c", "(printf 'CONNECT blocked.example:443 HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n'; sleep 2) | nc -w 3 127.0.0.1 3128"], None)
        .unwrap();
    assert!(
        c.stdout_str().contains("403"),
        "code={} stdout={:?} stderr={:?}",
        c.code,
        c.stdout_str(),
        String::from_utf8_lossy(&c.stderr)
    );

    // the guest cannot bypass the proxy: there is no route out at all
    let direct = f.sb.exec(&["/bin/sh", "-c", "env -u http_proxy -u HTTP_PROXY wget -T 3 -qO- http://93.184.216.34/ 2>&1; echo rc=$?"], None).unwrap();
    assert!(
        !direct.stdout_str().contains("rc=0"),
        "{}",
        direct.stdout_str()
    );
}

#[test]
fn published_ports_reach_guest_services() {
    let Some(f) = start(None) else { return };
    let started = f
        .sb
        .exec(&["/bin/sh", "-c", "mkdir -p /www && echo published-by-guest > /www/index.html && httpd -p 8080 -h /www && echo started"], None)
        .unwrap();
    assert_eq!(
        started.stdout_str().trim(),
        "started",
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let addr =
        f.sb.publish_port("127.0.0.1:0".parse().unwrap(), 8080)
            .unwrap();

    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(
        resp.contains("200") && resp.contains("published-by-guest"),
        "{resp}"
    );

    // Raw TCP where the client stays silent and the server speaks late (WebSocket after the
    // upgrade, VNC, terminals): the forward must keep the connection open until data arrives.
    let started = f
        .sb
        .exec(&["/bin/sh", "-c", "setsid sh -c '{ sleep 2; echo late-hello; sleep 1; } | nc -l -p 9090' >/dev/null 2>&1 < /dev/null & sleep 0.3; echo started"], None)
        .unwrap();
    assert_eq!(started.stdout_str().trim(), "started");
    let addr =
        f.sb.publish_port("127.0.0.1:0".parse().unwrap(), 9090)
            .unwrap();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let t = std::time::Instant::now();
    let mut got = String::new();
    let _ = s.read_to_string(&mut got);
    assert_eq!(
        got.trim(),
        "late-hello",
        "connection ended after {:?}",
        t.elapsed()
    );
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
}

#[test]
fn boots_a_real_root_filesystem_built_from_an_oci_image() {
    let Some((kernel, initrd)) = assets() else {
        return;
    };
    let image = std::env::var("OSBX_TEST_IMAGE").unwrap_or_else(|_| "ubuntu:24.04".into());
    let agent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest/assets/osbx-agent");
    if !osbx_image::missing_tools().is_empty()
        || !osbx_image::image_present(&image)
        || !agent.exists()
    {
        eprintln!(
            "need docker+fakeroot+mke2fs, a local {image} and guest/assets/osbx-agent; skipping"
        );
        return;
    }
    let ca = Ca::generate("osbx rootfs test CA").unwrap();
    let tmp = std::env::temp_dir().join(format!("osbx-rootfs-test-{}", std::process::id()));
    let _cleanup = TempDir(tmp.clone());
    std::fs::create_dir_all(&tmp).unwrap();
    let disk = tmp.join("root.img");
    osbx_image::build_rootfs(
        &osbx_image::RootfsSpec {
            image: &image,
            min_size_mib: 512,
            agent: &agent,
            ca_pem: Some(ca.cert_pem()),
            hostname: "osbx-test",
            extra_bins: &[],
            overlays: &[],
        },
        &disk,
    )
    .expect("build rootfs");

    let sb = Sandbox::start(SandboxConfig {
        name: "rootfs".into(),
        kernel,
        initrd,
        disks: vec![osbx_vmm::DiskConfig {
            path: disk.clone(),
            read_only: false,
        }],
        extra_cmdline: "root=/dev/vda".into(),
        shares: vec![],
        mem_mib: 512,
        cpus: 2,
        policy: Arc::new(RwLock::new(PolicySet::new(Preset::DenyAll))),
        credentials: Arc::new(NoCredentials),
        ca: Arc::new(ca),
        env: BTreeMap::new(),
        upstream: None,
        client_tls: None,
        events: None,
    })
    .expect("start");
    sb.wait_ready(Duration::from_secs(90)).expect("agent ready");
    {
        let os = sb
            .exec(
                &["/bin/sh", "-c", ". /etc/os-release; echo $ID $VERSION_ID"],
                None,
            )
            .unwrap();
        assert!(
            os.stdout_str().starts_with("ubuntu 24.04"),
            "{:?} {}",
            os,
            sb.console()
        );
        // ownership survived the fakeroot build, and the agent runs as root
        let who = sb
            .exec(
                &[
                    "/bin/sh",
                    "-c",
                    "id -u; stat -c '%U:%G' /etc/shadow /usr/bin/apt-get; hostname",
                ],
                None,
            )
            .unwrap();
        assert_eq!(
            who.stdout_str(),
            "0\nroot:shadow\nroot:root\nosbx-test\n",
            "{:?}",
            who
        );
        // commands can run as an unprivileged user with that user's home, groups and environment
        let user = sb
            .exec_request(
                osbx_proto::ExecRequest {
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "id -un; id -u; echo $HOME; pwd; touch /etc/x 2>&1 | grep -c denied".into(),
                    ],
                    user: Some("ubuntu".into()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(
            user.stdout_str(),
            "ubuntu\n1000\n/home/ubuntu\n/home/ubuntu\n1\n",
            "{:?}",
            user
        );
        // a real distro userland: the package manager runs, and the sandbox CA is in the trust bundle
        let apt = sb.exec(&["/usr/bin/apt-get", "--version"], None).unwrap();
        assert_eq!(apt.code, 0);
        let ca_in_bundle = sb
            .exec(
                &[
                    "/bin/sh",
                    "-c",
                    "grep -c 'BEGIN CERTIFICATE' /usr/local/share/ca-certificates/osbx-ca.crt",
                ],
                None,
            )
            .unwrap();
        assert_eq!(ca_in_bundle.stdout_str().trim(), "1");
        // writes to the root disk work; /tmp and /run are tmpfs
        let w = sb
            .exec(
                &[
                    "/bin/sh",
                    "-c",
                    "echo data > /root/persist && sync && grep -c tmpfs /proc/mounts",
                ],
                None,
            )
            .unwrap();
        assert_eq!(w.code, 0, "{:?}", w);
    }
    let exit = sb.shutdown(Duration::from_secs(20));
    let persisted = std::process::Command::new("debugfs")
        .arg("-R")
        .arg("cat /root/persist")
        .arg(&disk)
        .output()
        .ok();
    assert_eq!(exit, osbx_vmm::ExitReason::GuestReset);
    if let Some(p) = persisted {
        assert_eq!(
            String::from_utf8_lossy(&p.stdout),
            "data\n",
            "the guest's write must reach the disk image"
        );
    }
}

#[test]
fn shared_workspace_is_live_in_both_directions() {
    let Some((kernel, initrd)) = assets() else {
        return;
    };
    let host_dir = std::env::temp_dir().join(format!("osbx-share-{}", std::process::id()));
    let _cleanup = TempDir(host_dir.clone());
    std::fs::create_dir_all(host_dir.join("src")).unwrap();
    std::fs::write(host_dir.join("src/main.txt"), "from the host\n").unwrap();
    let sb = Sandbox::start(SandboxConfig {
        name: "share".into(),
        kernel,
        initrd,
        disks: vec![],
        extra_cmdline: String::new(),
        shares: vec![osbx_sandbox::Share {
            host_dir: host_dir.clone(),
            guest_path: "/workspace".into(),
            read_only: false,
        }],
        mem_mib: 256,
        cpus: 2,
        policy: Arc::new(RwLock::new(PolicySet::new(Preset::DenyAll))),
        credentials: Arc::new(NoCredentials),
        ca: Arc::new(Ca::generate("t").unwrap()),
        env: BTreeMap::new(),
        upstream: None,
        client_tls: None,
        events: None,
    })
    .expect("start");
    {
        sb.wait_ready(Duration::from_secs(60)).expect("ready");
        assert!(
            sb.console()
                .contains("osbx-guest: shared osbx0 at /workspace"),
            "{}",
            sb.console()
        );
        // host -> guest
        let r = sb
            .exec(&["/bin/cat", "/workspace/src/main.txt"], None)
            .unwrap();
        assert_eq!(r.stdout_str(), "from the host\n", "{:?}", r);
        // guest -> host, including new directories, renames and deletes
        let w = sb
            .exec(&["/bin/sh", "-c", "mkdir -p /workspace/out && echo built > /workspace/out/a && mv /workspace/out/a /workspace/out/b && rm /workspace/src/main.txt && echo ok"], None)
            .unwrap();
        assert_eq!(w.stdout_str(), "ok\n", "{:?}", w);
        assert_eq!(
            std::fs::read_to_string(host_dir.join("out/b")).unwrap(),
            "built\n"
        );
        assert!(!host_dir.join("src/main.txt").exists());
        // live: a host change made while the guest runs is visible at once
        std::fs::write(host_dir.join("later.txt"), "edited on host\n").unwrap();
        let r = sb
            .exec(&["/bin/cat", "/workspace/later.txt"], None)
            .unwrap();
        assert_eq!(r.stdout_str(), "edited on host\n");
        // a 5 MB file round-trips byte for byte
        let w = sb
            .exec(
                &[
                    "/bin/sh",
                    "-c",
                    "head -c 5000000 /dev/urandom > /workspace/big && cat /workspace/big",
                ],
                None,
            )
            .unwrap();
        assert_eq!(w.code, 0, "{:?}", w.stderr);
        let host = std::fs::read(host_dir.join("big")).unwrap();
        assert_eq!(host.len(), 5_000_000);
        assert!(w.stdout == host, "contents differ between guest and host");
        // the guest cannot escape the shared directory
        let esc = sb.exec(&["/bin/sh", "-c", "ls /workspace/../../.. >/dev/null; cat /workspace/../etc/hostname 2>&1; ls /workspace/.. | head -3"], None).unwrap();
        assert!(
            !esc.stdout_str()
                .contains(&*host_dir.parent().unwrap().to_string_lossy()),
            "{:?}",
            esc
        );
    }
    sb.shutdown(Duration::from_secs(10));
}
