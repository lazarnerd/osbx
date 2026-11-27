//! A running sandbox.
//!
//! A [`Sandbox`] owns one microVM. The guest's only route out is a TCP listener inside the guest
//! (`127.0.0.1:3128`, served by the guest agent) whose connections arrive on a vsock port and are
//! handed to the host policy proxy ([`osbx_proxy`]); there is no virtual NIC. The host talks to the
//! guest agent over vsock to run commands and to reach guest ports.

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!(
    "osbx-sandbox needs a hypervisor backend; osbx has Linux (KVM) and Windows (WHP) backends"
);

pub mod ssh_agent;

use osbx_policy::PolicySet;
use osbx_proto::{
    AGENT_PORT, EGRESS_PORT, ExecRequest, GUEST_PROXY_ADDR, POWEROFF, SSH_AGENT_PORT, TUNNEL_PORT,
    run_exec, write_frame,
};
use osbx_proxy::{
    Ca, Credentials, DirectUpstream, Event, ProxyConfig, Upstream, web_pki_client_config,
};
use osbx_vmm::virtio::vsock::{VsockHost, VsockStream};
use osbx_vmm::{BootConfig, DEFAULT_CMDLINE, ExitReason, UefiConfig, UefiVm, Vm};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use osbx_vmm::DiskConfig;

/// Guest CID used for every sandbox.
pub const GUEST_CID: u64 = 3;

/// A host directory mounted into the guest (virtio-fs). Changes are live in both directions.
#[derive(Debug, Clone)]
pub struct Share {
    /// Host directory.
    pub host_dir: PathBuf,
    /// Absolute mount point inside the guest (no whitespace).
    pub guest_path: String,
    /// Mount read-only (enforced both by guest mount flags and by the host FUSE server).
    pub read_only: bool,
}

/// How to build a sandbox.
pub struct SandboxConfig {
    /// Sandbox name (scopes sandbox-specific policy rules and secrets).
    pub name: String,
    /// Guest kernel (bzImage).
    pub kernel: PathBuf,
    /// Initramfs containing `/init` and `/bin/osbx-agent`.
    pub initrd: PathBuf,
    /// Extra disks (`/dev/vda`, ...), e.g. a root filesystem.
    pub disks: Vec<DiskConfig>,
    /// Extra kernel arguments (e.g. `root=/dev/vda`).
    pub extra_cmdline: String,
    /// Host directories to mount in the guest.
    pub shares: Vec<Share>,
    /// Guest RAM.
    pub mem_mib: usize,
    /// vCPUs.
    pub cpus: u8,
    /// Live network policy.
    pub policy: Arc<RwLock<PolicySet>>,
    /// Credentials the proxy may inject.
    pub credentials: Arc<dyn Credentials>,
    /// CA for TLS interception (its certificate must be trusted inside the guest).
    pub ca: Arc<Ca>,
    /// Environment given to every command (proxy variables are added automatically).
    pub env: BTreeMap<String, String>,
    /// Override how upstream connections are made (tests); default resolves and connects directly.
    pub upstream: Option<Arc<dyn Upstream>>,
    /// Override the TLS client config used towards upstream servers (tests); default web PKI.
    pub client_tls: Option<Arc<rustls_reexport::ClientConfig>>,
    /// Receive every policy decision.
    pub events: Option<tokio::sync::mpsc::UnboundedSender<Event>>,
    /// Forward the host SSH agent into the guest (`ssh-agent@1`), if granted.
    pub ssh_agent: Option<ssh_agent::SshAgentConfig>,
}

/// Re-exported so callers need not depend on rustls directly.
pub mod rustls_reexport {
    pub use osbx_proxy::ClientConfig;
}

/// Output of a finished command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Exit status (128+n if killed by signal n).
    pub code: i32,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// Captured stderr.
    pub stderr: Vec<u8>,
}

impl ExecOutput {
    /// stdout as lossy UTF-8.
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Configuration for starting a UEFI (Q35 PCIe / OVMF) sandbox (e.g., Windows guests).
pub struct UefiSandboxConfig {
    /// Sandbox name (scopes sandbox-specific policy rules and secrets).
    pub name: String,
    /// Read-only UEFI code firmware (`OVMF_CODE_4M.fd`).
    pub firmware_code: PathBuf,
    /// Writable per-sandbox UEFI NVRAM (`OVMF_VARS_4M.fd`).
    pub firmware_vars: PathBuf,
    /// Disks attached over `virtio-blk` PCIe (raw or QCOW2 CoW overlay).
    pub disks: Vec<DiskConfig>,
    /// Optional read-only ISO CD-ROMs attached over `virtio-scsi` / AHCI PCIe.
    pub cdroms: Vec<PathBuf>,
    /// Host directories shared over `virtio-fs` PCIe (`tag` derived from `guest_path`).
    pub shares: Vec<osbx_vmm::ShareConfig>,
    /// Guest RAM in MiB.
    pub mem_mib: usize,
    /// Number of vCPUs.
    pub cpus: u8,
    /// Live network policy.
    pub policy: Arc<RwLock<PolicySet>>,
    /// Credentials the proxy may inject.
    pub credentials: Arc<dyn Credentials>,
    /// CA for TLS interception.
    pub ca: Arc<Ca>,
    /// Environment given to every command (proxy variables are added automatically).
    pub env: BTreeMap<String, String>,
    /// Override upstream connector (tests).
    pub upstream: Option<Arc<dyn Upstream>>,
    /// Override upstream TLS client config (tests).
    pub client_tls: Option<Arc<rustls_reexport::ClientConfig>>,
    /// Receive every policy decision.
    pub events: Option<tokio::sync::mpsc::UnboundedSender<Event>>,
    /// Forward the host SSH agent into the guest (`ssh-agent@1`), if granted.
    pub ssh_agent: Option<ssh_agent::SshAgentConfig>,
    /// Optional persistent state file for an emulated CRB vTPM 2.0 device (`0xFED4_0000`).
    pub vtpm: Option<PathBuf>,
}

enum VmHandle {
    Linux(Vm),
    Uefi(UefiVm),
}

impl VmHandle {
    fn vsock(&self) -> Option<&VsockHost> {
        match self {
            Self::Linux(v) => v.vsock(),
            Self::Uefi(v) => v.vsock(),
        }
    }
    fn console(&self) -> String {
        match self {
            Self::Linux(v) => v.console(),
            Self::Uefi(v) => v.console(),
        }
    }
    fn finished(&self) -> bool {
        match self {
            Self::Linux(v) => v.finished(),
            Self::Uefi(v) => v.finished(),
        }
    }
    fn wait(&self, timeout: Option<Duration>) -> Option<Result<ExitReason, osbx_vmm::BootError>> {
        match self {
            Self::Linux(v) => v.wait(timeout),
            Self::Uefi(v) => v.wait(timeout),
        }
    }
    fn stop(&self) -> ExitReason {
        match self {
            Self::Linux(v) => v.stop(),
            Self::Uefi(v) => v.stop(),
        }
    }
}

/// A running sandbox.
pub struct Sandbox {
    name: String,
    vm: VmHandle,
    env: BTreeMap<String, String>,
    closed: Arc<AtomicBool>,
    _rt: Arc<tokio::runtime::Runtime>,
}

impl Sandbox {
    /// Boot the guest and start serving its egress. Use [`Sandbox::wait_ready`] before exec.
    pub fn start(cfg: SandboxConfig) -> io::Result<Sandbox> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?,
        );
        let upstream: Arc<dyn Upstream> = cfg.upstream.clone().unwrap_or_else(|| {
            Arc::new(DirectUpstream {
                policy: cfg.policy.clone(),
                sandbox: cfg.name.clone(),
                timeout: Duration::from_secs(30),
            })
        });
        let proxy = Arc::new(ProxyConfig {
            sandbox: cfg.name.clone(),
            policy: cfg.policy.clone(),
            credentials: cfg.credentials.clone(),
            upstream,
            ca: cfg.ca.clone(),
            client_tls: cfg.client_tls.clone().unwrap_or_else(web_pki_client_config),
            approve: None,
            events: cfg.events.clone(),
        });

        let mut share_args = String::new();
        let mut shares = Vec::new();
        for (i, sh) in cfg.shares.iter().enumerate() {
            if !sh.guest_path.starts_with('/') || sh.guest_path.chars().any(char::is_whitespace) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "guest path {:?} must be absolute without spaces",
                        sh.guest_path
                    ),
                ));
            }
            let tag = format!("osbx{i}");
            share_args.push_str(&format!(
                " osbx.share={tag}:{}{}",
                sh.guest_path,
                if sh.read_only { ":ro" } else { "" }
            ));
            shares.push(osbx_vmm::ShareConfig {
                tag,
                host_dir: sh.host_dir.clone(),
                read_only: sh.read_only,
            });
        }
        let ssh_arg = if cfg.ssh_agent.is_some() {
            " osbx.ssh_agent=1"
        } else {
            ""
        };
        let boot = BootConfig {
            kernel: cfg.kernel,
            initrd: Some(cfg.initrd),
            cmdline: format!(
                "{DEFAULT_CMDLINE} osbx.mode=agent {}{share_args}{ssh_arg}",
                cfg.extra_cmdline
            ),
            mem_mib: cfg.mem_mib,
            cpus: cfg.cpus,
            timeout: None,
            echo: false,
            stdin: false,
            disks: cfg.disks,
            vsock_cid: Some(GUEST_CID),
            shares,
        };
        let vm = Vm::start(&boot).map_err(|e| io::Error::other(e.to_string()))?;

        // Egress: every connection the guest agent opens to host port 3128 is served by the proxy.
        let accepted = vm.vsock().expect("vsock configured").listen(EGRESS_PORT);
        let handle = rt.handle().clone();
        std::thread::spawn(move || {
            while let Ok(stream) = accepted.recv() {
                bridge_to_proxy(&handle, stream, proxy.clone());
            }
        });
        if let Some(ssh_cfg) = cfg.ssh_agent {
            let ssh_rx = vm.vsock().expect("vsock configured").listen(SSH_AGENT_PORT);
            let ssh_cfg = Arc::new(ssh_cfg);
            std::thread::spawn(move || {
                while let Ok(stream) = ssh_rx.recv() {
                    let c = ssh_cfg.clone();
                    std::thread::spawn(move || ssh_agent::bridge(stream, &c));
                }
            });
        }

        let mut env = cfg.env;
        let proxy_url = format!("http://{GUEST_PROXY_ADDR}");
        for k in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
            env.entry(k.into()).or_insert_with(|| proxy_url.clone());
        }
        env.entry("NO_PROXY".into())
            .or_insert_with(|| "localhost,127.0.0.1".into());
        Ok(Sandbox {
            name: cfg.name,
            vm: VmHandle::Linux(vm),
            env,
            closed: Arc::new(AtomicBool::new(false)),
            _rt: rt,
        })
    }

    /// Boot a Q35 PCIe UEFI guest (e.g. Windows) and serve its egress through the host proxy.
    pub fn start_uefi(cfg: UefiSandboxConfig) -> io::Result<Sandbox> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?,
        );
        let upstream: Arc<dyn Upstream> = cfg.upstream.clone().unwrap_or_else(|| {
            Arc::new(DirectUpstream {
                policy: cfg.policy.clone(),
                sandbox: cfg.name.clone(),
                timeout: Duration::from_secs(30),
            })
        });
        let proxy = Arc::new(ProxyConfig {
            sandbox: cfg.name.clone(),
            policy: cfg.policy.clone(),
            credentials: cfg.credentials.clone(),
            upstream,
            ca: cfg.ca.clone(),
            client_tls: cfg.client_tls.clone().unwrap_or_else(web_pki_client_config),
            approve: None,
            events: cfg.events.clone(),
        });

        let mut uefi = UefiConfig::new(cfg.firmware_code);
        uefi.vars = Some(cfg.firmware_vars);
        uefi.mem_mib = cfg.mem_mib;
        uefi.cpus = cfg.cpus;
        uefi.disks = cfg.disks;
        uefi.cdroms = cfg.cdroms;
        uefi.shares = cfg.shares;
        uefi.vsock_cid = Some(GUEST_CID);
        uefi.hyperv = true;
        uefi.vtpm = cfg.vtpm;
        let vm = UefiVm::start(&uefi).map_err(|e| io::Error::other(e.to_string()))?;

        let accepted = vm.vsock().expect("vsock configured").listen(EGRESS_PORT);
        let handle = rt.handle().clone();
        std::thread::spawn(move || {
            while let Ok(stream) = accepted.recv() {
                bridge_to_proxy(&handle, stream, proxy.clone());
            }
        });
        if let Some(ssh_cfg) = cfg.ssh_agent {
            let ssh_rx = vm.vsock().expect("vsock configured").listen(SSH_AGENT_PORT);
            let ssh_cfg = Arc::new(ssh_cfg);
            std::thread::spawn(move || {
                while let Ok(stream) = ssh_rx.recv() {
                    let c = ssh_cfg.clone();
                    std::thread::spawn(move || ssh_agent::bridge(stream, &c));
                }
            });
        }

        let mut env = cfg.env;
        let proxy_url = format!("http://{GUEST_PROXY_ADDR}");
        for k in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
            env.entry(k.into()).or_insert_with(|| proxy_url.clone());
        }
        env.entry("NO_PROXY".into())
            .or_insert_with(|| "localhost,127.0.0.1".into());
        Ok(Sandbox {
            name: cfg.name,
            vm: VmHandle::Uefi(vm),
            env,
            closed: Arc::new(AtomicBool::new(false)),
            _rt: rt,
        })
    }

    /// The sandbox name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wait until the guest agent answers.
    pub fn wait_ready(&self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match self
                .vm
                .vsock()
                .expect("vsock")
                .connect(AGENT_PORT, Duration::from_secs(2))
            {
                Ok(_) => return Ok(()),
                Err(_) if self.vm.finished() => {
                    return Err(io::Error::other(format!(
                        "guest exited during boot:\n{}",
                        tail(&self.vm.console())
                    )));
                }
                Err(e) if Instant::now() >= deadline => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("guest agent not ready: {e}\n{}", tail(&self.vm.console())),
                    ));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }

    /// Run a command in the guest, streaming its output to `stdout`/`stderr`. Returns the exit status.
    pub fn exec_streaming(
        &self,
        mut req: ExecRequest,
        stdin: Option<Box<dyn Read + Send>>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> io::Result<i32> {
        for (k, v) in &self.env {
            req.env.entry(k.clone()).or_insert_with(|| v.clone());
        }
        let s = self
            .vm
            .vsock()
            .expect("vsock")
            .connect(AGENT_PORT, Duration::from_secs(10))?;
        Ok(run_exec(s.try_clone(), s, &req, stdin, stdout, stderr)?.code)
    }

    /// Run a command and collect its output.
    pub fn exec(&self, argv: &[&str], stdin: Option<Vec<u8>>) -> io::Result<ExecOutput> {
        let req = ExecRequest {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            ..Default::default()
        };
        self.exec_request(req, stdin)
    }

    /// Run a fully specified request (user, tty, env, cwd) and collect its output.
    pub fn exec_request(&self, req: ExecRequest, stdin: Option<Vec<u8>>) -> io::Result<ExecOutput> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let stdin = stdin.map(|d| Box::new(io::Cursor::new(d)) as Box<dyn Read + Send>);
        let code = self.exec_streaming(req, stdin, &mut out, &mut err)?;
        Ok(ExecOutput {
            code,
            stdout: out,
            stderr: err,
        })
    }

    /// A raw connection to the guest agent's control port (for callers that speak the protocol
    /// themselves, e.g. a supervisor relaying a client's session).
    pub fn agent_connection(&self) -> io::Result<VsockStream> {
        self.vm
            .vsock()
            .expect("vsock")
            .connect(AGENT_PORT, Duration::from_secs(10))
    }

    /// Environment added to every command (proxy variables and the configured env).
    pub fn default_env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// Listen on `bind` on the host and forward each connection to `127.0.0.1:guest_port` inside
    /// the guest. Returns the bound address (use port 0 to pick one).
    pub fn publish_port(&self, bind: SocketAddr, guest_port: u16) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let host = self.vm.vsock().expect("vsock").clone();
        let closed = self.closed.clone();
        std::thread::spawn(move || {
            while !closed.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((tcp, _)) => {
                        // Windows sockets inherit non-blocking mode from the listener (Unix ones
                        // do not): a non-blocking stream ends the relay with WouldBlock the
                        // first time the client is quiet (e.g. right after a WebSocket upgrade).
                        if tcp.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let _ = tcp.set_nodelay(true); // interactive protocols: VNC, terminals
                        let host = host.clone();
                        std::thread::spawn(move || {
                            let _ = tunnel(&host, tcp, guest_port);
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(addr)
    }

    /// The guest's serial console so far.
    pub fn console(&self) -> String {
        self.vm.console()
    }

    /// Has the guest stopped?
    pub fn finished(&self) -> bool {
        self.vm.finished()
    }

    /// Ask the guest to power off cleanly; kill it if it does not within `grace`.
    pub fn shutdown(&self, grace: Duration) -> ExitReason {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut s) = self
            .vm
            .vsock()
            .expect("vsock")
            .connect(AGENT_PORT, Duration::from_secs(2))
        {
            let _ = write_frame(&mut s, POWEROFF, &[]);
        }
        match self.vm.wait(Some(grace)) {
            Some(Ok(r)) => r,
            _ => self.vm.stop(),
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        if !self.vm.finished() {
            self.vm.stop();
        }
    }
}

fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

/// Pipe a host TCP connection into the guest.
fn tunnel(host: &VsockHost, tcp: TcpStream, guest_port: u16) -> io::Result<()> {
    let mut vs = host.connect(TUNNEL_PORT, Duration::from_secs(10))?;
    vs.write_all(format!("127.0.0.1:{guest_port}\n").as_bytes())?;
    let mut vs_read = vs.try_clone();
    let mut tcp_write = tcp.try_clone()?;
    let down = std::thread::spawn(move || {
        let _ = io::copy(&mut vs_read, &mut tcp_write);
        let _ = tcp_write.shutdown(std::net::Shutdown::Write);
    });
    let mut tcp_read = tcp;
    let _ = io::copy(&mut tcp_read, &mut vs);
    vs.shutdown_write();
    let _ = down.join();
    Ok(())
}

/// Connect a guest's vsock stream to an in-process proxy connection.
fn bridge_to_proxy(rt: &tokio::runtime::Handle, vs: VsockStream, cfg: Arc<ProxyConfig>) {
    let (client_side, proxy_side) = tokio::io::duplex(64 * 1024);
    rt.spawn(async move {
        let _ = osbx_proxy::serve_stream(proxy_side, cfg).await;
    });
    let (mut rd, mut wr) = tokio::io::split(client_side);
    let mut from_guest = vs.try_clone();
    let h = rt.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = from_guest.read(&mut buf) {
            if n == 0 || h.block_on(wr.write_all(&buf[..n])).is_err() {
                break;
            }
        }
        let _ = h.block_on(wr.shutdown());
    });
    let h = rt.clone();
    let mut to_guest = vs;
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = h.block_on(rd.read(&mut buf)) {
            if n == 0 || to_guest.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        to_guest.shutdown_write();
    });
}
