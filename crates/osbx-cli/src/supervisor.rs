//! The per-sandbox supervisor: a detached `osbx __supervise <name>` process that owns the
//! microVM and serves `sandboxes/<name>/control.sock`.
//!
//! Requests are one JSON line, `{"op": ...}`. `exec` is followed by the agent protocol: the
//! supervisor fills in the sandbox's environment, then splices the client to the guest agent.

use crate::state::{
    GuestOs, Record, StoredPolicy, WorkspaceMode, assets_dir, control_socket, sandbox_dir,
};
use crate::sys::{LocalListener as UnixListener, LocalStream as UnixStream};
use osbx_policy::PolicySet;
use osbx_proto::{EXEC, ExecRequest, read_frame, write_frame};
use osbx_proxy::{Ca, Credentials};
use osbx_sandbox::{Sandbox, SandboxConfig, Share};
use osbx_secrets::{FileStore, InjectRule, Resolver, builtin_services};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Guest path where clone mode exposes the host repository.
pub const CLONE_SOURCE: &str = "/run/sandbox/source";

/// Credentials from the osbx secret store, presented per kit-declared rules first, then per
/// built-in service rules.
struct StoreCredentials {
    resolver: Resolver<FileStore>,
    store: FileStore,
    sandbox: String,
    kit: Vec<crate::kits::KitCredential>,
    /// When `credentials.yaml` exists, only bound `(service, mechanism, host)` tuples are injected.
    bindings: Option<osbx_secrets::Bindings>,
}

/// Where a service's OAuth tokens live: a global entry, so a login made in one sandbox serves
/// every sandbox and survives re-creation. `osbx secret rm oauth/<service>` logs out.
fn oauth_key(service: &str) -> String {
    format!("oauth/{service}")
}

/// Read stored OAuth tokens.
fn load_oauth(store: &FileStore, service: &str) -> Option<osbx_proxy::OAuthTokens> {
    use osbx_secrets::{Scope, SecretStore, Source};
    let entry = store.get(&Scope::Global, &oauth_key(service)).ok()??;
    let Source::Value(json) = entry.source else {
        return None;
    };
    let v: Value = serde_json::from_str(&json).ok()?;
    Some(osbx_proxy::OAuthTokens {
        access_token: v["access_token"].as_str()?.to_owned(),
        refresh_token: v["refresh_token"].as_str().map(str::to_owned),
        expires_at_ms: v["expires_at_ms"].as_u64(),
        scopes: v["scopes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

impl Credentials for StoreCredentials {
    fn oauth_for_host(&self, host: &str) -> Option<osbx_proxy::OAuthSpec> {
        let covers = |d: &str| {
            d.parse::<osbx_policy::Destination>()
                .is_ok_and(|d| d.matches(host, None, 443))
        };
        self.kit.iter().find_map(|kc| {
            let o = kc.oauth.as_ref()?;
            if let Some(b) = &self.bindings
                && !b.allows(&kc.service, osbx_secrets::Mechanism::Oauth, host)
            {
                return None;
            }
            (o.token_host == host || o.resource_hosts.iter().any(|r| covers(r))).then(|| {
                osbx_proxy::OAuthSpec {
                    service: kc.service.clone(),
                    token_host: o.token_host.clone(),
                    token_path: o.token_path.clone(),
                    resource_hosts: o.resource_hosts.clone(),
                    access_sentinel: o.access_sentinel.clone(),
                    refresh_sentinel: o.refresh_sentinel.clone(),
                }
            })
        })
    }

    fn oauth_tokens(&self, service: &str) -> Option<osbx_proxy::OAuthTokens> {
        load_oauth(&self.store, service)
    }

    fn oauth_save(&self, service: &str, t: &osbx_proxy::OAuthTokens) {
        use osbx_secrets::{Refresh, Scope, SecretStore, Source, Stored};
        let json = json!({"access_token": t.access_token, "refresh_token": t.refresh_token, "expires_at_ms": t.expires_at_ms, "scopes": t.scopes});
        let entry = Stored {
            source: Source::Value(json.to_string()),
            refresh: Refresh::Default,
        };
        match self.store.set(&Scope::Global, &oauth_key(service), entry) {
            Ok(()) => eprintln!("oauth: login for {service} stored on the host"),
            Err(e) => eprintln!("oauth: could not store the {service} login: {e}"),
        }
    }

    fn for_host(&self, host: &str) -> Option<(Vec<InjectRule>, String)> {
        let covers = |d: &str| {
            d.parse::<osbx_policy::Destination>()
                .is_ok_and(|d| d.matches(host, None, 443))
        };
        let allowed = |service: &str| -> bool {
            self.bindings
                .as_ref()
                .is_none_or(|b| b.allows(service, osbx_secrets::Mechanism::ApiKey, host))
        };
        for kc in &self.kit {
            if !kc.inject.iter().any(|(d, _, _)| covers(d)) || !allowed(&kc.service) {
                continue;
            }
            if let Ok(Some(secret)) = self.resolver.resolve(&self.sandbox, &kc.service) {
                let rules = kc
                    .inject
                    .iter()
                    .map(|(d, h, f)| InjectRule {
                        domain: d.clone(),
                        header: h.clone(),
                        format: f.clone(),
                        basic_user: None,
                    })
                    .collect();
                return Some((rules, secret));
            }
        }
        for svc in builtin_services() {
            if !allowed(svc.name) {
                continue;
            }
            let rules = svc.inject_rules();
            let matches = rules.iter().any(|r| {
                r.domain
                    .parse::<osbx_policy::Destination>()
                    .is_ok_and(|d| d.matches(host, None, 443))
            });
            if !matches {
                continue;
            }
            match self.resolver.resolve(&self.sandbox, svc.name) {
                Ok(Some(secret)) => return Some((rules, secret)),
                Ok(None) => {}
                Err(e) => eprintln!("credential {} unavailable: {e}", svc.name),
            }
        }
        None
    }
}

/// The sandbox's policy: stored preset and rules, plus sandbox firewall rules and kit rules for
/// `phase` (`runtime` normally; `install` adds the install-phase rules while install hooks run).
fn effective_policy(rec: &Record, phase: &str) -> Result<PolicySet, String> {
    let mut p = StoredPolicy::load()
        .map_err(|e| e.to_string())?
        .to_policy()?;
    if let Some(fw) = &rec.firewall {
        if let Some(def) = fw.default {
            p.preset = def.to_preset();
        }
        for r in &fw.rules {
            let active = matches!(r.phase, osbx_spec::FirewallPhase::Runtime)
                || (matches!(r.phase, osbx_spec::FirewallPhase::Install) && phase == "install");
            if !active {
                continue;
            }
            let action = match r.action {
                osbx_spec::FirewallAction::Allow => osbx_policy::Action::Allow,
                osbx_spec::FirewallAction::Deny => osbx_policy::Action::Deny,
            };
            let mut rule = osbx_policy::Rule::new(
                action,
                &r.dest,
                osbx_policy::Origin::Sandbox(rec.name.clone()),
            )
            .map_err(|e| format!("firewall {}: {e}", r.dest))?;
            rule.http = r.http.as_ref().map(|h| osbx_policy::HttpMatch {
                methods: h.methods.clone(),
                path: h.path.clone(),
                query: h
                    .query
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            });
            p.rules.push(rule);
        }
    }
    for r in crate::kits::network_rules(&rec.kits) {
        if r.phase == "runtime" || r.phase == phase {
            let action = if r.allow {
                osbx_policy::Action::Allow
            } else {
                osbx_policy::Action::Deny
            };
            let mut rule =
                osbx_policy::Rule::new(action, &r.dest, osbx_policy::Origin::Kit(r.kit.clone()))
                    .map_err(|e| format!("kit {}: {}: {e}", r.kit, r.dest))?;
            rule.http = r.http;
            p.rules.push(rule);
        }
    }
    Ok(p)
}

/// Read one `\n`-terminated line without buffering past it (the rest of the stream is raw).
pub fn read_line(s: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.len() < 64 * 1024 {
        if s.read(&mut b)? == 0 {
            break;
        }
        if b[0] == b'\n' {
            return String::from_utf8(line).map_err(io::Error::other);
        }
        line.push(b[0]);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "request line missing or too long",
    ))
}

fn reply(s: &mut UnixStream, v: Value) {
    let _ = writeln!(s, "{v}");
}

struct State {
    sb: Sandbox,
    policy: Arc<RwLock<PolicySet>>,
    /// Destinations refused for want of approval: "host:port" -> attempts.
    pending: Arc<Mutex<std::collections::BTreeMap<String, u64>>>,
    ports: Mutex<Vec<(SocketAddr, u16)>>,
    launch_env: BTreeMap<String, String>,
}

/// Run the supervisor for `name` (does not return until the sandbox stops).
pub fn supervise(name: &str) -> io::Result<()> {
    let rec = Record::load(name)?;
    let dir = sandbox_dir(name);
    let assets = assets_dir();
    let (kernel, initrd) = (assets.join("vmlinuz"), assets.join("initramfs.cpio.gz"));
    if rec.guest_os == GuestOs::Linux {
        for p in [&kernel, &initrd] {
            if !p.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "{} missing (build guest assets and set OSBX_ASSETS)",
                        p.display()
                    ),
                ));
            }
        }
    }
    let ca_pem = std::fs::read_to_string(dir.join("ca.pem"))?;
    let ca = Ca::from_pem(&ca_pem, &std::fs::read_to_string(dir.join("ca.key"))?)
        .map_err(|e| io::Error::other(e.to_string()))?;
    if crate::kits::wants_kvm(&rec.kits) && !osbx_vmm::probe().nested_ready() {
        return Err(io::Error::other(
            "a kit requires kvm@1, but this host cannot give a sandbox KVM now",
        ));
    }
    let policy = Arc::new(RwLock::new(
        effective_policy(&rec, "runtime").map_err(io::Error::other)?,
    ));
    let store = FileStore::open(crate::state::home().join("secrets"))
        .map_err(|e| io::Error::other(e.to_string()))?;
    let kit_creds = crate::kits::credentials(&rec.kits);
    let oauth_store = FileStore::open(crate::state::home().join("secrets"))
        .map_err(|e| io::Error::other(e.to_string()))?;
    let bindings = crate::state::load_bindings()?;
    let credentials = Arc::new(StoreCredentials {
        resolver: Resolver::new(store),
        store: oauth_store,
        sandbox: name.to_owned(),
        kit: kit_creds.clone(),
        bindings,
    });

    let mut shares = Vec::new();
    if let Some(ws) = &rec.workspace {
        let path = crate::state::guest_path(&ws.host);
        match ws.mode {
            WorkspaceMode::Direct => shares.push(Share {
                host_dir: ws.host.clone(),
                guest_path: path,
                read_only: false,
            }),
            WorkspaceMode::Clone => {
                // the private clone (on the host, in the sandbox dir) at the workspace path, and
                // the original repository read-only beside it
                shares.push(Share {
                    host_dir: dir.join("clone"),
                    guest_path: path,
                    read_only: false,
                });
                shares.push(Share {
                    host_dir: ws.host.clone(),
                    guest_path: CLONE_SOURCE.into(),
                    read_only: true,
                });
            }
        }
    }
    let launch_env: BTreeMap<String, String> = rec
        .launch
        .env
        .iter()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    // kit host-mount@1: a host directory per (kit, path), unless the environment file chose one
    for (kit, path) in crate::kits::host_mounts(&rec.kits) {
        let host_dir = rec.mounts.get(&path).cloned().unwrap_or_else(|| {
            crate::state::home()
                .join("kit-mounts")
                .join(&kit)
                .join(path.trim_start_matches('/').replace('/', "_"))
        });
        std::fs::create_dir_all(&host_dir)?;
        shares.push(Share {
            host_dir,
            guest_path: path,
            read_only: false,
        });
    }
    // kit volume@1: persistent per-sandbox directory (survives stop/start, deleted on rm)
    for v in crate::kits::volumes(&rec.kits) {
        let host_dir = dir
            .join("volumes")
            .join(v.path.trim_start_matches('/').replace('/', "_"));
        std::fs::create_dir_all(&host_dir)?;
        shares.push(Share {
            host_dir,
            guest_path: v.path,
            read_only: false,
        });
    }
    // extra bind mounts / named volumes from osbx-compose.yml or sbxenv.yaml
    for s in &rec.extra_shares {
        if shares
            .iter()
            .any(|existing| existing.guest_path == s.guest_path)
        {
            continue;
        }
        std::fs::create_dir_all(&s.host_dir)?;
        shares.push(Share {
            host_dir: s.host_dir.clone(),
            guest_path: s.guest_path.clone(),
            read_only: s.read_only,
        });
    }
    let mut env = launch_env.clone();
    // kit create-phase args with `env:` delivery (user `-e` overrides them)
    for k in &rec.kits {
        env.extend(k.env.clone());
    }
    env.extend(rec.env.clone());
    // Node-based agents (Claude Code) do not read the system CA bundle: point them at the
    // sandbox CA so intercepted hosts (credential injection, OAuth) are trusted
    env.entry("NODE_EXTRA_CA_CERTS".into()).or_insert_with(|| {
        if rec.guest_os == GuestOs::Windows {
            r"C:\ProgramData\osbx\ca.pem".into()
        } else {
            "/usr/local/share/ca-certificates/osbx-ca.crt".into()
        }
    });
    // runtime-owned identity of the sandbox (sbx@1 asks for these; harmless for everyone)
    env.insert("SANDBOX_NAME".into(), name.to_owned());
    if let Some(wd) = &rec.workdir {
        env.insert("WORKSPACE_DIR".into(), wd.clone());
    } else if let Some(ws) = &rec.workspace {
        if rec.guest_os == GuestOs::Windows {
            env.insert("WORKSPACE_DIR".into(), r"C:\workspace".into());
        } else {
            env.insert("WORKSPACE_DIR".into(), crate::state::guest_path(&ws.host));
        }
    }
    if crate::kits::sbx_platform(&rec.kits) {
        env.entry("CLAUDE_ENV_FILE".into())
            .or_insert_with(|| crate::lifecycle::SBX_ENV_FILE.into());
    }
    // which credential mode each kit credential is wired in (read by kit hooks)
    {
        let probe = Resolver::new(
            FileStore::open(crate::state::home().join("secrets"))
                .map_err(|e| io::Error::other(e.to_string()))?,
        );
        for kc in &kit_creds {
            let mode = if matches!(probe.resolve(name, &kc.service), Ok(Some(_))) {
                "apikey"
            } else {
                "none"
            };
            env.insert(
                format!(
                    "SBX_CRED_{}_MODE",
                    kc.service.to_ascii_uppercase().replace('-', "_")
                ),
                mode.into(),
            );
        }
    }
    // a kit credential's variable carries the placeholder, never the secret
    for kc in &kit_creds {
        if let Some(var) = &kc.env_name {
            env.entry(var.clone())
                .or_insert_with(|| osbx_secrets::SENTINEL.into());
        }
    }

    // Requests the policy could not decide (no matching rule under balanced/deny-all) are
    // refused and remembered, so the user can approve them (`osbx policy approve`).
    let pending: Arc<Mutex<std::collections::BTreeMap<String, u64>>> = Arc::default();
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel::<osbx_proxy::Event>();
    {
        let pending = pending.clone();
        std::thread::spawn(move || {
            while let Some(e) = ev_rx.blocking_recv() {
                if e.decision == osbx_policy::Decision::NeedsApproval {
                    *pending
                        .lock()
                        .unwrap()
                        .entry(format!("{}:{}", e.host, e.port))
                        .or_default() += 1;
                }
            }
        });
    }
    let kit_ssh = crate::kits::ssh_agent(&rec.kits);
    let ssh_agent = match &kit_ssh {
        Some(sa) => {
            let socket = crate::kits::host_ssh_auth_sock().ok_or_else(|| {
                io::Error::other(
                    "a kit requires ssh-agent@1, but SSH_AUTH_SOCK is not set or missing",
                )
            })?;
            let policy = if sa.unrestricted {
                osbx_sandbox::ssh_agent::SshAgentPolicy::Unrestricted
            } else {
                osbx_sandbox::ssh_agent::SshAgentPolicy::SignOnly(sa.sign.clone())
            };
            Some(osbx_sandbox::ssh_agent::SshAgentConfig { socket, policy })
        }
        None => None,
    };
    if kit_ssh.as_ref().is_some_and(|sa| sa.runtime) {
        env.entry("SSH_AUTH_SOCK".into()).or_insert_with(|| {
            if rec.guest_os == GuestOs::Windows {
                osbx_proto::GUEST_WINDOWS_SSH_AGENT_PIPE.into()
            } else {
                osbx_proto::GUEST_SSH_AUTH_SOCK.into()
            }
        });
    }
    let mut win_mounts: Vec<osbx_proto::MountRequest> = Vec::new();
    let sb = match rec.guest_os {
        GuestOs::Linux => {
            // a larger disk size in the record (CLI --disk or sbxenv rootSize) is applied before boot
            if let Some(mib) = rec.root_size_mib {
                crate::lifecycle::grow_disk(&dir.join("root.img"), mib)?;
            }
            Sandbox::start(SandboxConfig {
                name: name.to_owned(),
                kernel,
                initrd,
                disks: vec![osbx_vmm_disk(dir.join("root.img"))],
                extra_cmdline: format!(
                    "root=/dev/vda{}{}",
                    if crate::kits::wants_kvm(&rec.kits) {
                        " osbx.kvm=1"
                    } else {
                        ""
                    },
                    if wants_docker(&rec) {
                        " osbx.docker=1"
                    } else {
                        ""
                    }
                ),
                shares,
                mem_mib: rec.mem_mib,
                cpus: rec.cpus,
                policy: policy.clone(),
                credentials,
                ca: Arc::new(ca),
                env,
                upstream: None,
                client_tls: None,
                events: Some(ev_tx),
                ssh_agent,
            })?
        }
        GuestOs::Windows => {
            let (fw_code, _) = crate::windows::find_ovmf(None, None)?;
            let fw_vars = dir.join("ovmf_vars.fd");
            let root_disk = if dir.join("root.qcow2").exists() {
                dir.join("root.qcow2")
            } else {
                dir.join("root.img")
            };
            let (win_shares, file_sync_shares, mounts) = build_windows_shares(&rec, &dir, &shares)?;
            win_mounts = mounts;
            Sandbox::start_uefi(osbx_sandbox::UefiSandboxConfig {
                name: name.to_owned(),
                firmware_code: fw_code,
                firmware_vars: fw_vars,
                disks: vec![osbx_vmm_disk(root_disk)],
                cdroms: vec![],
                shares: win_shares,
                file_sync_shares,
                mem_mib: rec.mem_mib,
                cpus: rec.cpus,
                policy: policy.clone(),
                credentials,
                ca: Arc::new(ca),
                env,
                upstream: None,
                client_tls: None,
                events: Some(ev_tx),
                ssh_agent,
                vtpm: rec.vtpm.then(|| dir.join("tpm.state")),
            })?
        }
    };
    sb.wait_ready(Duration::from_secs(if rec.guest_os == GuestOs::Windows {
        300
    } else {
        120
    }))?;
    if rec.guest_os == GuestOs::Windows {
        first_boot_setup_windows(&sb, &ca_pem, &win_mounts);
    } else {
        first_boot_setup(&sb, &rec, &ca_pem);
    }
    if let Err(e) = run_kit_lifecycle(&sb, &rec, &policy, &dir) {
        let _ = sb.shutdown(Duration::from_secs(10));
        return Err(e);
    }
    write_oauth_files(&sb, &rec, &kit_creds);

    // kit port@1: publish declared TCP ports on loopback with an ephemeral host port
    let mut initial_ports = Vec::new();
    for kp in crate::kits::ports(&rec.kits) {
        match sb.publish_port("127.0.0.1:0".parse().unwrap(), kp.container) {
            Ok(addr) => {
                eprintln!(
                    "kit port{}: published {addr} -> sandbox port {}",
                    kp.name
                        .as_deref()
                        .map(|n| format!(" {n}"))
                        .unwrap_or_default(),
                    kp.container
                );
                initial_ports.push((addr, kp.container));
            }
            Err(e) => eprintln!("warning: kit port {}: {e}", kp.container),
        }
    }

    let sock = control_socket(name);
    if let Some(parent) = sock.parent() {
        crate::sys::create_private_dir(parent)?;
    }
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    std::fs::write(dir.join("supervisor.pid"), std::process::id().to_string())?;
    eprintln!("osbx supervisor: {name} running");
    let state = Arc::new(State {
        sb,
        policy,
        pending,
        ports: Mutex::new(initial_ports),
        launch_env,
    });

    // If the guest dies on its own, clean up and exit.
    {
        let (state, sock, dir) = (state.clone(), sock.clone(), dir.clone());
        std::thread::spawn(move || {
            while !state.sb.finished() {
                std::thread::sleep(Duration::from_millis(500));
            }
            let _ = std::fs::write(dir.join("console.log"), state.sb.console());
            let _ = std::fs::remove_file(&sock);
            eprintln!("osbx supervisor: guest stopped");
            std::process::exit(0);
        });
    }

    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let (state, sock, dir) = (state.clone(), sock.clone(), dir.clone());
        std::thread::spawn(move || handle(conn, &state, &sock, &dir));
    }
    Ok(())
}

fn osbx_vmm_disk(path: std::path::PathBuf) -> osbx_sandbox::DiskConfig {
    osbx_sandbox::DiskConfig {
        path,
        read_only: false,
    }
}

/// kvm@1: the sandbox user can open /dev/kvm and /dev/vhost-vsock even after a package in the
/// image changes their permissions (e.g. qemu's postinst sets /dev/kvm to root:kvm 0660): the
/// devices get group `kvm`, mode 0666 for now, and the user joins group `kvm`. The agent reads
/// /etc/group at every exec, so this applies to every process started afterwards.
fn kvm_access_setup(sb: &Sandbox, rec: &Record) {
    let user = rec.launch.user.split(':').next().unwrap_or("").to_owned();
    let script = format!(
        r#"getent group kvm >/dev/null 2>&1 || groupadd -r kvm 2>/dev/null || addgroup --system kvm 2>/dev/null || {{
  gid=990; while cut -d: -f3 /etc/group | grep -qx "$gid"; do gid=$((gid-1)); done
  echo "kvm:x:$gid:" >> /etc/group
}}
for d in /dev/kvm /dev/vhost-vsock; do [ -e "$d" ] && chgrp kvm "$d" && chmod 0666 "$d"; done
u='{user}'
[ -n "$u" ] || exit 0
name=$(getent passwd "$u" | cut -d: -f1)
[ -n "$name" ] && [ "$name" != root ] || exit 0
id -nG "$name" 2>/dev/null | tr ' ' '\n' | grep -qx kvm && exit 0
usermod -aG kvm "$name" 2>/dev/null || adduser "$name" kvm >/dev/null 2>&1 || \
  sed -i "/^kvm:/{{s/:\$/:$name/;t;s/\$/,$name/}}" /etc/group"#
    );
    match sb.exec(&["/bin/sh", "-c", &script], None) {
        Ok(o) if o.code == 0 => {}
        Ok(o) => eprintln!(
            "kvm@1: setting up /dev/kvm access failed ({}): {}",
            o.code,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => eprintln!("kvm@1: setting up /dev/kvm access failed: {e}"),
    }
}

/// Normalize a Windows target path for overlap/coexistence checks.
fn normalize_win_target_key(p: &str) -> String {
    p.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// Build host-side PCIe `virtio-fs` configs, `FILE_SYNC_PORT` shares, and guest `MOUNT` requests
/// for a Windows guest, routing each volume to its configured `ShareBackend` and rejecting nested
/// mount paths.
fn build_windows_shares(
    rec: &Record,
    sandbox_dir: &std::path::Path,
    all_shares: &[Share],
) -> io::Result<(
    Vec<osbx_vmm::ShareConfig>,
    Vec<osbx_sandbox::file_sync::FileSyncShare>,
    Vec<osbx_proto::MountRequest>,
)> {
    let mut entries: Vec<(
        String,
        std::path::PathBuf,
        String,
        bool,
        osbx_spec::ShareBackend,
    )> = Vec::new();
    let mut ws_host_dirs: Vec<&std::path::Path> = Vec::new();

    if let Some(ws) = &rec.workspace {
        match ws.mode {
            WorkspaceMode::Direct => {
                entries.push((
                    "workspace".into(),
                    ws.host.clone(),
                    r"C:\workspace".into(),
                    false,
                    ws.backend,
                ));
                ws_host_dirs.push(ws.host.as_path());
            }
            WorkspaceMode::Clone => {
                let clone_dir = sandbox_dir.join("clone");
                entries.push((
                    "workspace".into(),
                    clone_dir,
                    r"C:\workspace".into(),
                    false,
                    ws.backend,
                ));
                entries.push((
                    "source".into(),
                    ws.host.clone(),
                    r"C:\mnt\source".into(),
                    true,
                    ws.backend,
                ));
                ws_host_dirs.push(ws.host.as_path());
            }
        }
    }

    // Extra shares (kit host-mount@1, volume@1, extra_shares) — skip workspace shares already added.
    let mut extra_idx = 0usize;
    let clone_path = sandbox_dir.join("clone");
    for sh in all_shares {
        if sh.guest_path == CLONE_SOURCE
            || sh.host_dir == clone_path
            || ws_host_dirs.contains(&sh.host_dir.as_path())
        {
            continue;
        }
        let leaf = sh
            .guest_path
            .trim_end_matches(['/', '\\'])
            .rsplit(['/', '\\'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("share");
        let sanitized: String = leaf
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .take(24)
            .collect();
        let tag = format!("mnt{extra_idx}_{sanitized}");
        let win_mount = if sh.guest_path.as_bytes().get(1) == Some(&b':') {
            sh.guest_path.replace('/', "\\")
        } else {
            format!(r"C:\mnt\{sanitized}")
        };
        let backend = rec
            .extra_shares
            .iter()
            .find(|es| es.guest_path == sh.guest_path)
            .map_or(osbx_spec::ShareBackend::Auto, |es| es.backend);
        extra_idx += 1;
        entries.push((tag, sh.host_dir.clone(), win_mount, sh.read_only, backend));
    }

    // Validate non-nested coexistence: reject duplicate or nested Windows mount targets.
    let norm_targets: Vec<(String, &str)> = entries
        .iter()
        .map(|(_, _, target, _, _)| (normalize_win_target_key(target), target.as_str()))
        .collect();
    for i in 0..norm_targets.len() {
        for j in (i + 1)..norm_targets.len() {
            let (a, a_raw) = &norm_targets[i];
            let (b, b_raw) = &norm_targets[j];
            if a == b
                || a.strip_prefix(b.as_str())
                    .is_some_and(|rest| rest.starts_with('\\'))
                || b.strip_prefix(a.as_str())
                    .is_some_and(|rest| rest.starts_with('\\'))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Windows share mount targets {a_raw:?} and {b_raw:?} overlap or are nested (use sibling mount points)"
                    ),
                ));
            }
        }
    }

    let mut pci_shares = Vec::new();
    let mut file_sync_shares = Vec::new();
    let mut mounts = Vec::new();
    for (tag, host_dir, target, read_only, backend) in entries {
        if backend.uses_virtiofs_pci() {
            pci_shares.push(osbx_vmm::ShareConfig {
                tag: tag.clone(),
                host_dir: host_dir.clone(),
                read_only,
            });
        }
        if backend.uses_file_sync() {
            file_sync_shares.push(osbx_sandbox::file_sync::FileSyncShare {
                tag: tag.clone(),
                host_dir,
                read_only,
            });
        }
        mounts.push(osbx_proto::MountRequest {
            tag,
            target,
            read_only,
            backend: backend.as_str().into(),
        });
    }

    Ok((pci_shares, file_sync_shares, mounts))
}

/// Windows guest first-boot setup: push the per-sandbox CA PEM via native `SETUP_CA` and mount
/// every configured host share via native `MOUNT` (zero `powershell.exe` / WMI / `netsh.exe`).
/// Falls back gracefully to the Phase W2 PowerShell path only if talking to a pre-W3 guest agent.
fn first_boot_setup_windows(sb: &Sandbox, ca_pem: &str, mounts: &[osbx_proto::MountRequest]) {
    let mut legacy_agent = false;
    match sb.setup_ca(ca_pem) {
        Ok(()) => {}
        Err(e) if e.to_string().contains("unexpected frame") => {
            legacy_agent = true;
            legacy_windows_setup_ca(sb, ca_pem);
        }
        Err(e) => eprintln!("windows first-boot CA setup failed: {e}"),
    }

    if mounts.is_empty() {
        return;
    }
    if legacy_agent {
        legacy_windows_mount_shares(sb, mounts);
        return;
    }
    for (idx, m) in mounts.iter().enumerate() {
        match sb.mount_share(m) {
            Ok(active_backend) => {
                eprintln!(
                    "windows mount {} -> {} ({}{})",
                    m.tag,
                    m.target,
                    active_backend,
                    if m.read_only { ", ro" } else { "" }
                );
            }
            Err(e) if e.to_string().contains("unexpected frame") => {
                legacy_windows_mount_shares(sb, &mounts[idx..]);
                return;
            }
            Err(e) => {
                eprintln!(
                    "windows mount {} -> {} ({}) failed: {e}",
                    m.tag, m.target, m.backend
                );
            }
        }
    }
}

/// Legacy Phase W2 fallback for older Windows templates that do not handle `SETUP_CA`.
fn legacy_windows_setup_ca(sb: &Sandbox, ca_pem: &str) {
    let ps = r#"New-Item -ItemType Directory -Force -Path 'C:\ProgramData\osbx' | Out-Null; [Console]::In.ReadToEnd() | Set-Content -NoNewline -Encoding Ascii 'C:\ProgramData\osbx\ca.pem'; & 'C:\Program Files\osbx\osbx-agent.exe' --install-ca 'C:\ProgramData\osbx\ca.pem'"#;
    let req = ExecRequest {
        argv: vec![
            "powershell.exe".into(),
            "-NoProfile".into(),
            "-Command".into(),
            ps.into(),
        ],
        user: Some("SYSTEM".into()),
        ..Default::default()
    };
    match sb.exec_request(req, Some(ca_pem.as_bytes().to_vec())) {
        Ok(o) if o.code == 0 => {}
        Ok(o) => eprintln!(
            "windows first-boot CA setup failed ({}): {}",
            o.code,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => eprintln!("windows first-boot CA setup failed: {e}"),
    }
}

/// Legacy Phase W2 fallback for older Windows templates that do not handle `MOUNT`.
fn legacy_windows_mount_shares(sb: &Sandbox, mounts: &[osbx_proto::MountRequest]) {
    let mut mount_ps = String::from(
        "$vfs = 'C:\\Program Files\\osbx\\virtiofs.exe'; if (-not (Test-Path $vfs)) { exit 0 }; ",
    );
    for m in mounts {
        let tag_esc = m.tag.replace('\'', "''");
        let mp_esc = m.target.replace('\'', "''");
        mount_ps.push_str(&format!(
            "$mp = '{mp_esc}'; $par = Split-Path -Parent $mp; if ($par -and -not (Test-Path $par)) {{ New-Item -ItemType Directory -Force -Path $par | Out-Null }}; if (Test-Path $mp) {{ try {{ Remove-Item $mp -Force -ErrorAction Stop }} catch {{}} }}; $cmd = '\"' + $vfs + '\" -t {tag_esc} -m \"' + $mp + '\"'; Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{ CommandLine = $cmd }} | Out-Null; "
        ));
    }
    mount_ps.push_str("Start-Sleep -Milliseconds 2000");
    let mreq = ExecRequest {
        argv: vec![
            "powershell.exe".into(),
            "-NoProfile".into(),
            "-Command".into(),
            mount_ps,
        ],
        user: Some("SYSTEM".into()),
        ..Default::default()
    };
    if let Ok(o) = sb.exec_request(mreq, None)
        && o.code != 0
    {
        eprintln!(
            "windows virtio-fs mount setup exited {}: {}",
            o.code,
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
}

/// Hostname, CA trust and volume permissions. Idempotent per boot.
fn first_boot_setup(sb: &Sandbox, rec: &Record, ca_pem: &str) {
    if crate::kits::wants_kvm(&rec.kits) {
        kvm_access_setup(sb, rec);
    }
    for v in crate::kits::volumes(&rec.kits) {
        if let Some(mode) = v.mode {
            let _ = sb.exec(
                &[
                    "/bin/sh",
                    "-c",
                    &format!("chmod {mode} '{}'", v.path.replace('\'', "'\\''")),
                ],
                None,
            );
        }
    }
    if crate::kits::sbx_platform(&rec.kits) {
        let owner = if rec.launch.user.is_empty() {
            "0".to_owned()
        } else {
            rec.launch.user.clone()
        };
        let f = crate::lifecycle::SBX_ENV_FILE;
        let _ = sb.exec(
            &[
                "/bin/sh",
                "-c",
                &format!("touch {f} && chown {owner} {f} && chmod 0644 {f}"),
            ],
            None,
        );
    }
    let script = format!(
        "echo {name} > /etc/hostname; hostname {name}; \
         mkdir -p /usr/local/share/ca-certificates && cat > /usr/local/share/ca-certificates/osbx-ca.crt; \
         for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do \
           [ -f \"$b\" ] && ! grep -q osbx-ca-marker \"$b\" && {{ echo '# osbx-ca-marker' >> \"$b\"; cat /usr/local/share/ca-certificates/osbx-ca.crt >> \"$b\"; }}; \
         done; true",
        name = rec.name
    );
    match sb.exec(
        &["/bin/sh", "-c", &script],
        Some(ca_pem.as_bytes().to_vec()),
    ) {
        Ok(o) if o.code == 0 => {}
        Ok(o) => eprintln!(
            "setup: exit {} {}",
            o.code,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => eprintln!("setup failed: {e}"),
    }
}

/// For every kit OAuth credential with a login stored on the host, write the agent's credential
/// file with placeholders and the real expiry, so the agent starts logged in (in any sandbox).
fn write_oauth_files(sb: &Sandbox, rec: &Record, creds: &[crate::kits::KitCredential]) {
    let Ok(store) = FileStore::open(crate::state::home().join("secrets")) else {
        return;
    };
    for kc in creds {
        let Some(o) = &kc.oauth else { continue };
        let (Some(path), Some(structure)) = (&o.file_path, &o.file_structure) else {
            continue;
        };
        let Some(t) = load_oauth(&store, &kc.service) else {
            continue;
        };
        let Some(doc) =
            crate::kits::render_credential_file(structure, o, t.expires_at_ms, &t.scopes)
        else {
            continue;
        };
        let target = match path.strip_prefix("~/") {
            Some(rest) => format!("\"$HOME\"/'{rest}'"),
            None => format!("'{path}'"),
        };
        let script = format!("umask 077; mkdir -p \"$(dirname {target})\" && cat > {target}");
        let req = ExecRequest {
            argv: vec!["/bin/sh".into(), "-c".into(), script],
            user: (!rec.launch.user.is_empty()).then(|| rec.launch.user.clone()),
            ..Default::default()
        };
        match sb.exec_request(req, Some(doc.to_string().into_bytes())) {
            Ok(r) if r.code == 0 => {
                eprintln!("oauth: {} login provided to the agent ({path})", kc.service)
            }
            Ok(r) => eprintln!(
                "oauth: writing {path} failed: {}",
                String::from_utf8_lossy(&r.stderr).trim()
            ),
            Err(e) => eprintln!("oauth: writing {path} failed: {e}"),
        }
    }
}

fn wants_docker(rec: &Record) -> bool {
    rec.docker || crate::kits::wants_docker(&rec.kits)
}

/// Start Docker Engine in the guest if the image has it. Pulls go through the sandbox proxy
/// (daemon `proxies`), and containers get the proxy through the client config: they reach it on
/// the bridge address, because the guest's 127.0.0.1 is not theirs.
fn start_docker(sb: &Sandbox, rec: &Record) -> io::Result<()> {
    let user = if rec.launch.user.is_empty() {
        "root".to_owned()
    } else {
        rec.launch.user.clone()
    };
    let script = format!(
        r#"command -v dockerd >/dev/null 2>&1 || {{ echo "dockerd is not installed in this image (e.g. apt-get install docker.io), not started" >&2; exit 0; }}
mkdir -p /etc/docker
[ -f /etc/docker/daemon.json ] || printf '%s
' '{{"proxies": {{"http-proxy": "http://127.0.0.1:3128", "https-proxy": "http://127.0.0.1:3128", "no-proxy": "localhost,127.0.0.1"}}, "ip6tables": false}}' > /etc/docker/daemon.json
for h in /root "$(getent passwd {user} | cut -d: -f6)"; do
  [ -n "$h" ] || continue
  mkdir -p "$h/.docker"
  [ -f "$h/.docker/config.json" ] || printf '%s
' '{{"proxies": {{"default": {{"httpProxy": "http://172.17.0.1:3128", "httpsProxy": "http://172.17.0.1:3128", "noProxy": "localhost,127.0.0.1"}}}}}}' > "$h/.docker/config.json"
  chown -R --reference="$h" "$h/.docker" 2>/dev/null
done
getent group docker >/dev/null && [ {user} != root ] && usermod -aG docker {user} 2>/dev/null
if ! {{ [ -f /var/run/docker.pid ] && kill -0 "$(cat /var/run/docker.pid)" 2>/dev/null; }}; then
  rm -f /var/run/docker.pid /var/run/docker.sock
  setsid dockerd >/var/log/dockerd.log 2>&1 < /dev/null &
fi
i=0; while [ $i -lt 120 ]; do [ -S /var/run/docker.sock ] && exit 0; i=$((i+1)); sleep 0.25; done
echo "dockerd did not come up:" >&2; tail -5 /var/log/dockerd.log >&2; exit 1"#
    );
    let o = sb.exec(&["/bin/sh", "-c", &script], None)?;
    let err = String::from_utf8_lossy(&o.stderr);
    if o.code != 0 {
        return Err(io::Error::other(format!("docker: {}", err.trim())));
    }
    if !err.trim().is_empty() {
        eprintln!("docker: {}", err.trim());
    }
    Ok(())
}

/// Kit lifecycle@1: files every start, install hooks once per sandbox (with the install-phase
/// network rules open only while they run), startup hooks every start. A failing install hook
/// fails the start.
fn run_kit_lifecycle(
    sb: &Sandbox,
    rec: &Record,
    policy: &Arc<RwLock<PolicySet>>,
    dir: &std::path::Path,
) -> io::Result<()> {
    let (install, startup, files) = crate::kits::lifecycle(&rec.kits);
    let env_for = |names: &[String]| -> BTreeMap<String, String> {
        names
            .iter()
            .filter_map(|n| sb.default_env().get(n).map(|v| (n.clone(), v.clone())))
            .collect()
    };
    for f in &files {
        let mode = f.mode.clone().unwrap_or_else(|| "0644".into());
        let guard = if f.overwrite {
            String::new()
        } else {
            format!("[ -e '{p}' ] && exit 0; ", p = f.path)
        };
        let script = format!(
            "{guard}mkdir -p \"$(dirname '{p}')\" && cat > '{p}' && chmod {mode} '{p}'",
            p = f.path
        );
        let o = sb.exec(
            &["/bin/sh", "-c", &script],
            Some(f.content.clone().into_bytes()),
        )?;
        if o.code != 0 {
            return Err(io::Error::other(format!(
                "kit file {}: {}",
                f.path,
                String::from_utf8_lossy(&o.stderr).trim()
            )));
        }
    }
    let marker = dir.join("kit-install.done");
    if !install.is_empty() && !marker.exists() {
        // install-phase rules: open now, closed again before the agent runs
        *policy.write().unwrap() = effective_policy(rec, "install").map_err(io::Error::other)?;
        let install_ssh = crate::kits::ssh_agent(&rec.kits).is_some_and(|sa| sa.install);
        let result = install.iter().try_for_each(|h| {
            // install hooks see only the variables they declare (deny by default), not the proxy settings
            let mut env = env_for(&h.env);
            if install_ssh {
                env.insert(
                    "SSH_AUTH_SOCK".into(),
                    osbx_proto::GUEST_SSH_AUTH_SOCK.into(),
                );
            }
            for k in [
                "http_proxy",
                "https_proxy",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "NO_PROXY",
            ] {
                if let Some(v) = sb.default_env().get(k) {
                    env.insert(k.into(), v.clone()); // the network path itself, not a secret
                }
            }
            let req = ExecRequest {
                argv: h.argv.clone(),
                env,
                user: h.user.clone(),
                ..Default::default()
            };
            let o = sb.exec_request(req, None)?;
            if o.code != 0 {
                return Err(io::Error::other(format!(
                    "kit install hook {:?} failed (exit {}): {}",
                    h.argv,
                    o.code,
                    String::from_utf8_lossy(&o.stderr).trim()
                )));
            }
            Ok(())
        });
        *policy.write().unwrap() = effective_policy(rec, "runtime").map_err(io::Error::other)?;
        result?;
        std::fs::write(&marker, b"")?;
    }
    // dockerd@1: the engine is up before startup hooks run
    if wants_docker(rec) {
        start_docker(sb, rec)?;
    }
    for h in startup {
        let req = ExecRequest {
            argv: h.argv.clone(),
            env: env_for(&h.env),
            user: h.user.clone(),
            ..Default::default()
        };
        if h.background {
            let conn = sb.agent_connection();
            std::thread::spawn(move || {
                if let Ok(c) = conn {
                    let _ = osbx_proto::run_exec(
                        c.try_clone(),
                        c,
                        &req,
                        None,
                        &mut io::sink(),
                        &mut io::sink(),
                    );
                }
            });
        } else {
            let o = sb.exec_request(req, None)?;
            if o.code != 0 {
                eprintln!("kit startup hook {:?} exited {}", h.argv, o.code);
            }
        }
    }
    Ok(())
}

fn handle(mut conn: UnixStream, st: &State, sock: &std::path::Path, dir: &std::path::Path) {
    let Ok(line) = read_line(&mut conn) else {
        return;
    };
    let req: Value = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(e) => return reply(&mut conn, json!({"error": format!("bad request: {e}")})),
    };
    match req["op"].as_str().unwrap_or("") {
        "status" => {
            let ports: Vec<Value> = st
                .ports
                .lock()
                .unwrap()
                .iter()
                .map(|(a, g)| json!({"host": a.to_string(), "guest": g}))
                .collect();
            reply(
                &mut conn,
                json!({"state": "running", "pid": std::process::id(), "ports": ports}),
            );
        }
        "console" => reply(&mut conn, json!({"console": st.sb.console()})),
        "pending" => {
            // drop entries the current policy now allows
            let policy = st.policy.read().unwrap();
            let name = st.sb.name().to_owned();
            let mut pending = st.pending.lock().unwrap();
            pending.retain(|dest, _| {
                let (host, port) = dest.rsplit_once(':').unwrap_or((dest, "443"));
                let req = osbx_policy::Request {
                    host,
                    ip: host.parse().ok(),
                    port: port.parse().unwrap_or(443),
                    http: None,
                };
                !policy.evaluate(&name, &req).is_allow()
            });
            let list: Vec<Value> = pending
                .iter()
                .map(|(d, n)| json!({"dest": d, "attempts": n}))
                .collect();
            reply(&mut conn, json!({"pending": list}));
        }
        "reload-policy" => match Record::load(st.sb.name())
            .map_err(|e| e.to_string())
            .and_then(|r| effective_policy(&r, "runtime"))
        {
            Ok(p) => {
                *st.policy.write().unwrap() = p;
                reply(&mut conn, json!({"ok": true}));
            }
            Err(e) => reply(&mut conn, json!({"error": e})),
        },
        "publish" => {
            let host: Result<SocketAddr, _> = req["host"].as_str().unwrap_or("127.0.0.1:0").parse();
            let guest = req["guest"].as_u64().and_then(|g| u16::try_from(g).ok());
            match (host, guest) {
                (Ok(h), Some(g)) => match st.sb.publish_port(h, g) {
                    Ok(addr) => {
                        st.ports.lock().unwrap().push((addr, g));
                        reply(
                            &mut conn,
                            json!({"ok": true, "host": addr.to_string(), "guest": g}),
                        );
                    }
                    Err(e) => reply(&mut conn, json!({"error": e.to_string()})),
                },
                _ => reply(
                    &mut conn,
                    json!({"error": "publish needs host (ip:port) and guest (port)"}),
                ),
            }
        }
        "stop" => {
            reply(&mut conn, json!({"ok": true}));
            let exit = st.sb.shutdown(Duration::from_secs(20));
            let _ = std::fs::write(dir.join("console.log"), st.sb.console());
            let _ = std::fs::remove_file(sock);
            eprintln!("osbx supervisor: stopped ({exit:?})");
            std::process::exit(0);
        }
        "exec" => relay_exec(conn, st),
        "cp-put" | "cp-get" => relay_raw_agent(conn, st),
        other => reply(&mut conn, json!({"error": format!("unknown op {other:?}")})),
    }
}

/// Splice a client's raw `osbx-proto` frames (`CP_PUT`, `CP_GET`) directly to the guest agent.
fn relay_raw_agent(mut client: UnixStream, st: &State) {
    let mut agent = match st.sb.agent_connection() {
        Ok(a) => a,
        Err(e) => {
            let _ = write_frame(
                &mut client,
                osbx_proto::ERROR,
                format!("guest agent unreachable: {e}").as_bytes(),
            );
            return;
        }
    };
    let (Ok(mut client_r), mut agent_r) = (client.try_clone(), agent.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut agent);
        agent.shutdown_write();
    });
    let _ = io::copy(&mut agent_r, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

/// Fill in the sandbox environment, then splice the client to the guest agent until it closes.
fn relay_exec(mut client: UnixStream, st: &State) {
    let mut req: ExecRequest = match read_frame(&mut client) {
        Ok(Some((EXEC, payload))) => match serde_json::from_slice(&payload) {
            Ok(r) => r,
            Err(_) => return,
        },
        _ => return,
    };
    for (k, v) in st.sb.default_env().iter().chain(st.launch_env.iter()) {
        req.env.entry(k.clone()).or_insert_with(|| v.clone());
    }
    let mut agent = match st.sb.agent_connection() {
        Ok(a) => a,
        Err(e) => {
            let _ = write_frame(
                &mut client,
                osbx_proto::ERROR,
                format!("guest agent unreachable: {e}").as_bytes(),
            );
            return;
        }
    };
    let Ok(payload) = serde_json::to_vec(&req) else {
        return;
    };
    if write_frame(&mut agent, EXEC, &payload).is_err() {
        return;
    }
    let (Ok(mut client_r), mut agent_r) = (client.try_clone(), agent.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut agent);
        agent.shutdown_write();
    });
    let _ = io::copy(&mut agent_r, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

/// Send one request to a running sandbox's supervisor and read the one-line JSON reply.
pub fn request(name: &str, req: Value) -> io::Result<Value> {
    let mut s = UnixStream::connect(control_socket(name))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    writeln!(s, "{req}")?;
    let mut line = String::new();
    io::BufReader::new(s).read_line(&mut line)?;
    let v: Value = serde_json::from_str(line.trim())
        .map_err(|e| io::Error::other(format!("bad supervisor reply: {e}")))?;
    if let Some(e) = v["error"].as_str() {
        return Err(io::Error::other(e.to_owned()));
    }
    Ok(v)
}

/// Is the sandbox's supervisor up?
pub fn is_running(name: &str) -> bool {
    request(name, json!({"op": "status"})).is_ok()
}
