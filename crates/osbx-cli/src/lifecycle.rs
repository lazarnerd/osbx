//! Sandbox lifecycle commands (Linux/KVM and Windows/WHP hosts).

use crate::client::{self, Attach};
use crate::state::{
    Launch, Record, StoredPolicy, StoredRule, Workspace, WorkspaceMode, assets_dir, check_name,
    home, sandbox_dir,
};
use crate::supervisor;
use osbx_proto::ExecRequest;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The persistent environment file an `sbx@1` agent's bash sources (`BASH_ENV`).
pub const SBX_ENV_FILE: &str = "/etc/sandbox-persistent.sh";

/// Map an agent name to an image. A value with `/` or `:` is taken as an image reference.
///
/// ASSUMPTION: built-in agents other than `shell` map to Docker's published agent images under
/// `docker.io/sbx/<agent>`; pass `--image` to use something else.
pub fn image_for(agent: &str) -> String {
    if agent.contains('/') || agent.contains(':') {
        return agent.to_owned();
    }
    match agent {
        "shell" => "ubuntu:24.04".into(),
        other => format!("docker.io/sbx/{other}:latest"),
    }
}

fn file_stamp(p: &Path) -> io::Result<String> {
    let m = std::fs::metadata(p)?;
    let t = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    Ok(format!("{}-{t}", m.len()))
}

/// Build (or reuse) the read-only base root filesystem for `image` with kit content `overlays`.
fn base_rootfs(image: &str, overlays: &[String]) -> io::Result<PathBuf> {
    let mut key = crate::images::image_id(image)?;
    for o in overlays {
        key.push('+');
        key.push_str(&crate::images::image_id(o)?);
    }
    let agent = assets_dir().join("osbx-agent");
    if !agent.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} missing (run guest/build-assets.sh --with-osbx, set OSBX_ASSETS)",
                agent.display()
            ),
        ));
    }
    let probe = assets_dir().join("osbx-probe");
    // the injected binaries are part of the image, so they are part of the cache key
    let mut stamp = file_stamp(&agent)?;
    if probe.exists() {
        stamp.push('-');
        stamp.push_str(&file_stamp(&probe)?);
    }
    let key = format!("{key}-{stamp}");
    // a long overlay list would make an unwieldy file name: hash it
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    let dir = home().join("images");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{h:016x}.img"));
    if path.exists() {
        return Ok(path);
    }
    eprintln!(
        "building root filesystem from {image}{} ...",
        if overlays.is_empty() {
            String::new()
        } else {
            format!(" + {} kit layer(s)", overlays.len())
        }
    );
    let tmp = path.with_extension("building");
    let extra: Vec<&Path> = if probe.exists() {
        vec![probe.as_path()]
    } else {
        vec![]
    };
    crate::images::build_base(image, overlays, &tmp, &agent, &extra)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

fn template_dir() -> PathBuf {
    home().join("templates")
}

/// `osbx save NAME TEMPLATE`: capture a stopped sandbox's root disk (and launch settings) as a
/// template for `create --template`. The workspace, kits and secrets are not part of it.
pub fn save(name: &str, template: &str) -> io::Result<()> {
    check_name(template).map_err(io::Error::other)?;
    let rec = Record::load(name)?;
    if supervisor::is_running(name) {
        return Err(io::Error::other(format!(
            "stop {name} first: a template is taken from a consistent disk"
        )));
    }
    let dir = template_dir();
    std::fs::create_dir_all(&dir)?;
    osbx_vmm::disk::copy_sparse(
        &sandbox_dir(name).join("root.img"),
        &dir.join(format!("{template}.img")),
    )
    .map_err(|e| io::Error::new(e.kind(), format!("copying the disk failed: {e}")))?;
    let meta = json!({"from": name, "image": rec.image, "launch": rec.launch});
    crate::state::write_atomic(
        &dir.join(format!("{template}.json")),
        meta.to_string().as_bytes(),
    )
}

/// `osbx templates`: list saved templates.
pub fn templates() -> io::Result<()> {
    let mut names: Vec<String> = std::fs::read_dir(template_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".json")
                .map(str::to_owned)
        })
        .collect();
    names.sort();
    for n in names {
        let meta: Value = std::fs::read(template_dir().join(format!("{n}.json")))
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        println!(
            "{n:<24} from {} ({})",
            meta["from"].as_str().unwrap_or("?"),
            meta["image"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

/// Grow an (unattached) ext4 disk image to `mib` MiB: extend the sparse file; the guest grows the
/// file system to match at its next boot (`resize2fs` in the initramfs, online). On hosts with
/// e2fsprogs the file system is also grown right away (works with older guest assets too).
/// Returns whether it grew; a smaller or equal size is left alone (shrinking is not supported).
pub fn grow_disk(img: &Path, mib: u64) -> io::Result<bool> {
    let want = mib << 20;
    let have = std::fs::metadata(img)?.len();
    if want <= have {
        if want < have {
            eprintln!(
                "note: disk is {} MiB, larger than the requested {mib} MiB; disks are never shrunk",
                have >> 20
            );
        }
        return Ok(false);
    }
    eprintln!("growing root disk {} -> {mib} MiB ...", have >> 20);
    osbx_vmm::disk::grow_sparse(img, want)?;
    // e2fsck exit codes 0 and 1 mean clean / errors corrected
    let fsck = match Command::new("e2fsck").args(["-f", "-p"]).arg(img).output() {
        Ok(o) => o,
        // no e2fsprogs on this host (Windows): the guest resizes at boot
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    if fsck.status.code().is_none_or(|c| c > 1) {
        return Err(io::Error::other(format!(
            "e2fsck failed before resizing: {}",
            String::from_utf8_lossy(&fsck.stdout).trim()
        )));
    }
    let rs = Command::new("resize2fs").arg(img).output()?;
    if !rs.status.success() {
        return Err(io::Error::other(format!(
            "resize2fs failed: {}",
            String::from_utf8_lossy(&rs.stderr).trim()
        )));
    }
    Ok(true)
}

/// Options for `create`/`run`.
#[derive(Debug, Clone, Default)]
pub struct CreateOpts {
    /// Agent or image.
    pub agent: String,
    /// Explicit image (overrides the agent's default).
    pub image: Option<String>,
    /// Sandbox name.
    pub name: Option<String>,
    /// Workspace directory (None with `no_workspace`).
    pub workspace: Option<PathBuf>,
    /// Do not mount a workspace.
    pub no_workspace: bool,
    /// Clone mode.
    pub clone: bool,
    /// Extra env `K=V`.
    pub env: Vec<String>,
    /// Guest RAM.
    pub mem_mib: usize,
    /// vCPUs.
    pub cpus: u8,
    /// Kits (local directories or image references).
    pub kits: Vec<String>,
    /// Give the sandbox usable /dev/kvm (a `kvm@1` grant).
    pub kvm: bool,
    /// Run Docker Engine inside the sandbox.
    pub docker: bool,
    /// Start from a saved template instead of building from the image.
    pub template: Option<String>,
    /// Root disk size in MiB.
    pub root_size_mib: Option<u64>,
    /// Host directories for kit host-mount paths (sandbox path -> host dir).
    pub mounts: BTreeMap<String, PathBuf>,
}

fn default_name(agent: &str, ws: Option<&Path>) -> String {
    let base = agent
        .rsplit('/')
        .next()
        .unwrap_or(agent)
        .split(':')
        .next()
        .unwrap_or(agent)
        .to_owned();
    let raw = match ws.and_then(|w| w.file_name()) {
        Some(n) => format!("{base}-{}", n.to_string_lossy()),
        None => base,
    };
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_start_matches(['-', '.', '_'])
        .to_owned()
}

/// Create a sandbox (does not start it). Returns its name.
pub fn create(o: &CreateOpts) -> io::Result<String> {
    let ws = if o.no_workspace {
        None
    } else {
        let p = match &o.workspace {
            Some(p) => p.clone(),
            None => std::env::current_dir()?,
        };
        Some(crate::state::plain_path(
            &std::fs::canonicalize(&p)
                .map_err(|e| io::Error::new(e.kind(), format!("workspace {}: {e}", p.display())))?,
        ))
    };
    if o.clone && ws.as_ref().is_none_or(|w| !w.join(".git").exists()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--clone needs a workspace that is a git repository",
        ));
    }
    let name = o
        .name
        .clone()
        .unwrap_or_else(|| default_name(&o.agent, ws.as_deref()));
    check_name(&name).map_err(io::Error::other)?;
    if sandbox_dir(&name).join("sandbox.json").exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("sandbox {name:?} already exists"),
        ));
    }
    // kits: load and validate, compose, select capabilities against this host
    let mut kits = o
        .kits
        .iter()
        .map(|k| crate::kits::load(k))
        .collect::<io::Result<Vec<_>>>()?;
    if o.kvm {
        kits.push(crate::kits::KitRecord {
            source: "--kvm".into(),
            handle: "osbx-kvm".into(),
            kind: "mixin".into(),
            descriptor: "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - type: com.docker.sandbox/kvm@1\n".into(),
            image: None,
            granted: vec![],
            skipped: vec![],
        });
    }
    // an agent image that is itself a workload kit (sbx/claude, ...) is composed as one
    if o.image.is_none()
        && o.template.is_none()
        && !kits.iter().any(|k| k.kind == "workload")
        && let Some(w) = crate::kits::workload_for_image(&image_for(&o.agent))?
    {
        kits.insert(0, w);
    }
    let kvm_available = osbx_vmm::probe().nested_ready();
    crate::kits::plan(&mut kits, kvm_available)?;
    for k in &kits {
        eprintln!("kit {}", crate::kits::describe(k));
    }
    // a workload kit is the root filesystem; mixin images are layered on top
    let workload_image = kits
        .iter()
        .find(|k| k.kind == "workload")
        .and_then(|k| k.image.clone());
    let image = o
        .image
        .clone()
        .or(workload_image)
        .unwrap_or_else(|| image_for(&o.agent));
    let overlays: Vec<String> = kits
        .iter()
        .filter(|k| k.kind == "mixin")
        .filter_map(|k| k.image.clone())
        .collect();
    let (image, base, launch) = match &o.template {
        Some(t) => {
            let meta: Value = serde_json::from_slice(
                &std::fs::read(template_dir().join(format!("{t}.json")))
                    .map_err(|e| io::Error::new(e.kind(), format!("no template {t:?} ({e})")))?,
            )
            .map_err(io::Error::other)?;
            if !overlays.is_empty() {
                return Err(io::Error::other(
                    "--template cannot be combined with kits that add content",
                ));
            }
            let launch: Launch =
                serde_json::from_value(meta["launch"].clone()).map_err(io::Error::other)?;
            (
                meta["image"].as_str().unwrap_or(&image).to_owned(),
                template_dir().join(format!("{t}.img")),
                launch,
            )
        }
        None => {
            let base = base_rootfs(&image, &overlays)?;
            let launch = crate::images::launch_of(&image)?;
            (image, base, launch)
        }
    };
    let dir = sandbox_dir(&name);
    std::fs::create_dir_all(&dir)?;
    osbx_vmm::disk::copy_sparse(&base, &dir.join("root.img")).map_err(|e| {
        io::Error::new(e.kind(), format!("copying the root filesystem failed: {e}"))
    })?;
    if let Some(mib) = o.root_size_mib {
        grow_disk(&dir.join("root.img"), mib)?;
    }
    if o.clone
        && let Some(repo) = &ws
    {
        make_clone(&name, repo)?;
    }
    let (cert, key) = osbx_proxy::Ca::generate_pem(&format!("osbx sandbox {name}"))
        .map_err(|e| io::Error::other(e.to_string()))?;
    std::fs::write(dir.join("ca.pem"), cert)?;
    crate::sys::write_private(&dir.join("ca.key"), key.as_bytes())?;
    let env: BTreeMap<String, String> = o
        .env
        .iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .ok_or_else(|| io::Error::other(format!("-e {kv:?}: expected KEY=VALUE")))
        })
        .collect::<io::Result<_>>()?;
    Record {
        name: name.clone(),
        agent: o.agent.clone(),
        image,
        workspace: ws.map(|host| Workspace {
            host,
            mode: if o.clone {
                WorkspaceMode::Clone
            } else {
                WorkspaceMode::Direct
            },
        }),
        env,
        mem_mib: o.mem_mib,
        cpus: o.cpus,
        root_size_mib: o.root_size_mib,
        kits,
        docker: o.docker,
        mounts: o.mounts.clone(),
        launch,
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    }
    .save()?;
    Ok(name)
}

/// Clone mode: a private clone of the host repository in the sandbox's directory (shared into the
/// guest at the workspace path), plus a `sandbox-<name>` remote on the host repository so the
/// agent's commits can be fetched (`git fetch sandbox-<name>`).
fn make_clone(name: &str, repo: &Path) -> io::Result<()> {
    let clone = sandbox_dir(name).join("clone");
    let git = |args: &[&std::ffi::OsStr]| -> io::Result<()> {
        let out = Command::new("git").args(args).output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "git {:?}: {}",
                args,
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    };
    std::fs::create_dir_all(sandbox_dir(name))?;
    git(&[
        "clone".as_ref(),
        "-q".as_ref(),
        "--no-hardlinks".as_ref(),
        repo.as_os_str(),
        clone.as_os_str(),
    ])?;
    let remote = format!("sandbox-{name}");
    let _ = git(&[
        "-C".as_ref(),
        repo.as_os_str(),
        "remote".as_ref(),
        "remove".as_ref(),
        remote.as_ref(),
    ]);
    git(&[
        "-C".as_ref(),
        repo.as_os_str(),
        "remote".as_ref(),
        "add".as_ref(),
        remote.as_ref(),
        clone.as_os_str(),
    ])
}

/// Start the supervisor for `name` and wait until the sandbox is ready.
pub fn start(name: &str) -> io::Result<()> {
    Record::load(name)?;
    if supervisor::is_running(name) {
        return Ok(());
    }
    let dir = sandbox_dir(name);
    let log = std::fs::File::create(dir.join("supervisor.log"))?;
    let mut child = {
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.arg("__supervise")
            .arg(name)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        crate::sys::detach(&mut cmd); // not killed by Ctrl-C in this terminal
        cmd.spawn()?
    };
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if supervisor::is_running(name) {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            let log = std::fs::read_to_string(dir.join("supervisor.log")).unwrap_or_default();
            let tail: Vec<&str> = log.lines().rev().take(25).collect();
            return Err(io::Error::other(format!(
                "sandbox {name} failed to start ({status}):\n{}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            )));
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("sandbox {name} did not become ready"),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Stop a running sandbox (state is kept).
pub fn stop(name: &str) -> io::Result<()> {
    Record::load(name)?;
    if !supervisor::is_running(name) {
        return Ok(());
    }
    supervisor::request(name, json!({"op": "stop"}))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while crate::state::control_socket(name).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// Delete a sandbox and everything in its directory (the workspace on the host is untouched,
/// except that clone mode's `sandbox-<name>` remote is removed from it).
pub fn rm(name: &str, force: bool) -> io::Result<()> {
    let rec = Record::load(name)?;
    if supervisor::is_running(name) {
        if !force {
            return Err(io::Error::other(format!(
                "sandbox {name} is running (stop it or use --force)"
            )));
        }
        stop(name)?;
    }
    if let Some(ws) = rec.workspace.filter(|w| w.mode == WorkspaceMode::Clone) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&ws.host)
            .args(["remote", "remove", &format!("sandbox-{name}")])
            .output();
    }
    std::fs::remove_dir_all(sandbox_dir(name))
}

/// The command `run`/attach executes, and how.
pub fn agent_request(rec: &Record, extra: &[String]) -> ExecRequest {
    let argv = if extra.is_empty() {
        let mut a = rec.launch.argv.clone();
        // the workload kit's interactive tail applies to terminal sessions
        if client::is_tty(0)
            && let Some(tail) = crate::kits::interactive_tail(&rec.kits)
        {
            a.extend(tail);
        }
        a
    } else {
        extra.to_vec()
    };
    let cwd = match &rec.workspace {
        Some(w) => Some(crate::state::guest_path(&w.host)),
        None if !rec.launch.workdir.is_empty() => Some(rec.launch.workdir.clone()),
        None => None,
    };
    // sbx@1: the host launches the agent under bash so the persistent environment file is sourced
    let (argv, env) = if crate::kits::sbx_platform(&rec.kits) {
        let mut wrapped = vec![
            "/bin/bash".to_owned(),
            "-c".to_owned(),
            "exec \"$@\"".to_owned(),
            "osbx-launch".to_owned(),
        ];
        wrapped.extend(argv);
        (
            wrapped,
            BTreeMap::from([("BASH_ENV".to_owned(), SBX_ENV_FILE.to_owned())]),
        )
    } else {
        (argv, BTreeMap::new())
    };
    ExecRequest {
        argv,
        env,
        user: (!rec.launch.user.is_empty()).then(|| rec.launch.user.clone()),
        cwd,
        ..Default::default()
    }
}

/// `osbx run`: create if needed, start if needed, attach to the agent.
pub fn run(o: &CreateOpts, args: &[String]) -> io::Result<i32> {
    let name = match &o.name {
        Some(n) if sandbox_dir(n).join("sandbox.json").exists() => n.clone(),
        _ => {
            let ws = if o.no_workspace {
                None
            } else {
                Some(o.workspace.clone().map_or_else(std::env::current_dir, Ok)?)
            };
            let n = o.name.clone().unwrap_or_else(|| {
                default_name(
                    &o.agent,
                    ws.as_deref()
                        .and_then(|p| std::fs::canonicalize(p).ok())
                        .as_deref(),
                )
            });
            if sandbox_dir(&n).join("sandbox.json").exists() {
                n
            } else {
                create(&CreateOpts {
                    name: Some(n),
                    ..o.clone()
                })?
            }
        }
    };
    start(&name)?;
    let rec = Record::load(&name)?;
    let tty = client::is_tty(0) && client::is_tty(1);
    client::exec(
        &name,
        agent_request(&rec, args),
        Attach { stdin: true, tty },
    )
}

/// `osbx ls`.
pub fn ls() -> io::Result<()> {
    println!("{:<24} {:<10} {:<8} WORKSPACE", "NAME", "AGENT", "STATUS");
    for r in Record::all() {
        let status = if supervisor::is_running(&r.name) {
            "running"
        } else {
            "stopped"
        };
        let ws = r.workspace.as_ref().map_or("-".to_owned(), |w| {
            let mode = format!("{:?}", w.mode).to_lowercase();
            format!("{} ({mode})", w.host.display())
        });
        println!("{:<24} {:<10} {:<8} {}", r.name, r.agent, status, ws);
    }
    Ok(())
}

/// `osbx ports NAME [--publish SPEC]`. SPEC: `[IP:]HOST:GUEST` or `GUEST` (host port picked).
pub fn ports(name: &str, publish: Option<&str>) -> io::Result<()> {
    if let Some(spec) = publish {
        let parts: Vec<&str> = spec.split(':').collect();
        let (host, guest) = match parts.as_slice() {
            [g] => ("127.0.0.1:0".to_owned(), *g),
            [h, g] => (format!("127.0.0.1:{h}"), *g),
            [ip, h, g] => (format!("{ip}:{h}"), *g),
            _ => return Err(io::Error::other("port spec: [IP:]HOST:GUEST or GUEST")),
        };
        let guest: u16 = guest
            .parse()
            .map_err(|_| io::Error::other("guest port must be a number"))?;
        let v = supervisor::request(name, json!({"op": "publish", "host": host, "guest": guest}))?;
        println!(
            "{} -> sandbox port {}",
            v["host"].as_str().unwrap_or("?"),
            guest
        );
        return Ok(());
    }
    let v = supervisor::request(name, json!({"op": "status"}))?;
    for p in v["ports"].as_array().into_iter().flatten() {
        println!(
            "{} -> sandbox port {}",
            p["host"].as_str().unwrap_or("?"),
            p["guest"]
        );
    }
    Ok(())
}

/// `osbx logs NAME`: the guest console.
pub fn logs(name: &str) -> io::Result<()> {
    Record::load(name)?;
    let text = match supervisor::request(name, json!({"op": "console"})) {
        Ok(v) => v["console"].as_str().unwrap_or("").to_owned(),
        Err(_) => {
            std::fs::read_to_string(sandbox_dir(name).join("console.log")).unwrap_or_default()
        }
    };
    print!("{text}");
    Ok(())
}

// ---- persistent policy -----------------------------------------------------------------

fn reload_all() {
    for r in Record::all() {
        if supervisor::is_running(&r.name)
            && let Err(e) = supervisor::request(&r.name, json!({"op": "reload-policy"}))
        {
            eprintln!("warning: {}: policy not reloaded: {e}", r.name);
        }
    }
}

/// `osbx policy ls`.
pub fn policy_ls() -> io::Result<()> {
    let p = StoredPolicy::load()?;
    println!("preset: {}", p.preset);
    for r in &p.rules {
        println!(
            "{:<6} {}{}",
            r.action,
            r.dest,
            r.sandbox
                .as_deref()
                .map(|s| format!("  (sandbox {s})"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

/// `osbx policy init PRESET`.
pub fn policy_init(preset: &str) -> io::Result<()> {
    preset
        .parse::<osbx_policy::Preset>()
        .map_err(io::Error::other)?;
    let mut p = StoredPolicy::load()?;
    p.preset = preset.to_owned();
    p.save()?;
    reload_all();
    Ok(())
}

/// `osbx policy allow|deny DEST...`.
pub fn policy_add(action: &str, dests: &[String], sandbox: Option<String>) -> io::Result<()> {
    let mut p = StoredPolicy::load()?;
    for d in dests
        .iter()
        .flat_map(|d| d.split(','))
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        d.parse::<osbx_policy::Destination>()
            .map_err(|e| io::Error::other(format!("{d}: {e}")))?;
        let rule = StoredRule {
            action: action.to_owned(),
            dest: d.to_owned(),
            sandbox: sandbox.clone(),
        };
        if !p.rules.contains(&rule) {
            p.rules.push(rule);
        }
    }
    p.save()?;
    reload_all();
    Ok(())
}

/// `osbx policy pending NAME`: destinations refused for want of approval.
pub fn policy_pending(name: &str) -> io::Result<()> {
    let v = supervisor::request(name, json!({"op": "pending"}))?;
    let list = v["pending"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no pending destinations");
    }
    for p in list {
        println!(
            "{:<40} {} attempt(s)",
            p["dest"].as_str().unwrap_or("?"),
            p["attempts"]
        );
    }
    Ok(())
}

/// `osbx policy approve NAME DEST...`: allow for this sandbox (or all sandboxes).
pub fn policy_approve(name: &str, dests: &[String], all_sandboxes: bool) -> io::Result<()> {
    Record::load(name)?;
    // "host:443" from the pending list means the web default; store it as the bare host
    let dests: Vec<String> = dests
        .iter()
        .map(|d| d.strip_suffix(":443").unwrap_or(d).to_owned())
        .collect();
    policy_add("allow", &dests, (!all_sandboxes).then(|| name.to_owned()))
}

/// `osbx policy rm DEST`.
pub fn policy_rm(dest: &str, sandbox: Option<String>) -> io::Result<()> {
    let mut p = StoredPolicy::load()?;
    let before = p.rules.len();
    p.rules
        .retain(|r| !(r.dest == dest && r.sandbox == sandbox));
    if p.rules.len() == before {
        return Err(io::Error::other(format!("no rule for {dest}")));
    }
    p.save()?;
    reload_all();
    Ok(())
}

// ---- secrets -----------------------------------------------------------------------------

fn store() -> io::Result<osbx_secrets::FileStore> {
    osbx_secrets::FileStore::open(home().join("secrets"))
        .map_err(|e| io::Error::other(e.to_string()))
}

/// `osbx secret set`.
pub fn secret_set(
    service: &str,
    sandbox: Option<String>,
    command: Option<String>,
    reference: Option<String>,
) -> io::Result<()> {
    use osbx_secrets::{Refresh, Scope, SecretStore, Source, Stored};
    if osbx_secrets::find_service(service).is_none() {
        eprintln!(
            "note: {service:?} is not a built-in service; it is stored but only kits can use it"
        );
    }
    let source = match (command, reference) {
        (Some(c), None) => Source::Command(c),
        (None, Some(r)) => Source::Ref(r),
        (None, None) => {
            if client::is_tty(0) {
                eprintln!("enter the secret for {service} and press Ctrl-D:");
            }
            let mut v = String::new();
            io::stdin().read_to_string(&mut v)?;
            let v = v.trim_end_matches(['\r', '\n']).to_owned();
            if v.is_empty() {
                return Err(io::Error::other("empty secret"));
            }
            Source::Value(v)
        }
        _ => return Err(io::Error::other("use only one of --command and --ref")),
    };
    let scope = sandbox.map_or(Scope::Global, Scope::Sandbox);
    store()?
        .set(
            &scope,
            service,
            Stored {
                source,
                refresh: Refresh::Default,
            },
        )
        .map_err(|e| io::Error::other(e.to_string()))
}

/// `osbx secret ls`.
pub fn secret_ls() -> io::Result<()> {
    use osbx_secrets::{Scope, SecretStore};
    for (scope, svc) in store()?
        .list()
        .map_err(|e| io::Error::other(e.to_string()))?
    {
        match scope {
            Scope::Global => println!("{svc}  (global)"),
            Scope::Sandbox(s) => println!("{svc}  (sandbox {s})"),
        }
    }
    Ok(())
}

/// `osbx secret rm`.
pub fn secret_rm(service: &str, sandbox: Option<String>) -> io::Result<()> {
    use osbx_secrets::{Scope, SecretStore};
    let scope = sandbox.map_or(Scope::Global, Scope::Sandbox);
    if !store()?
        .remove(&scope, service)
        .map_err(|e| io::Error::other(e.to_string()))?
    {
        return Err(io::Error::other(format!(
            "no secret {service:?} in that scope"
        )));
    }
    Ok(())
}

// ---- sbxenv.yaml -------------------------------------------------------------------------

/// Parse `"16g"`, `"512m"`, `"2048"` (MiB) into MiB.
pub fn parse_mem(s: &str) -> Option<usize> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mult) = match s.chars().last()? {
        'g' => (&s[..s.len() - 1], 1024),
        'm' => (&s[..s.len() - 1], 1),
        _ => (s.as_str(), 1),
    };
    num.parse::<usize>().ok().map(|n| n * mult)
}

/// `osbx env run [FILE]`: create/start the environment's sandbox and attach.
pub fn env_run(file: &Path, env_args: &[String], detach: bool) -> io::Result<i32> {
    let text = std::fs::read_to_string(file)?;
    let dir = crate::state::plain_path(&std::fs::canonicalize(
        file.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?);
    let mut args = BTreeMap::new();
    for a in env_args {
        let (k, v) = a
            .split_once('=')
            .ok_or_else(|| io::Error::other(format!("--env-arg {a}: expected name=value")))?;
        args.insert(k.to_owned(), v.to_owned());
    }
    let ctx = osbx_env::Context {
        project_dir: dir.to_string_lossy().into(),
        file_dir: dir.to_string_lossy().into(),
        args,
    };
    let e = osbx_env::load(&[&text], &ctx).map_err(|e| io::Error::other(e.to_string()))?;
    // kits: local sources resolve against the file's directory
    let kit_sources: Vec<String> = e
        .kits
        .iter()
        .map(|k| match k.kind() {
            osbx_env::KitSource::Local(p) => dir.join(p).to_string_lossy().into_owned(),
            osbx_env::KitSource::Git(g) => g,
            osbx_env::KitSource::Oci(r) => r,
        })
        .collect();
    if let Some(k) = e
        .kits
        .iter()
        .find(|k| matches!(k.kind(), osbx_env::KitSource::Git(_)))
    {
        return Err(io::Error::other(format!(
            "git kit sources are not supported yet: {}",
            k.source()
        )));
    }
    let (ws, clone) = match &e.workspace {
        None => (None, false),
        Some(osbx_env::Workspace::Path(p)) => (Some(dir.join(p)), false),
        Some(osbx_env::Workspace::Full { path, clone }) => (Some(dir.join(path)), *clone),
    };
    let opts = CreateOpts {
        agent: e.agent.clone(),
        image: e.sandbox_options.template.clone(),
        name: e.name.clone(),
        no_workspace: ws.is_none(),
        workspace: ws,
        clone,
        env: e.env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        mem_mib: e
            .sandbox_options
            .memory
            .as_deref()
            .and_then(parse_mem)
            .unwrap_or(2048),
        cpus: e
            .sandbox_options
            .cpus
            .filter(|c| *c > 0)
            .map_or(2, |c| u8::try_from(c.min(32)).unwrap_or(32)),
        kits: kit_sources,
        kvm: false,
        docker: false,
        template: None,
        root_size_mib: e
            .sandbox_options
            .root_size
            .as_deref()
            .and_then(parse_mem)
            .map(|m| m as u64),
        mounts: e
            .mounts
            .iter()
            .map(|(k, v)| (k.clone(), PathBuf::from(v)))
            .collect(),
    };
    let name = opts
        .name
        .clone()
        .unwrap_or_else(|| default_name(&opts.agent, opts.workspace.as_deref()));
    if !sandbox_dir(&name).join("sandbox.json").exists() {
        create(&CreateOpts {
            name: Some(name.clone()),
            ..opts
        })?;
    } else {
        // resources stated in the file apply to the existing sandbox at its next start
        let mut rec = Record::load(&name)?;
        let before = (rec.mem_mib, rec.cpus, rec.root_size_mib);
        if e.sandbox_options.memory.is_some() {
            rec.mem_mib = opts.mem_mib;
        }
        if e.sandbox_options.cpus.is_some() {
            rec.cpus = opts.cpus;
        }
        if opts.root_size_mib.is_some() {
            rec.root_size_mib = opts.root_size_mib;
        }
        if (rec.mem_mib, rec.cpus, rec.root_size_mib) != before {
            rec.save()?;
            if supervisor::is_running(&name) {
                eprintln!(
                    "note: resources changed (memory {} MiB, {} vCPUs, disk {}); they apply after `osbx stop {name}`",
                    rec.mem_mib,
                    rec.cpus,
                    rec.root_size_mib
                        .map_or("unchanged".into(), |m| format!("{m} MiB"))
                );
            }
        }
    }
    start(&name)?;
    for p in &e.ports {
        let host = format!(
            "{}:{}",
            p.host_ip
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("127.0.0.1"),
            p.host.unwrap_or(0)
        );
        match supervisor::request(
            &name,
            json!({"op": "publish", "host": host, "guest": p.sandbox}),
        ) {
            Ok(v) => eprintln!(
                "published {} -> sandbox port {}",
                v["host"].as_str().unwrap_or("?"),
                p.sandbox
            ),
            Err(err) => eprintln!("warning: port {}: {err}", p.sandbox),
        }
    }
    if detach {
        return Ok(0);
    }
    let rec = Record::load(&name)?;
    let tty = client::is_tty(0) && client::is_tty(1);
    let mut req = agent_request(&rec, &e.cmd.clone().unwrap_or_default());
    if let Some(ep) = &e.entrypoint {
        req.argv = ep
            .iter()
            .cloned()
            .chain(req.argv.into_iter().skip(rec.launch.argv.len().min(1)))
            .collect();
    }
    client::exec(&name, req, Attach { stdin: true, tty })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_images() {
        assert_eq!(
            default_name("shell", Some(Path::new("/home/me/my proj"))),
            "shell-my-proj"
        );
        assert_eq!(default_name("docker.io/sbx/claude:1.0", None), "claude");
        assert_eq!(image_for("shell"), "ubuntu:24.04");
        assert_eq!(image_for("debian:12"), "debian:12");
        assert_eq!(image_for("claude"), "docker.io/sbx/claude:latest");
        assert_eq!(parse_mem("16g"), Some(16384));
        assert_eq!(parse_mem("512m"), Some(512));
        assert_eq!(parse_mem("x"), None);
    }

    #[test]
    fn agent_request_prefers_workspace_and_image_user() {
        let rec = Record {
            name: "n".into(),
            agent: "shell".into(),
            image: "i".into(),
            workspace: Some(Workspace {
                host: "/w".into(),
                mode: WorkspaceMode::Direct,
            }),
            env: BTreeMap::new(),
            mem_mib: 512,
            cpus: 1,
            root_size_mib: None,
            launch: Launch {
                argv: vec!["claude".into()],
                env: vec![],
                user: "agent".into(),
                workdir: "/home/agent".into(),
            },
            created: 0,
            kits: vec![],
            docker: false,
            mounts: BTreeMap::new(),
        };
        let r = agent_request(&rec, &[]);
        assert_eq!(
            (r.argv, r.cwd.as_deref(), r.user.as_deref()),
            (vec!["claude".to_owned()], Some("/w"), Some("agent"))
        );
        let r = agent_request(&rec, &["bash".into()]);
        assert_eq!(r.argv, ["bash"]);
    }
}
