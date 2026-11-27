//! On-disk state: `$OSBX_HOME` (default `$XDG_DATA_HOME/osbx` or `~/.local/share/osbx`).
//!
//! ```text
//! policy.json                 preset + rules (shared by all sandboxes)
//! secrets/secrets.json        credential store (0700 dir, 0600 file)
//! images/<key>.img            root filesystems built from images (read-only bases)
//! sandboxes/<name>/sandbox.json   the sandbox's definition
//! sandboxes/<name>/root.img       its own copy of the root filesystem
//! sandboxes/<name>/ca.pem, ca.key its TLS-interception CA (key 0600)
//! sandboxes/<name>/control.sock   present while running (served by the supervisor)
//! sandboxes/<name>/supervisor.log, console.log
//! ```

use osbx_policy::{Action, Origin, PolicySet, Preset, Rule};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Root of all state.
pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("OSBX_HOME") {
        return PathBuf::from(h);
    }
    #[cfg(windows)]
    if let Some(x) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(x).join("osbx");
    }
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(x).join("osbx");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".local/share/osbx")
}

/// Guest kernel/initramfs/agent: `$OSBX_ASSETS`, else `<install dir>/guest` (beside `bin/`,
/// as the Windows and Flatpak layouts place it), else `<install dir>/share/osbx/guest`
/// (FHS layout, e.g. `/usr/share/osbx/guest` for `/usr/bin/osbx`), else `$OSBX_HOME/guest`.
pub fn assets_dir() -> PathBuf {
    if let Some(a) = std::env::var_os("OSBX_ASSETS") {
        return PathBuf::from(a);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| assets_dir_for_exe(&exe))
        .unwrap_or_else(|| home().join("guest"))
}

fn assets_dir_for_exe(exe: &Path) -> Option<PathBuf> {
    let prefix = exe.parent()?.parent()?;
    for rel in ["guest", "share/osbx/guest"] {
        let candidate = prefix.join(rel);
        if candidate.join("vmlinuz").exists() {
            return Some(candidate);
        }
    }
    None
}

/// `p` without Windows' verbatim prefix (`\\?\C:\x` -> `C:\x`, `\\?\UNC\h\s` -> `\\h\s`), as
/// `canonicalize` returns it; other paths unchanged.
pub fn plain_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match s.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => p.to_path_buf(),
    }
}

/// Where host directory `host` appears inside a sandbox. Unix hosts: the same absolute path.
/// Windows hosts: `C:\Users\me\proj` -> `/c/Users/me/proj` (the Docker Desktop / Git Bash
/// convention), `\\server\share\x` -> `/unc/server/share/x`.
pub fn guest_path(host: &Path) -> String {
    let s = plain_path(host).to_string_lossy().into_owned();
    if cfg!(windows) || s.contains('\\') || s.as_bytes().get(1) == Some(&b':') {
        let b = s.as_bytes();
        if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
            let rest = s[2..].replace('\\', "/");
            let rest = rest.trim_end_matches('/');
            return format!("/{}{rest}", (b[0] as char).to_ascii_lowercase());
        }
        if let Some(unc) = s.strip_prefix(r"\\") {
            return format!("/unc/{}", unc.replace('\\', "/").trim_end_matches('/'));
        }
    }
    s
}

/// Directory of one sandbox.
pub fn sandbox_dir(name: &str) -> PathBuf {
    home().join("sandboxes").join(name)
}

/// The supervisor's control socket. Unix socket paths are limited to ~108 bytes, so when the
/// sandbox directory is too deep the socket lives in a short per-user runtime directory instead
/// (`$XDG_RUNTIME_DIR` or the temp dir), keyed by the state root so separate `OSBX_HOME`s never
/// collide.
pub fn control_socket(name: &str) -> PathBuf {
    let p = sandbox_dir(name).join("control.sock");
    if p.as_os_str().len() < 100 {
        return p;
    }
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    // FNV-1a of the state root: stable, dependency-free, collision risk irrelevant at this scale
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in home().to_string_lossy().bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    base.join(format!("osbx-{h:016x}"))
        .join(format!("{name}.sock"))
}

/// Validate a sandbox name (it becomes a directory name and a hostname).
pub fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid sandbox name {name:?} (letters, digits, - _ ., at most 63)"
        ))
    }
}

/// How the workspace reaches the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceMode {
    /// Shared read-write at the same absolute path (changes are live on the host).
    Direct,
    /// Host repo shared read-only at /run/sandbox/source; the agent works on a private clone.
    Clone,
}

/// A workspace binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    /// Absolute host path.
    pub host: PathBuf,
    /// Mode.
    pub mode: WorkspaceMode,
}

/// An additional host-directory share (bind mount or named volume).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredShare {
    /// Absolute host directory.
    pub host_dir: PathBuf,
    /// Absolute path inside the guest.
    pub guest_path: String,
    /// Mount read-only inside the guest.
    #[serde(default)]
    pub read_only: bool,
}

/// Launch settings taken from the image config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Launch {
    /// Entrypoint + Cmd.
    pub argv: Vec<String>,
    /// Image environment (`K=V`).
    pub env: Vec<String>,
    /// User to run as (empty = root).
    pub user: String,
    /// Working directory.
    pub workdir: String,
}

/// Guest operating system running inside a sandbox microVM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestOs {
    /// Linux direct-boot microVM (default).
    #[default]
    Linux,
    /// Windows UEFI (Q35 PCIe + OVMF) VM.
    Windows,
}

/// A sandbox definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Name.
    pub name: String,
    /// Guest OS (`linux` by default; `windows` for UEFI Windows sandboxes).
    #[serde(default)]
    pub guest_os: GuestOs,
    /// Agent name or image reference it was created from.
    pub agent: String,
    /// Image reference the root filesystem was built from.
    pub image: String,
    /// Workspace, if any.
    pub workspace: Option<Workspace>,
    /// Extra environment for every command.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Guest RAM in MiB.
    pub mem_mib: usize,
    /// vCPUs.
    #[serde(default = "default_cpus")]
    pub cpus: u8,
    /// Root disk size in MiB (grown at start if larger than the disk; never shrunk).
    #[serde(default)]
    pub root_size_mib: Option<u64>,
    /// How to start the agent.
    #[serde(default)]
    pub launch: Launch,
    /// Kits composed into this sandbox.
    #[serde(default)]
    pub kits: Vec<crate::kits::KitRecord>,
    /// Start Docker Engine inside the sandbox (`--docker`; kits ask with `dockerd@1`).
    #[serde(default)]
    pub docker: bool,
    /// Host directories chosen for kit host-mount paths (sandbox path -> host dir).
    #[serde(default)]
    pub mounts: BTreeMap<String, PathBuf>,
    /// Explicit guest working directory (e.g. `workspace: /workspace` in `osbx-compose.yml`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Additional host directory / named volume shares mounted into the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_shares: Vec<StoredShare>,
    /// Optional per-sandbox egress firewall (preset override + allow/deny/HTTP rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<osbx_spec::FirewallSpec>,
    /// Attach an emulated CRB vTPM 2.0 device (`0xFED4_0000`, Windows UEFI guests).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vtpm: bool,
    /// Unix seconds.
    pub created: u64,
}

fn default_cpus() -> u8 {
    2
}

impl Record {
    /// Load `sandboxes/<name>/sandbox.json`.
    pub fn load(name: &str) -> io::Result<Record> {
        let p = sandbox_dir(name).join("sandbox.json");
        let data = std::fs::read(&p)
            .map_err(|e| io::Error::new(e.kind(), format!("no sandbox named {name:?} ({e})")))?;
        serde_json::from_slice(&data).map_err(|e| io::Error::other(format!("{}: {e}", p.display())))
    }
    /// Write it back (atomically).
    pub fn save(&self) -> io::Result<()> {
        let dir = sandbox_dir(&self.name);
        std::fs::create_dir_all(&dir)?;
        write_atomic(
            &dir.join("sandbox.json"),
            &serde_json::to_vec_pretty(self).map_err(io::Error::other)?,
        )
    }
    /// All sandboxes, sorted by name.
    pub fn all() -> Vec<Record> {
        let mut v: Vec<Record> = std::fs::read_dir(home().join("sandboxes"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| Record::load(&e.file_name().to_string_lossy()).ok())
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
}

/// Path to the credential-binding approvals file (`$OSBX_HOME/secrets/credentials.yaml`).
pub fn bindings_path() -> PathBuf {
    home().join("secrets").join("credentials.yaml")
}

/// Load credential bindings if `credentials.yaml` exists (`Ok(None)` when absent).
pub fn load_bindings() -> io::Result<Option<osbx_secrets::Bindings>> {
    let p = bindings_path();
    match std::fs::read_to_string(&p) {
        Ok(s) => osbx_secrets::Bindings::from_yaml(&s)
            .map(Some)
            .map_err(|e| io::Error::other(format!("{}: {e}", p.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write a file via a temporary sibling and rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

/// One persisted rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRule {
    /// `allow` or `deny`.
    pub action: String,
    /// Destination pattern.
    pub dest: String,
    /// Limit to one sandbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

/// `policy.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPolicy {
    /// `allow-all` | `balanced` | `deny-all`.
    pub preset: String,
    /// Local rules.
    #[serde(default)]
    pub rules: Vec<StoredRule>,
}

impl Default for StoredPolicy {
    fn default() -> Self {
        Self {
            preset: "balanced".into(),
            rules: Vec::new(),
        }
    }
}

impl StoredPolicy {
    /// Load (default: balanced, no rules).
    pub fn load() -> io::Result<StoredPolicy> {
        match std::fs::read(home().join("policy.json")) {
            Ok(d) => serde_json::from_slice(&d)
                .map_err(|e| io::Error::other(format!("policy.json: {e}"))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(StoredPolicy::default()),
            Err(e) => Err(e),
        }
    }
    /// Save.
    pub fn save(&self) -> io::Result<()> {
        std::fs::create_dir_all(home())?;
        write_atomic(
            &home().join("policy.json"),
            &serde_json::to_vec_pretty(self).map_err(io::Error::other)?,
        )
    }
    /// Turn into an evaluable policy (invalid stored rules are reported, not silently dropped).
    pub fn to_policy(&self) -> Result<PolicySet, String> {
        let mut p = PolicySet::new(self.preset.parse::<Preset>()?);
        for r in &self.rules {
            let action = match r.action.as_str() {
                "allow" => Action::Allow,
                "deny" => Action::Deny,
                other => return Err(format!("bad action {other:?} in policy.json")),
            };
            let origin = r.sandbox.clone().map_or(Origin::Local, Origin::Sandbox);
            p.rules
                .push(Rule::new(action, &r.dest, origin).map_err(|e| format!("{}: {e}", r.dest))?);
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_paths_map_into_the_guest() {
        assert_eq!(
            plain_path(Path::new(r"\\?\C:\Users\me\proj")),
            PathBuf::from(r"C:\Users\me\proj")
        );
        assert_eq!(
            plain_path(Path::new(r"\\?\UNC\srv\share\x")),
            PathBuf::from(r"\\srv\share\x")
        );
        assert_eq!(
            guest_path(Path::new(r"C:\Users\me\proj")),
            "/c/Users/me/proj"
        );
        assert_eq!(guest_path(Path::new(r"\\?\D:\work\")), "/d/work");
        assert_eq!(guest_path(Path::new(r"\\srv\share\x")), "/unc/srv/share/x");
        assert_eq!(guest_path(Path::new("/home/me/proj")), "/home/me/proj");
    }

    #[test]
    fn names() {
        assert!(check_name("my-sandbox_1.0").is_ok());
        for bad in ["", "-x", "a/b", "a b", "..", &"x".repeat(64)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn stored_policy_roundtrip_and_conversion() {
        let p = StoredPolicy {
            preset: "deny-all".into(),
            rules: vec![
                StoredRule {
                    action: "allow".into(),
                    dest: "api.github.com".into(),
                    sandbox: None,
                },
                StoredRule {
                    action: "deny".into(),
                    dest: "evil.example".into(),
                    sandbox: Some("s1".into()),
                },
            ],
        };
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<StoredPolicy>(&j).unwrap(), p);
        let set = p.to_policy().unwrap();
        assert_eq!(set.rules.len(), 2);
        assert_eq!(set.rules[1].origin, Origin::Sandbox("s1".into()));
        let bad = StoredPolicy {
            preset: "x".into(),
            rules: vec![],
        };
        assert!(bad.to_policy().is_err());
    }

    #[test]
    fn assets_dir_finds_sibling_and_fhs_layouts() {
        let root = std::env::temp_dir().join(format!(
            "osbx-assets-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let exe = root.join("usr/bin/osbx");
        let fhs = root.join("usr/share/osbx/guest");
        let sibling = root.join("usr/guest");

        std::fs::create_dir_all(&fhs).unwrap();
        std::fs::write(fhs.join("vmlinuz"), b"k").unwrap();
        assert_eq!(assets_dir_for_exe(&exe), Some(fhs.clone()));

        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("vmlinuz"), b"k").unwrap();
        assert_eq!(assets_dir_for_exe(&exe), Some(sibling));

        let _ = std::fs::remove_dir_all(&root);
    }
}
