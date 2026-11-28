//! Canonical internal verbose specification IR for `osbx` sandbox environments.
//!
//! Both frontends — `osbx-env` (`sbxenv.yaml`) and `osbx-compose` (`osbx-compose.yml`) — parse,
//! layer, interpolate, and lower their surface syntax into [`ProjectSpec`] / [`SandboxSpec`].
//! Every shorthand (port strings, volume strings, size suffixes, boolean capability toggles,
//! reusable top-level resources) is normalized here into explicit, strongly-typed fields.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Agents the runtime ships as built-ins.
pub const BUILTIN_AGENTS: &[&str] = &[
    "claude",
    "codex",
    "copilot",
    "cursor",
    "devin",
    "docker-agent",
    "droid",
    "kiro",
    "opencode",
    "shell",
];

/// Validation or normalization error for a compiled specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecError(pub String);

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SpecError {}

fn bad<T>(msg: impl Into<String>) -> Result<T, SpecError> {
    Err(SpecError(msg.into()))
}

/// Parse a human-readable size string into MiB (`"8G"`, `"512m"`, `"128Gi"`, `"1T"`, or plain MiB).
pub fn parse_size_mib(raw: &str) -> Result<u64, SpecError> {
    let s = raw.trim();
    if s.is_empty() {
        return bad("size must not be empty");
    }
    let lower = s.to_ascii_lowercase();
    let (num_str, mult): (&str, u64) = if let Some(n) = lower
        .strip_suffix("tib")
        .or_else(|| lower.strip_suffix("ti"))
        .or_else(|| lower.strip_suffix("tb"))
        .or_else(|| lower.strip_suffix('t'))
    {
        (n, 1024 * 1024)
    } else if let Some(n) = lower
        .strip_suffix("gib")
        .or_else(|| lower.strip_suffix("gi"))
        .or_else(|| lower.strip_suffix("gb"))
        .or_else(|| lower.strip_suffix('g'))
    {
        (n, 1024)
    } else if let Some(n) = lower
        .strip_suffix("mib")
        .or_else(|| lower.strip_suffix("mi"))
        .or_else(|| lower.strip_suffix("mb"))
        .or_else(|| lower.strip_suffix('m'))
    {
        (n, 1)
    } else {
        (lower.as_str(), 1)
    };
    let n: u64 = num_str.trim().parse().map_err(|_| {
        SpecError(format!(
            "invalid size {raw:?} (expected e.g. 8G, 512M, or MiB)"
        ))
    })?;
    if n == 0 {
        return bad(format!("size {raw:?} must be greater than zero"));
    }
    n.checked_mul(mult)
        .ok_or_else(|| SpecError(format!("size {raw:?} overflows MiB")))
}

/// A compiled multi-sandbox project specification.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectSpec {
    /// Optional project name (used as default sandbox/volume prefix).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Declared named persistent volumes (referenced by [`MountKind::Volume`] mounts).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, VolumeSpec>,
    /// Fully resolved sandbox specifications, keyed by logical service/sandbox key.
    #[serde(default)]
    pub sandboxes: BTreeMap<String, SandboxSpec>,
}

/// Backing storage driver for a named volume.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "driver", rename_all = "snake_case")]
pub enum VolumeDriver {
    /// Persistent directory managed by `osbx` under `$OSBX_HOME/volumes`.
    #[default]
    Managed,
    /// Host directory explicitly chosen by the user.
    Host {
        /// Resolved host path.
        path: String,
    },
}

/// A named volume declaration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeSpec {
    /// Where the volume's data lives on the host.
    #[serde(flatten)]
    pub driver: VolumeDriver,
}

/// Base image pull policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PullPolicy {
    /// Always check/pull from the registry.
    Always,
    /// Pull only if not cached locally.
    Missing,
    /// Never pull; fail if not present locally.
    Never,
}

/// Agent skills sharing mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SkillsMode {
    /// Do not expose host skills.
    Off,
    /// Expose host skills read-only.
    Readonly,
    /// Expose host skills read-write.
    Readwrite,
}

/// How a primary workspace or git volume is shared with the sandbox.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceMode {
    /// Live bidirectional share.
    #[default]
    Direct,
    /// Private git clone inside the sandbox; original repo mounted read-only at `/run/sandbox/source`.
    Clone,
}

/// Pluggable host-to-guest file-sharing backend for Windows-guest sandboxes (ignored on Linux,
/// which always uses kernel `virtiofs`).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ShareBackend {
    /// Automatically pick the best available backend in the guest
    /// (`virtiofs-native` -> `winfsp` -> `dokany` -> `projfs` -> `sync`).
    #[default]
    Auto,
    /// Pure-Rust bidirectional sync over `viosock` onto native NTFS (zero guest drivers).
    Sync,
    /// Windows inbox Projected File System (`ProjectedFSLib.dll`) over `viosock`.
    Projfs,
    /// Live `virtio-fs` (`viofs.sys`) via dynamically loaded LGPL-3.0 `dokan2.dll`.
    Dokany,
    /// Live `virtio-fs` (`viofs.sys`) via out-of-process WinFsp `virtiofs.exe`.
    #[serde(rename = "winfsp")]
    WinFsp,
    /// Reserved for a future standalone Apache-2.0 kernel `viofs` IFS driver.
    VirtiofsNative,
}

impl ShareBackend {
    /// Canonical lowercase string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Sync => "sync",
            Self::Projfs => "projfs",
            Self::Dokany => "dokany",
            Self::WinFsp => "winfsp",
            Self::VirtiofsNative => "virtiofs-native",
        }
    }

    /// True if this backend can use a PCIe `virtio-fs` device.
    pub const fn uses_virtiofs_pci(self) -> bool {
        matches!(
            self,
            Self::Auto | Self::Dokany | Self::WinFsp | Self::VirtiofsNative
        )
    }

    /// True if this backend can use the host `FILE_SYNC_PORT` vsock file RPC service.
    pub const fn uses_file_sync(self) -> bool {
        matches!(self, Self::Auto | Self::Sync | Self::Projfs)
    }
}

impl std::fmt::Display for ShareBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ShareBackend {
    type Err = SpecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "sync" => Ok(Self::Sync),
            "projfs" => Ok(Self::Projfs),
            "dokany" | "dokan" => Ok(Self::Dokany),
            "winfsp" => Ok(Self::WinFsp),
            "virtiofs-native" | "virtiofs_native" => Ok(Self::VirtiofsNative),
            other => bad(format!(
                "invalid share backend {other:?} (expected auto|sync|projfs|dokany|winfsp|virtiofs-native)"
            )),
        }
    }
}

/// True if `p` is a valid absolute Linux (`/foo`) or Windows (`C:\foo` / `C:/foo`) guest path.
pub fn is_valid_guest_path(p: &str) -> bool {
    if p.starts_with('/') {
        return !p.contains(':');
    }
    let b = p.as_bytes();
    b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && matches!(b[2], b'\\' | b'/')
        && !p[2..].contains(':')
}

/// A primary workspace declaration (used by `sbxenv.yaml` and optional single-repo setups).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSpec {
    /// Host path of the workspace directory.
    pub host_path: String,
    /// Optional explicit guest mount path (when `None`, mirrors host path via `guest_path()`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_path: Option<String>,
    /// Direct live share or private git clone.
    #[serde(default)]
    pub mode: WorkspaceMode,
    /// Windows file-sharing backend (`auto` by default).
    #[serde(default)]
    pub backend: ShareBackend,
}

/// What kind of mount a [`MountSpec`] represents.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MountKind {
    /// Direct host directory bind mount.
    Bind,
    /// Named persistent volume declared under [`ProjectSpec::volumes`].
    Volume,
    /// Git repository mounted as a private clone (host repo mounted read-only as source).
    Clone,
    /// Host directory binding for a kit's `host-mount@1` capability.
    KitMount,
}

/// A fully resolved mount into the sandbox guest filesystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountSpec {
    /// Mount type.
    pub kind: MountKind,
    /// Host path (for `Bind`, `Clone`, `KitMount`) or named volume key (for `Volume`).
    pub source: String,
    /// Absolute path inside the sandbox guest (`/abs/path` on Linux or `C:\path` on Windows).
    pub target: String,
    /// Mount read-only inside the guest.
    #[serde(default)]
    pub read_only: bool,
    /// Optional octal permissions hint (e.g. `"0700"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Optional owning kit handle when [`MountKind::KitMount`] is scoped to a specific kit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kit: Option<String>,
    /// Windows file-sharing backend (`auto` by default).
    #[serde(default)]
    pub backend: ShareBackend,
}

/// Disk sizes in MiB.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisksSpec {
    /// Root ext4 disk size in MiB (grown online, never shrunk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_mib: Option<u64>,
    /// Docker data disk size in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_mib: Option<u64>,
    /// Cloned-workspace disk size in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloned_workspace_mib: Option<u64>,
}

/// Compute and storage resources for a sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcesSpec {
    /// vCPU count (`Some(0)` = auto).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u32>,
    /// Guest RAM in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u64>,
    /// Disk allocations.
    #[serde(default)]
    pub disks: DisksSpec,
}

/// A capability toggle with optionality semantics (matching Kit v3 capability selection).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToggle {
    /// Whether this capability is requested.
    pub enabled: bool,
    /// If `true` and the host cannot satisfy it, refuse sandbox creation; if `false`, skip.
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool {
    true
}

impl CapabilityToggle {
    /// Convenience constructor for an enabled capability with explicit `required` flag.
    pub const fn new(enabled: bool, required: bool) -> Self {
        Self { enabled, required }
    }
}

/// Host SSH agent forwarding configuration (`ssh-agent@1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshAgentSpec {
    /// Whether host SSH agent forwarding is requested.
    pub enabled: bool,
    /// If `true`, refuse sandbox creation when `SSH_AUTH_SOCK` is absent.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Forward all SSH agent operations without filtering.
    #[serde(default)]
    pub unrestricted: bool,
    /// Allowed `SSHSIG` signing namespaces when `unrestricted` is `false`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sign_namespaces: Vec<String>,
}

/// Host hardware and runtime capabilities granted to a sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilitiesSpec {
    /// Hardware virtualization inside the sandbox (`/dev/kvm` + `/dev/vhost-vsock`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvm: Option<CapabilityToggle>,
    /// Docker Engine inside the sandbox (`dockerd@1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker: Option<CapabilityToggle>,
    /// Privileged mode (`privileged@1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<CapabilityToggle>,
    /// Nested virtualization hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested: Option<bool>,
    /// GPU passthrough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<bool>,
    /// Display socket forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<bool>,
    /// FUSE enabled inside the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuse: Option<bool>,
    /// USB device selectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usb: Vec<String>,
    /// Host SSH agent forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_agent: Option<SshAgentSpec>,
}

/// Agent-specific runtime behavior knobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentOptionsSpec {
    /// Host skills mount mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skills: Option<SkillsMode>,
    /// Allow the sandbox to modify its own environment files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable_env_files: Option<bool>,
}

/// Where a kit comes from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KitSourceKind {
    /// OCI registry reference (optionally `:tag` and `@digest`).
    Oci,
    /// Local directory or ZIP archive (`./x`, `../x`, `.`, `..`, `/abs/x`, `*.zip`).
    Local,
    /// `git+https://...#dir=...`.
    Git,
}

/// A resolved kit reference attached to a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KitSpec {
    /// Raw source string (local path, OCI ref, or git URL).
    pub source: String,
    /// Classified source kind.
    pub kind: KitSourceKind,
    /// Handle used for `agent:` matching and scoped kit arguments.
    pub handle: String,
    /// Optional content digest (`sha256:...`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Create-phase kit arguments.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,
    /// Kit-scoped `host-mount@1` bindings (`guest_path -> host_path`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mounts: BTreeMap<String, String>,
}

impl KitSpec {
    /// Classify a raw kit source string.
    ///
    /// `./`, `../`, `.`, `..`, absolute paths, and `*.zip` are local; `git+` is git;
    /// bare `org/tool` is an OCI registry reference.
    pub fn classify(source: &str) -> KitSourceKind {
        if source.starts_with("git+") {
            KitSourceKind::Git
        } else if source == "."
            || source == ".."
            || source.starts_with("./")
            || source.starts_with("../")
            || source.starts_with('/')
            || source.ends_with(".zip")
            || (source.as_bytes().get(1) == Some(&b':')
                && source
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic))
        {
            KitSourceKind::Local
        } else {
            KitSourceKind::Oci
        }
    }

    /// Derive the handle for a raw kit source string.
    pub fn derive_handle(source: &str, kind: KitSourceKind) -> String {
        let last = |p: &str| {
            p.trim_end_matches(['/', '\\'])
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(p)
                .to_owned()
        };
        match kind {
            KitSourceKind::Git => source.split_once("dir=").map_or_else(
                || last(source.split('#').next().unwrap_or(source)),
                |(_, d)| last(d.split('&').next().unwrap_or(d)),
            ),
            KitSourceKind::Local => last(source.strip_suffix(".zip").unwrap_or(source)),
            KitSourceKind::Oci => {
                let no_digest = source.split('@').next().unwrap_or(source);
                let repo = match no_digest.rsplit_once(':') {
                    Some((r, t)) if !t.contains('/') => r,
                    _ => no_digest,
                };
                last(repo)
            }
        }
    }

    /// Construct a [`KitSpec`] from its raw source and optional metadata.
    pub fn from_source(
        source: impl Into<String>,
        digest: Option<String>,
        args: BTreeMap<String, String>,
        mounts: BTreeMap<String, String>,
    ) -> Self {
        let source = source.into();
        let kind = Self::classify(&source);
        let handle = Self::derive_handle(&source, kind);
        Self {
            source,
            kind,
            handle,
            digest,
            args,
            mounts,
        }
    }
}

/// Transport protocol for a published port.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    /// TCP (IPv4 or IPv6).
    Tcp,
    /// TCP over IPv4 (default).
    #[default]
    Tcp4,
    /// TCP over IPv6.
    Tcp6,
    /// UDP (IPv4 or IPv6).
    Udp,
    /// UDP over IPv4.
    Udp4,
    /// UDP over IPv6.
    Udp6,
}

impl std::str::FromStr for PortProtocol {
    type Err = SpecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "tcp4" => Ok(Self::Tcp4),
            "tcp6" => Ok(Self::Tcp6),
            "udp" => Ok(Self::Udp),
            "udp4" => Ok(Self::Udp4),
            "udp6" => Ok(Self::Udp6),
            other => bad(format!(
                "invalid port protocol {other:?} (expected tcp|tcp4|tcp6|udp|udp4|udp6)"
            )),
        }
    }
}

/// A published sandbox port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortSpec {
    /// Host bind address (canonicalized; default `"127.0.0.1"`).
    pub host_ip: String,
    /// Host port (`0` = ephemeral).
    pub host: u16,
    /// Guest port (`1..=65535`).
    pub target: u16,
    /// Transport protocol.
    #[serde(default)]
    pub protocol: PortProtocol,
}

/// Default egress posture for a sandbox firewall.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallDefault {
    /// Deny all unless explicitly allowed (`osbx_policy::Preset::DenyAll`).
    Deny,
    /// Deny by default plus the built-in developer baseline (`osbx_policy::Preset::Balanced`).
    Balanced,
    /// Allow all unless explicitly denied (`osbx_policy::Preset::AllowAll`).
    Allow,
}

impl FirewallDefault {
    /// Convert to [`osbx_policy::Preset`].
    pub const fn to_preset(self) -> osbx_policy::Preset {
        match self {
            Self::Deny => osbx_policy::Preset::DenyAll,
            Self::Balanced => osbx_policy::Preset::Balanced,
            Self::Allow => osbx_policy::Preset::AllowAll,
        }
    }
}

/// Firewall rule action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    /// Permit matching traffic.
    Allow,
    /// Block matching traffic (explicit deny always wins over allow).
    Deny,
}

/// Lifecycle phase in which a firewall rule is active.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallPhase {
    /// Active throughout normal sandbox execution.
    #[default]
    Runtime,
    /// Active only during first-boot install hooks.
    Install,
}

/// Layer-7 HTTP matching constraints for a firewall rule (`network-policy@2`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpMatchSpec {
    /// Allowed HTTP methods (empty = any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Optional path glob (`*` matches any chars including `/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Required query parameters (all must match).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
}

/// A single canonical firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallRule {
    /// Allow or deny.
    pub action: FirewallAction,
    /// Destination pattern (`host`, `host:port`, `*.domain`, IP, CIDR, `**`).
    pub dest: String,
    /// Active phase.
    #[serde(default)]
    pub phase: FirewallPhase,
    /// Optional HTTP-layer constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpMatchSpec>,
}

/// Egress firewall specification for a sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallSpec {
    /// Optional default preset override (`None` inherits host `policy.json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<FirewallDefault>,
    /// Explicit sandbox-scoped rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<FirewallRule>,
}

/// Where a secret value is obtained on the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SecretSource {
    /// Literal value (discouraged; should not be committed).
    Value(String),
    /// Vault reference (e.g. `op://...` or AWS Secrets Manager ARN).
    Ref(String),
    /// Host shell command printing the secret to stdout.
    Command(String),
}

/// Vault backend selector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretBackend {
    /// Native SDK backend.
    Sdk,
    /// External CLI backend.
    Cli,
}

impl std::str::FromStr for SecretBackend {
    type Err = SpecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sdk" => Ok(Self::Sdk),
            "cli" => Ok(Self::Cli),
            other => bad(format!(
                "invalid secret backend {other:?} (expected sdk|cli)"
            )),
        }
    }
}

/// A standalone secret value resolution spec (used for registry logins and secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretValueSpec {
    /// How the host obtains the secret.
    pub source: SecretSource,
    /// Skip one-shot resolution check during plan/create.
    #[serde(default)]
    pub no_verify: bool,
    /// Refresh cadence (`"on-demand"`, `"55m"`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<String>,
    /// Vault backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<SecretBackend>,
    /// Snapshot the create-time resolved value as a literal.
    #[serde(default)]
    pub snapshot: bool,
}

impl SecretValueSpec {
    /// True if this secret embeds a literal value.
    pub const fn is_literal(&self) -> bool {
        matches!(self.source, SecretSource::Value(_))
    }

    /// Validate snapshot invariants.
    pub fn validate(&self, name: &str) -> Result<(), SpecError> {
        if self.snapshot {
            if self.is_literal() {
                return bad(format!("secret {name:?}: snapshot needs ref or command"));
            }
            if self.refresh.is_some() || self.no_verify {
                return bad(format!(
                    "secret {name:?}: snapshot cannot be combined with refresh or no_verify"
                ));
            }
        }
        Ok(())
    }
}

/// Approved domains for proxy-side credential presentation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindingSpec {
    /// Approved domains for static API-key injection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_key_domains: Vec<String>,
    /// Approved domains for host-managed OAuth.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oauth_domains: Vec<String>,
}

/// Custom proxy header injection rule for a non-built-in secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretInjectRule {
    /// Destination domain pattern.
    pub domain: String,
    /// HTTP header name (default `"Authorization"`).
    pub header: String,
    /// Format string with `%s` placeholder (default `"%s"`).
    pub format: String,
}

/// Custom injection specification for a secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretInjectSpec {
    /// Guest environment variable carrying the sentinel placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Domain/header injection rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SecretInjectRule>,
}

/// A sandbox-scoped proxy-injected secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretSpec {
    /// Value resolution configuration (optional when only domain bindings are declared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SecretValueSpec>,
    /// Whether sandbox creation should fail if this secret cannot be resolved.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Approved domains per mechanism.
    #[serde(default)]
    pub bindings: BindingSpec,
    /// Optional custom proxy injection rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject: Option<SecretInjectSpec>,
}

impl SecretSpec {
    /// True if this secret embeds a literal value.
    pub fn is_literal(&self) -> bool {
        self.value.as_ref().is_some_and(SecretValueSpec::is_literal)
    }
}

/// An OCI registry login.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySpec {
    /// Password or access token.
    pub secret: SecretValueSpec,
    /// Optional username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<SecretValueSpec>,
}

/// Transport for an MCP server registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum McpTransport {
    /// Remote HTTP/SSE MCP server.
    Remote {
        /// Server URL.
        url: String,
    },
    /// Host-side stdio MCP server.
    Stdio {
        /// Command executable.
        command: String,
        /// Command arguments.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
    },
}

/// An MCP server registered for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpServerSpec {
    /// Registration name.
    pub name: String,
    /// Connection transport.
    #[serde(flatten)]
    pub transport: McpTransport,
}

/// A host-side lifecycle hook command (runs with user privileges).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostCommandSpec {
    /// Optional display label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Shell command (`sh -c` on Unix, `cmd /c` on Windows).
    pub command: String,
    /// Optional working directory (default: file/project directory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Optional timeout string (e.g. `"5m"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// A file written inside the guest on boot (inline sugar over kit `lifecycle@1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestFileSpec {
    /// Absolute path inside the guest.
    pub path: String,
    /// File contents.
    pub content: String,
    /// Optional octal mode (e.g. `"0644"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Whether to overwrite an existing file on subsequent boots.
    #[serde(default)]
    pub overwrite: bool,
}

/// An in-guest install or startup command (inline sugar over kit `lifecycle@1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestCommandSpec {
    /// Shell command executed inside the guest.
    pub command: String,
    /// Optional guest user to run as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Run in background (startup hooks only).
    #[serde(default)]
    pub background: bool,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Host and guest lifecycle hooks for a sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HooksSpec {
    /// Host hook: runs before resolution on create and attach (must be idempotent).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initialize: Vec<HostCommandSpec>,
    /// Host hook: runs after create, before attach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_create: Vec<HostCommandSpec>,
    /// Host hook: runs before sandbox removal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_remove: Vec<HostCommandSpec>,
    /// In-guest files seeded at boot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guest_files: Vec<GuestFileSpec>,
    /// In-guest install commands (run once on first boot).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guest_install: Vec<GuestCommandSpec>,
    /// In-guest startup commands (run on every boot).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guest_startup: Vec<GuestCommandSpec>,
}

impl HooksSpec {
    /// True if any host-privileged hook is configured.
    pub fn has_host_hooks(&self) -> bool {
        !self.initialize.is_empty() || !self.post_create.is_empty() || !self.pre_remove.is_empty()
    }
}

/// Canonical verbose specification for a single sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxSpec {
    /// Explicit runtime sandbox name (if `None`, derived from project/key/agent/workspace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Profiles this sandbox belongs to (empty = active by default).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// Built-in agent name or handle of a listed kit.
    pub agent: String,
    /// Explicit OCI image override (exclusive with `template`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Saved `osbx save` template name (exclusive with `image`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Base image pull policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<PullPolicy>,
    /// Replaces image entrypoint (`Some(vec![])` clears).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Replaces default command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Explicit guest working directory (e.g. `"/workspace"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Primary workspace binding, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceSpec>,
    /// All explicit mounts (bind mounts, named volumes, clone mounts, kit host-mount overrides).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountSpec>,
    /// Resolved guest environment variables.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Compute and disk resources.
    #[serde(default)]
    pub resources: ResourcesSpec,
    /// Hardware and runtime capabilities.
    #[serde(default)]
    pub capabilities: CapabilitiesSpec,
    /// Agent-specific options.
    #[serde(default)]
    pub agent_options: AgentOptionsSpec,
    /// Kits to compose into this sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kits: Vec<KitSpec>,
    /// Published ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortSpec>,
    /// Egress firewall configuration.
    #[serde(default)]
    pub firewall: FirewallSpec,
    /// Sandbox-scoped proxy-injected secrets and bindings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretSpec>,
    /// OCI registry credentials.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub registries: BTreeMap<String, RegistrySpec>,
    /// Registered MCP servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp: Vec<McpServerSpec>,
    /// Host and guest lifecycle hooks.
    #[serde(default)]
    pub hooks: HooksSpec,
}

impl ProjectSpec {
    /// Validate cross-field invariants across the entire project.
    pub fn validate(&self) -> Result<(), SpecError> {
        for (key, sb) in &self.sandboxes {
            sb.validate(key, &self.volumes)?;
        }
        Ok(())
    }

    /// Return the sandbox keys that are active given the enabled `profiles`.
    ///
    /// A sandbox with no profiles is always active; a sandbox with profiles is active
    /// when at least one of its profiles appears in `profiles`.
    pub fn active_sandboxes<'a>(&'a self, profiles: &[String]) -> Vec<(&'a str, &'a SandboxSpec)> {
        self.sandboxes
            .iter()
            .filter(|(_, sb)| {
                sb.profiles.is_empty() || sb.profiles.iter().any(|p| profiles.contains(p))
            })
            .map(|(k, v)| (k.as_str(), v))
            .collect()
    }
}

impl SandboxSpec {
    /// Validate invariants for one sandbox specification.
    pub fn validate(
        &self,
        key: &str,
        declared_volumes: &BTreeMap<String, VolumeSpec>,
    ) -> Result<(), SpecError> {
        if self.agent.is_empty() {
            return bad(format!("sandbox {key:?}: agent is required"));
        }
        if self.image.is_some() && self.template.is_some() {
            return bad(format!(
                "sandbox {key:?}: image and template are mutually exclusive"
            ));
        }
        let handles: Vec<&str> = self.kits.iter().map(|k| k.handle.as_str()).collect();
        if !BUILTIN_AGENTS.contains(&self.agent.as_str()) && !handles.contains(&self.agent.as_str())
        {
            return bad(format!(
                "sandbox {key:?}: agent {:?} is neither a built-in nor the handle of a listed kit (handles: {handles:?})",
                self.agent
            ));
        }
        let mut seen_handles = BTreeSet::new();
        for h in &handles {
            if !seen_handles.insert(*h) {
                return bad(format!("sandbox {key:?}: two kits share the handle {h:?}"));
            }
        }
        if let Some(wd) = &self.workdir
            && !is_valid_guest_path(wd)
        {
            return bad(format!(
                "sandbox {key:?}: workdir {wd:?} must be an absolute guest path"
            ));
        }
        if let Some(ws) = &self.workspace {
            if ws.host_path.trim().is_empty() {
                return bad(format!("sandbox {key:?}: workspace path must not be blank"));
            }
            if let Some(gp) = &ws.guest_path
                && !is_valid_guest_path(gp)
            {
                return bad(format!(
                    "sandbox {key:?}: workspace target {gp:?} must be an absolute Unix or Windows path"
                ));
            }
        }
        for m in &self.mounts {
            if m.source.trim().is_empty() {
                return bad(format!(
                    "sandbox {key:?}: mount source for {:?} must not be blank",
                    m.target
                ));
            }
            if !is_valid_guest_path(&m.target) {
                return bad(format!(
                    "sandbox {key:?}: mount target {:?} must be an absolute Unix or Windows path",
                    m.target
                ));
            }
            if m.kind == MountKind::Volume && !declared_volumes.contains_key(&m.source) {
                return bad(format!(
                    "sandbox {key:?}: volume mount references undeclared top-level volume {:?}",
                    m.source
                ));
            }
        }
        for k in &self.kits {
            for target in k.mounts.keys() {
                if !is_valid_guest_path(target) {
                    return bad(format!(
                        "sandbox {key:?}: kit {:?} mount target {target:?} must be an absolute Unix or Windows path",
                        k.handle
                    ));
                }
            }
        }
        for p in &self.ports {
            if p.target == 0 {
                return bad(format!("sandbox {key:?}: port target must be 1..=65535"));
            }
        }
        for r in &self.firewall.rules {
            r.dest.parse::<osbx_policy::Destination>().map_err(|e| {
                SpecError(format!(
                    "sandbox {key:?}: invalid firewall destination {:?}: {e}",
                    r.dest
                ))
            })?;
        }
        for (name, sec) in &self.secrets {
            if let Some(v) = &sec.value {
                v.validate(name)?;
            }
            for d in sec
                .bindings
                .api_key_domains
                .iter()
                .chain(&sec.bindings.oauth_domains)
            {
                d.parse::<osbx_policy::Destination>().map_err(|e| {
                    SpecError(format!(
                        "sandbox {key:?}: secret {name:?}: invalid binding domain {d:?}: {e}"
                    ))
                })?;
            }
            if let Some(inj) = &sec.inject {
                for rule in &inj.rules {
                    rule.domain
                        .parse::<osbx_policy::Destination>()
                        .map_err(|e| {
                            SpecError(format!(
                                "sandbox {key:?}: secret {name:?}: invalid inject domain {:?}: {e}",
                                rule.domain
                            ))
                        })?;
                }
            }
        }
        for (reg_name, reg) in &self.registries {
            reg.secret.validate(reg_name)?;
            if let Some(u) = &reg.username {
                u.validate(reg_name)?;
            }
        }
        for f in &self.hooks.guest_files {
            if !is_valid_guest_path(&f.path) {
                return bad(format!(
                    "sandbox {key:?}: guest file path {:?} must be absolute",
                    f.path
                ));
            }
        }
        Ok(())
    }

    /// Collect all `host-mount@1` overrides (`guest_path -> host_path`) from both
    /// `mounts` (`KitMount` / `Bind`) and kit-scoped `kits[].mounts`.
    pub fn kit_mount_overrides(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for m in &self.mounts {
            if matches!(m.kind, MountKind::KitMount | MountKind::Bind) {
                out.insert(m.target.clone(), m.source.clone());
            }
        }
        for k in &self.kits {
            for (guest, host) in &k.mounts {
                out.insert(guest.clone(), host.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size_mib("8G").unwrap(), 8192);
        assert_eq!(parse_size_mib("128Gi").unwrap(), 131_072);
        assert_eq!(parse_size_mib("512m").unwrap(), 512);
        assert_eq!(parse_size_mib("2048").unwrap(), 2048);
        assert_eq!(parse_size_mib("1T").unwrap(), 1024 * 1024);
        assert!(parse_size_mib("0G").is_err());
        assert!(parse_size_mib("abc").is_err());
    }

    #[test]
    fn kit_classification_and_handles() {
        let k = |s: &str| KitSpec::from_source(s, None, BTreeMap::new(), BTreeMap::new());
        assert_eq!(k("sbx/claude").handle, "claude");
        assert_eq!(k("sbx/claude").kind, KitSourceKind::Oci);
        assert_eq!(k("sbx/gh:2.103.2@sha256:abc").handle, "gh");
        assert_eq!(k("registry:5000/org/tool:1").handle, "tool");
        assert_eq!(k("./kits/dev-tools").handle, "dev-tools");
        assert_eq!(k("./kits/dev-tools").kind, KitSourceKind::Local);
        assert_eq!(k("./dist/tool.zip").handle, "tool");
        assert_eq!(
            k("git+https://github.com/org/repo.git#dir=kits/tool").handle,
            "tool"
        );
        assert_eq!(
            k("git+https://github.com/org/repo.git#dir=kits/tool").kind,
            KitSourceKind::Git
        );
    }

    #[test]
    fn project_validation_catches_errors() {
        let mut sb = SandboxSpec {
            name: None,
            profiles: vec![],
            agent: "claude".into(),
            image: None,
            template: None,
            pull_policy: None,
            entrypoint: None,
            command: None,
            workdir: Some("/workspace".into()),
            workspace: None,
            mounts: vec![MountSpec {
                kind: MountKind::Volume,
                source: "missing-vol".into(),
                target: "/data".into(),
                read_only: false,
                mode: None,
                kit: None,
                backend: ShareBackend::Auto,
            }],
            env: BTreeMap::new(),
            resources: ResourcesSpec::default(),
            capabilities: CapabilitiesSpec::default(),
            agent_options: AgentOptionsSpec::default(),
            kits: vec![],
            ports: vec![],
            firewall: FirewallSpec::default(),
            secrets: BTreeMap::new(),
            registries: BTreeMap::new(),
            mcp: vec![],
            hooks: HooksSpec::default(),
        };
        let proj = ProjectSpec {
            name: None,
            volumes: BTreeMap::new(),
            sandboxes: BTreeMap::from([("dev".into(), sb.clone())]),
        };
        assert!(
            proj.validate()
                .unwrap_err()
                .to_string()
                .contains("undeclared top-level volume")
        );

        sb.mounts.clear();
        let proj = ProjectSpec {
            name: None,
            volumes: BTreeMap::new(),
            sandboxes: BTreeMap::from([("dev".into(), sb)]),
        };
        assert!(proj.validate().is_ok());
    }

    #[test]
    fn share_backend_and_windows_guest_paths() {
        assert_eq!("auto".parse::<ShareBackend>().unwrap(), ShareBackend::Auto);
        assert_eq!("sync".parse::<ShareBackend>().unwrap(), ShareBackend::Sync);
        assert_eq!(
            "projfs".parse::<ShareBackend>().unwrap(),
            ShareBackend::Projfs
        );
        assert_eq!(
            "dokany".parse::<ShareBackend>().unwrap(),
            ShareBackend::Dokany
        );
        assert_eq!(
            "winfsp".parse::<ShareBackend>().unwrap(),
            ShareBackend::WinFsp
        );
        assert_eq!(
            "virtiofs-native".parse::<ShareBackend>().unwrap(),
            ShareBackend::VirtiofsNative
        );
        assert!(is_valid_guest_path("/workspace"));
        assert!(is_valid_guest_path(r"C:\workspace"));
        assert!(is_valid_guest_path("D:/mnt/data"));
        assert!(!is_valid_guest_path("relative/path"));
        assert!(!is_valid_guest_path("/bad:colon"));
        assert!(!is_valid_guest_path(r"C:\bad:colon"));
    }
}
