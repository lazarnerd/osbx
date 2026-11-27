//! `sbxenv.yaml`: the declarative description of one sandbox environment.
//!
//! Decoding is strict (unknown keys anywhere are errors, as the reference requires).
//! Files layer: a user base (`~/.sbxenv.yaml`) beneath the project file, later files win.
//! `${{ env.args.<n> }}`, `${{ env.projectDir }}` and `${{ env.fileDir }}` expand
//! structurally into scalars only, so a value can never add keys.
//!
//! ASSUMPTION: layering deep-merges maps, replaces scalars and lists, and concatenates
//! the three `lifecycle` lists (base first) — the reference states only the last part.

use regex::Regex;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};
use std::collections::BTreeMap;
use std::sync::LazyLock;

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

static REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{\{\s*env\.([A-Za-z]+)(?:\.([A-Za-z_][A-Za-z0-9_]*))?\s*\}\}").unwrap()
});
static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());

/// Anything wrong with a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvError(pub String);
impl std::fmt::Display for EnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for EnvError {}
fn bad<T>(m: impl Into<String>) -> Result<T, EnvError> {
    Err(EnvError(m.into()))
}

/// A declared environment argument.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvArg {
    /// Shown in prompts.
    pub description: Option<String>,
    /// Used when no value is supplied (exclusive with `required`).
    pub default: Option<String>,
    /// Caller must supply it.
    pub required: Option<bool>,
    /// Accepted set (exclusive with `pattern`).
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    /// Regex for the whole value.
    pub pattern: Option<String>,
}

/// One `kits:` entry: a bare reference or `{source, args}`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum KitEntry {
    /// `- sbx/gh:2.1.0`
    Ref(String),
    /// `- {source: …, args: {…}}`
    Full(KitFull),
}
/// Long form of a kit entry.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KitFull {
    /// Where the kit comes from.
    pub source: String,
    /// Create-phase kit args.
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

/// Where a kit comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KitSource {
    /// OCI reference (registry, optionally `:tag` and `@digest`).
    Oci(String),
    /// Local directory or ZIP (`./x`, `../x`, `.`, `..`, `*.zip`).
    Local(String),
    /// `git+https://…#dir=…`.
    Git(String),
}

impl KitEntry {
    /// The raw source string.
    pub fn source(&self) -> &str {
        match self {
            Self::Ref(s) => s,
            Self::Full(f) => &f.source,
        }
    }
    /// Classify the source. Only `./`, `../`, `.`, `..` and `*.zip` are paths; a bare
    /// `kits/tool` is a registry reference.
    pub fn kind(&self) -> KitSource {
        let s = self.source();
        if s.starts_with("git+") {
            KitSource::Git(s.to_owned())
        } else if s == "."
            || s == ".."
            || s.starts_with("./")
            || s.starts_with("../")
            || s.ends_with(".zip")
        {
            KitSource::Local(s.to_owned())
        } else {
            KitSource::Oci(s.to_owned())
        }
    }
    /// The handle `agent:` uses: last path segment of the repository (tag/digest stripped),
    /// the `dir=` basename for git, or the directory name for a local path.
    pub fn handle(&self) -> String {
        let s = self.source();
        let last = |p: &str| {
            p.trim_end_matches('/')
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(p)
                .to_owned()
        };
        match self.kind() {
            KitSource::Git(g) => g.split_once("dir=").map_or_else(
                || last(g.split('#').next().unwrap_or(&g)),
                |(_, d)| last(d.split('&').next().unwrap_or(d)),
            ),
            KitSource::Local(p) => last(p.strip_suffix(".zip").unwrap_or(&p)),
            KitSource::Oci(_) => {
                let no_digest = s.split('@').next().unwrap_or(s);
                let repo = match no_digest.rsplit_once(':') {
                    Some((r, t)) if !t.contains('/') => r,
                    _ => no_digest,
                };
                last(repo)
            }
        }
    }
}

/// `workspace:` is a path or `{path, clone}`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Workspace {
    /// Plain path.
    Path(String),
    /// Path plus clone mode.
    Full {
        /// Host path.
        path: String,
        /// Work on a private clone.
        #[serde(default)]
        clone: bool,
    },
}

/// An extra mount.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtraWorkspace {
    /// Host path.
    pub path: String,
    /// Absolute sandbox path (no `:`).
    pub target: Option<String>,
    /// Mount read-only.
    pub read_only: Option<bool>,
}

/// Create-time knobs.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxOptions {
    /// Override the base image.
    pub template: Option<String>,
    /// e.g. `16g`.
    pub memory: Option<String>,
    /// CPU count (0 = auto).
    pub cpus: Option<u32>,
    /// Root disk size.
    pub root_size: Option<String>,
    /// Docker data disk size.
    pub docker_size: Option<String>,
    /// Cloned-workspace disk size.
    pub cloned_workspace_size: Option<String>,
    /// `always` | `missing` | `never`.
    pub pull_policy: Option<String>,
    /// `off` | `readonly` | `readwrite`.
    pub skills: Option<String>,
    /// Expose a display socket.
    pub display: Option<bool>,
    /// GPU passthrough.
    pub gpu: Option<bool>,
    /// FUSE on/off.
    pub fuse: Option<bool>,
    /// Nested virtualization.
    pub nested: Option<bool>,
    /// USB selectors.
    pub usb: Option<Vec<String>>,
    /// Let the sandbox edit its own env files.
    pub writable_env_files: Option<bool>,
}

/// A secret provisioned at sandbox scope. Exactly one of `value`/`ref`/`command`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSpec {
    /// Literal (discouraged).
    pub value: Option<String>,
    /// Vault reference.
    #[serde(rename = "ref")]
    pub reference: Option<String>,
    /// Host command printing the secret.
    pub command: Option<String>,
    /// Skip the one-shot resolve check.
    pub no_verify: Option<bool>,
    /// `on-demand`, `55m`, …
    pub refresh: Option<String>,
    /// `sdk` | `cli`.
    pub backend: Option<String>,
    /// Store the create-time result as a literal.
    pub snapshot: Option<bool>,
}

/// A mechanism approval.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Domains {
    /// Hosts the credential may be presented to.
    #[serde(default)]
    pub domains: Vec<String>,
}
/// Per-service bindings.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingSpec {
    /// API-key mechanism.
    pub api_key: Option<Domains>,
    /// OAuth mechanism.
    pub oauth: Option<Domains>,
}

/// A registry login.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistrySpec {
    /// Password or token.
    pub secret: SecretSpec,
    /// Optional username.
    pub username: Option<SecretSpec>,
}

/// An MCP server registration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpServer {
    /// Registration name.
    pub name: String,
    /// Remote server URL (exclusive with `command`).
    pub url: Option<String>,
    /// Local stdio command (exclusive with `url`).
    pub command: Option<String>,
    /// Arguments for `command`.
    #[serde(default)]
    pub args: Vec<String>,
}
/// `mcp:` block.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Mcp {
    /// Servers to register.
    #[serde(default)]
    pub servers: Vec<McpServer>,
}

/// A published port.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortSpec {
    /// Sandbox port, 1-65535.
    pub sandbox: u32,
    /// Host port (0/omitted = ephemeral).
    pub host: Option<u32>,
    /// `tcp`, `tcp4` (default), `tcp6`, `udp`, `udp4`, `udp6`.
    pub protocol: Option<String>,
    /// Bind address (empty = loopback).
    #[serde(rename = "hostIP")]
    pub host_ip: Option<String>,
}

/// A host-side command.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostCommand {
    /// Label.
    pub name: Option<String>,
    /// Shell command (`sh -c`, `cmd /c` on Windows).
    pub command: String,
    /// Working directory (default: project dir).
    pub workdir: Option<String>,
    /// e.g. `5m`.
    pub timeout: Option<String>,
}
/// Host-side lifecycle hooks (they run with the user's privileges: part of the plan the user approves).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lifecycle {
    /// Before anything is resolved; runs on create and attach, so must be idempotent.
    #[serde(default)]
    pub initialize: Vec<HostCommand>,
    /// After create, before attach.
    #[serde(default)]
    pub post_create: Vec<HostCommand>,
    /// Before `env rm`.
    #[serde(default)]
    pub pre_remove: Vec<HostCommand>,
}

/// A parsed, validated environment file.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvFile {
    /// Must be `"1"`.
    pub schema_version: String,
    /// Sandbox name.
    pub name: Option<String>,
    /// Declared environment args.
    #[serde(default)]
    pub args: BTreeMap<String, EnvArg>,
    /// Built-in agent or handle of the agent kit.
    pub agent: String,
    /// Replaces the agent entrypoint (`[]` clears).
    pub entrypoint: Option<Vec<String>>,
    /// Replaces the default command.
    pub cmd: Option<Vec<String>>,
    /// Kits to compose.
    #[serde(default)]
    pub kits: Vec<KitEntry>,
    /// Primary workspace.
    pub workspace: Option<Workspace>,
    /// More mounts (require `workspace`).
    #[serde(default)]
    pub additional_workspaces: Vec<ExtraWorkspace>,
    /// Sandbox path → host directory (each must be declared by a kit's host-mount).
    #[serde(default)]
    pub mounts: BTreeMap<String, String>,
    /// Environment variables.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Create-time knobs.
    #[serde(default)]
    pub sandbox_options: SandboxOptions,
    /// Sandbox-scoped secrets.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretSpec>,
    /// Credential approvals.
    #[serde(default)]
    pub bindings: BTreeMap<String, BindingSpec>,
    /// Registry logins.
    #[serde(default)]
    pub registries: BTreeMap<String, RegistrySpec>,
    /// MCP registrations.
    #[serde(default)]
    pub mcp: Mcp,
    /// Published ports.
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// Host-side hooks.
    #[serde(default)]
    pub lifecycle: Lifecycle,
}

/// Where a file lives, for `${{ env.fileDir }}` / `${{ env.projectDir }}`.
#[derive(Debug, Clone)]
pub struct Context {
    /// Project directory.
    pub project_dir: String,
    /// Directory of the file being expanded.
    pub file_dir: String,
    /// Values for declared args (`--env-arg`).
    pub args: BTreeMap<String, String>,
}

/// Merge `top` over `base` (see the module docs for the rules).
pub fn layer(base: Value, top: Value) -> Value {
    match (base, top) {
        (Value::Mapping(mut b), Value::Mapping(t)) => {
            for (k, v) in t {
                let merged = match b.remove(&k) {
                    Some(old) if k.as_str() == Some("lifecycle") => layer_lifecycle(old, v),
                    Some(old) => layer(old, v),
                    None => v,
                };
                b.insert(k, merged);
            }
            Value::Mapping(b)
        }
        (_, t) => t,
    }
}

fn layer_lifecycle(base: Value, top: Value) -> Value {
    let (Value::Mapping(mut b), Value::Mapping(t)) = (base, top) else {
        return Value::Null;
    };
    for (k, v) in t {
        let joined = match (b.remove(&k), v) {
            (Some(Value::Sequence(mut x)), Value::Sequence(y)) => {
                x.extend(y);
                Value::Sequence(x)
            }
            (_, v) => v,
        };
        b.insert(k, joined);
    }
    Value::Mapping(b)
}

/// Expand `${{ env.* }}` in every string value (never in keys, never in the `args:` block).
pub fn expand(
    doc: &Value,
    ctx: &Context,
    declared: &BTreeMap<String, EnvArg>,
) -> Result<Value, EnvError> {
    let values = resolve_args(declared, &ctx.args)?;
    let Value::Mapping(top) = doc else {
        return bad("file must be a mapping");
    };
    let mut out = Mapping::new();
    for (k, v) in top {
        out.insert(
            k.clone(),
            if k.as_str() == Some("args") {
                v.clone()
            } else {
                walk(v, ctx, &values)?
            },
        );
    }
    Ok(Value::Mapping(out))
}

fn resolve_args(
    declared: &BTreeMap<String, EnvArg>,
    supplied: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, EnvError> {
    if let Some(n) = supplied.keys().find(|n| !declared.contains_key(*n)) {
        return bad(format!("--env-arg {n:?} is not declared"));
    }
    let mut out = BTreeMap::new();
    for (n, a) in declared {
        if !NAME.is_match(n) {
            return bad(format!("arg name {n:?} is invalid"));
        }
        let v = match (supplied.get(n), &a.default) {
            (Some(v), _) => v.clone(),
            (None, Some(d)) => d.clone(),
            (None, None) if a.required == Some(true) => {
                return bad(format!(
                    "required arg {n:?} not supplied (use --env-arg {n}=…)"
                ));
            }
            (None, None) => continue,
        };
        if let Some(e) = &a.enum_values
            && !e.contains(&v)
        {
            return bad(format!("arg {n:?}: {v:?} not in {e:?}"));
        }
        if let Some(p) = &a.pattern {
            let re = Regex::new(&format!("^(?:{p})$"))
                .map_err(|e| EnvError(format!("arg {n:?}: bad pattern: {e}")))?;
            if !re.is_match(&v) {
                return bad(format!("arg {n:?}: {v:?} does not match {p:?}"));
            }
        }
        out.insert(n.clone(), v);
    }
    Ok(out)
}

fn walk(v: &Value, ctx: &Context, vals: &BTreeMap<String, String>) -> Result<Value, EnvError> {
    match v {
        Value::String(s) => {
            let mut out = String::new();
            let mut last = 0;
            for m in REF.captures_iter(s) {
                let w = m.get(0).unwrap();
                out.push_str(&s[last..w.start()]);
                let piece = match (&m[1], m.get(2).map(|x| x.as_str())) {
                    ("args", Some(n)) => vals.get(n).cloned().ok_or_else(|| {
                        EnvError(format!("env.args.{n} is undeclared or has no value"))
                    })?,
                    ("projectDir", None) => ctx.project_dir.clone(),
                    ("fileDir", None) => ctx.file_dir.clone(),
                    _ => return bad(format!("unknown reference {}", w.as_str())),
                };
                out.push_str(&piece);
                last = w.end();
            }
            out.push_str(&s[last..]);
            Ok(Value::String(out))
        }
        Value::Sequence(x) => x
            .iter()
            .map(|i| walk(i, ctx, vals))
            .collect::<Result<_, _>>()
            .map(Value::Sequence),
        Value::Mapping(m) => m
            .iter()
            .map(|(k, x)| Ok((k.clone(), walk(x, ctx, vals)?)))
            .collect::<Result<Mapping, EnvError>>()
            .map(Value::Mapping),
        o => Ok(o.clone()),
    }
}

/// Parse and validate. `files` are YAML documents, lowest priority first (user base,
/// then project, then explicit files).
pub fn load(files: &[&str], ctx: &Context) -> Result<EnvFile, EnvError> {
    let mut merged = Value::Mapping(Mapping::new());
    for f in files {
        let v: Value = serde_yaml_ng::from_str(f).map_err(|e| EnvError(e.to_string()))?;
        merged = layer(merged, v);
    }
    // args are declared in the merged document, so read them before expanding
    let declared: BTreeMap<String, EnvArg> = match merged.get("args") {
        Some(a) => {
            serde_yaml_ng::from_value(a.clone()).map_err(|e| EnvError(format!("args: {e}")))?
        }
        None => BTreeMap::new(),
    };
    let expanded = expand(&merged, ctx, &declared)?;
    let env: EnvFile = serde_yaml_ng::from_value(expanded).map_err(|e| EnvError(e.to_string()))?;
    env.validate()?;
    Ok(env)
}

impl EnvFile {
    /// Cross-field rules from the reference.
    pub fn validate(&self) -> Result<(), EnvError> {
        if self.schema_version != "1" {
            return bad(format!(
                "schemaVersion must be \"1\", got {:?}",
                self.schema_version
            ));
        }
        if self.agent.is_empty() {
            return bad("agent is required");
        }
        let handles: Vec<String> = self.kits.iter().map(KitEntry::handle).collect();
        if !BUILTIN_AGENTS.contains(&self.agent.as_str()) && !handles.contains(&self.agent) {
            return bad(format!(
                "agent {:?} is neither a built-in nor the handle of a listed kit (handles: {handles:?})",
                self.agent
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for h in &handles {
            if !seen.insert(h) {
                return bad(format!("two kits share the handle {h:?}"));
            }
        }
        if let Some(Workspace::Path(p) | Workspace::Full { path: p, .. }) = &self.workspace
            && p.trim().is_empty()
        {
            return bad("workspace path must not be blank");
        }
        if !self.additional_workspaces.is_empty() && self.workspace.is_none() {
            return bad("additionalWorkspaces requires workspace");
        }
        for w in &self.additional_workspaces {
            if let Some(t) = &w.target
                && (!t.starts_with('/') || t.contains(':'))
            {
                return bad(format!(
                    "additionalWorkspaces target {t:?} must be absolute and contain no ':'"
                ));
            }
        }
        for sandbox_path in self.mounts.keys() {
            if !sandbox_path.starts_with('/') {
                return bad(format!(
                    "mounts key {sandbox_path:?} must be an absolute sandbox path"
                ));
            }
        }
        for (name, s) in self
            .secrets
            .iter()
            .chain(self.registries.iter().map(|(n, r)| (n, &r.secret)))
        {
            s.check(name)?;
        }
        if let Some(p) = &self.sandbox_options.pull_policy
            && !["always", "missing", "never"].contains(&p.as_str())
        {
            return bad(format!("pullPolicy {p:?} must be always|missing|never"));
        }
        if let Some(p) = &self.sandbox_options.skills
            && !["off", "readonly", "readwrite"].contains(&p.as_str())
        {
            return bad(format!("skills {p:?} must be off|readonly|readwrite"));
        }
        for s in &self.mcp.servers {
            if s.url.is_some() == s.command.is_some() {
                return bad(format!(
                    "mcp server {:?}: exactly one of url/command",
                    s.name
                ));
            }
        }
        for p in &self.ports {
            if !(1..=65535).contains(&p.sandbox) {
                return bad(format!("port.sandbox {} out of range", p.sandbox));
            }
            if p.host.is_some_and(|h| h > 65535) {
                return bad("port.host out of range");
            }
            if let Some(proto) = &p.protocol
                && !["tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"].contains(&proto.as_str())
            {
                return bad(format!("port.protocol {proto:?} is invalid"));
            }
        }
        Ok(())
    }
}

impl SecretSpec {
    fn check(&self, name: &str) -> Result<(), EnvError> {
        let n = [
            self.value.is_some(),
            self.reference.is_some(),
            self.command.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if n != 1 {
            return bad(format!(
                "secret {name:?}: exactly one of value/ref/command is required"
            ));
        }
        if self.snapshot == Some(true) {
            if self.value.is_some() {
                return bad(format!("secret {name:?}: snapshot needs ref or command"));
            }
            if self.refresh.is_some() || self.no_verify == Some(true) {
                return bad(format!(
                    "secret {name:?}: snapshot cannot be combined with refresh or noVerify"
                ));
            }
        }
        Ok(())
    }

    /// True if this secret embeds a literal value (should never be committed).
    pub fn is_literal(&self) -> bool {
        self.value.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            project_dir: "/p".into(),
            file_dir: "/p".into(),
            args: BTreeMap::new(),
        }
    }
    fn ok(y: &str) -> EnvFile {
        load(&[y], &ctx()).unwrap()
    }
    fn err(y: &str) -> String {
        load(&[y], &ctx()).unwrap_err().to_string()
    }
    const H: &str = "schemaVersion: \"1\"\nagent: claude\n";

    #[test]
    fn minimal_and_the_project_template() {
        assert_eq!(ok(H).agent, "claude");
        let tpl = "schemaVersion: \"1\"\nname: osbx\nagent: claude\nworkspace: ./osbx\nkits:\n  - ./osbx/dev/kits/host-state\nmounts:\n  /home/agent/claude-history: \"${{ env.fileDir }}/sessions\"\nenv:\n  CARGO_INCREMENTAL: \"0\"\n";
        let e = load(
            &[tpl],
            &Context {
                project_dir: "/r".into(),
                file_dir: "/r".into(),
                args: BTreeMap::new(),
            },
        )
        .unwrap();
        assert_eq!(e.mounts["/home/agent/claude-history"], "/r/sessions");
        assert_eq!(e.kits[0].handle(), "host-state");
        assert!(matches!(e.kits[0].kind(), KitSource::Local(_)));
    }

    #[test]
    fn strict_decoding() {
        assert!(err(&format!("{H}bogus: 1\n")).contains("bogus"));
        assert!(err(&format!("{H}sandboxOptions: {{nope: 1}}\n")).contains("nope"));
        assert!(err("schemaVersion: \"2\"\nagent: claude\n").contains("schemaVersion"));
    }

    #[test]
    fn kit_sources_and_handles() {
        let h = |s: &str| KitEntry::Ref(s.into()).handle();
        assert_eq!(h("sbx/claude"), "claude");
        assert_eq!(h("docker/sbx-kit-codex:0.166.0"), "sbx-kit-codex");
        assert_eq!(h("sbx/gh:2.103.2@sha256:abc"), "gh");
        assert_eq!(h("registry:5000/org/tool:1"), "tool");
        assert_eq!(h("./kits/dev-tools"), "dev-tools");
        assert_eq!(h("./dist/tool.zip"), "tool");
        assert_eq!(
            h("git+https://github.com/org/repo.git#dir=kits/tool"),
            "tool"
        );
        // a bare `kits/tool` is a registry reference, not a path
        assert!(matches!(
            KitEntry::Ref("kits/tool".into()).kind(),
            KitSource::Oci(_)
        ));
    }

    #[test]
    fn agent_must_be_builtin_or_a_listed_handle() {
        assert!(err("schemaVersion: \"1\"\nagent: mine\n").contains("neither a built-in"));
        ok("schemaVersion: \"1\"\nagent: mine\nkits: [docker.io/me/mine:1]\n");
        assert!(
            err("schemaVersion: \"1\"\nagent: claude\nkits: [a/x:1, b/x:2]\n")
                .contains("share the handle")
        );
    }

    #[test]
    fn workspace_rules() {
        assert!(
            err(&format!("{H}additionalWorkspaces: [{{path: ./x}}]\n"))
                .contains("requires workspace")
        );
        assert!(err(&format!("{H}workspace: \"  \"\n")).contains("blank"));
        assert!(
            err(&format!(
                "{H}workspace: .\nadditionalWorkspaces: [{{path: ./x, target: rel}}]\n"
            ))
            .contains("absolute")
        );
        let w = ok(&format!("{H}workspace: {{path: ., clone: true}}\n"));
        assert_eq!(
            w.workspace,
            Some(Workspace::Full {
                path: ".".into(),
                clone: true
            })
        );
    }

    #[test]
    fn secrets_need_exactly_one_source() {
        assert!(err(&format!("{H}secrets: {{github: {{}}}}\n")).contains("exactly one"));
        assert!(
            err(&format!("{H}secrets: {{github: {{ref: a, command: b}}}}\n"))
                .contains("exactly one")
        );
        assert!(
            err(&format!(
                "{H}secrets: {{github: {{ref: a, snapshot: true, refresh: 5m}}}}\n"
            ))
            .contains("snapshot")
        );
        let e = ok(&format!(
            "{H}secrets: {{github: {{command: gh auth token}}}}\n"
        ));
        assert!(!e.secrets["github"].is_literal());
    }

    #[test]
    fn env_args_expand_structurally() {
        let y = format!(
            "{H}args:\n  model:\n    default: opus\n    pattern: '[a-z]+'\nenv:\n  MODEL: \"${{{{ env.args.model }}}}\"\n"
        );
        assert_eq!(ok(&y).env["MODEL"], "opus");
        let mut c = ctx();
        c.args.insert("model".into(), "sonnet".into());
        assert_eq!(load(&[&y], &c).unwrap().env["MODEL"], "sonnet");
        c.args.insert("model".into(), "Bad Value".into());
        assert!(load(&[&y], &c).is_err()); // pattern
        c.args = [("other".to_owned(), "x".to_owned())].into();
        assert!(
            load(&[&y], &c)
                .unwrap_err()
                .to_string()
                .contains("not declared")
        );
        // required without a value
        let req =
            format!("{H}args:\n  t:\n    required: true\nenv:\n  T: \"${{{{ env.args.t }}}}\"\n");
        assert!(err(&req).contains("required arg"));
        // a value cannot inject keys
        let mut c = ctx();
        c.args.insert("t".into(), "x\nbogus: 1".into());
        assert_eq!(load(&[&req], &c).unwrap().env["T"], "x\nbogus: 1");
    }

    #[test]
    fn layering_user_base_under_project() {
        let base = "schemaVersion: \"1\"\nagent: claude\nenv: {A: base, B: base}\nsandboxOptions: {memory: 8g}\nlifecycle:\n  initialize:\n    - {command: echo base}\n";
        let proj = "env: {B: project}\nsandboxOptions: {cpus: 4}\nlifecycle:\n  initialize:\n    - {command: echo project}\n";
        let e = load(&[base, proj], &ctx()).unwrap();
        assert_eq!(e.env["A"], "base");
        assert_eq!(e.env["B"], "project");
        assert_eq!(e.sandbox_options.memory.as_deref(), Some("8g"));
        assert_eq!(e.sandbox_options.cpus, Some(4));
        let cmds: Vec<_> = e
            .lifecycle
            .initialize
            .iter()
            .map(|c| c.command.as_str())
            .collect();
        assert_eq!(cmds, ["echo base", "echo project"]); // base-layer commands run first
    }

    #[test]
    fn options_ports_mcp_validation() {
        assert!(
            err(&format!("{H}sandboxOptions: {{pullPolicy: sometimes}}\n")).contains("pullPolicy")
        );
        assert!(err(&format!("{H}ports: [{{sandbox: 70000}}]\n")).contains("out of range"));
        assert!(
            err(&format!("{H}ports: [{{sandbox: 80, protocol: sctp}}]\n")).contains("protocol")
        );
        assert!(err(&format!("{H}mcp: {{servers: [{{name: a}}]}}\n")).contains("exactly one"));
        assert!(
            err(&format!(
                "{H}mcp: {{servers: [{{name: a, url: x, command: y}}]}}\n"
            ))
            .contains("exactly one")
        );
        ok(&format!(
            "{H}ports: [{{sandbox: 8080, host: 0, hostIP: ''}}]\nmcp: {{servers: [{{name: a, command: npx, args: [x]}}]}}\n"
        ));
    }
}
