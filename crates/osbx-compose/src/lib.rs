//! `osbx-compose.yml`: a Docker Compose-inspired declarative specification for one or more
//! `osbx` sandboxes that compiles into the canonical [`osbx_spec::ProjectSpec`] IR.
//!
//! Features:
//! - Strict decoding (unknown keys are errors; top-level `x-*` extension fields and YAML anchors
//!   / `<<:` merge keys are supported just like Docker Compose).
//! - File layering: lower-priority base files merged beneath higher-priority overrides; `hooks`
//!   lists concatenate (base first).
//! - Structural scalar-only `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `${VAR:?err}`,
//!   `${VAR?err}`, and `$$` interpolation from declared `args:`, `.env` variables, and built-ins
//!   (`${OSBX_PROJECT_DIR}`, `${OSBX_FILE_DIR}`).
//! - Ergonomic short & long syntax for `volumes`, `ports`, `disk`, `capabilities`, `kits`,
//!   `environment`, `firewall`, `secrets`, `registries`, `mcp`, and `hooks`.

use regex::Regex;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};
use std::collections::BTreeMap;
use std::sync::LazyLock;

pub use osbx_spec;

static NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());

/// Anything wrong with an `osbx-compose.yml` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeError(pub String);

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ComposeError {}

fn bad<T>(msg: impl Into<String>) -> Result<T, ComposeError> {
    Err(ComposeError(msg.into()))
}

/// Interpolation context supplied when loading `osbx-compose.yml`.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Project root directory (`${OSBX_PROJECT_DIR}`).
    pub project_dir: String,
    /// Directory containing the compose file (`${OSBX_FILE_DIR}`).
    pub file_dir: String,
    /// Values explicitly supplied for declared `args:` (`--arg name=value`).
    pub args: BTreeMap<String, String>,
    /// Ambient variables for `${VAR}` interpolation (typically `.env` + host env).
    pub vars: BTreeMap<String, String>,
    /// Pre-loaded `env_file` contents (`path -> parsed K=V pairs`), if provided by caller.
    /// When `load_from_paths` is used, `env_file` paths are read automatically from disk.
    pub env_files: BTreeMap<String, BTreeMap<String, String>>,
}

/// Parse a `.env` file into key/value pairs (supports comments, blank lines, optional `export `,
/// single- and double-quoted values).
pub fn parse_dotenv(src: &str) -> Result<BTreeMap<String, String>, ComposeError> {
    let mut out = BTreeMap::new();
    for (idx, raw_line) in src.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map(str::trim_start).unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            return bad(format!(".env line {}: expected KEY=VALUE", idx + 1));
        };
        let key = k.trim();
        if !NAME_RE.is_match(key) {
            return bad(format!(".env line {}: invalid variable name {key:?}", idx + 1));
        }
        let v = v.trim();
        let val = if let Some(rest) = v.strip_prefix('"') {
            let mut out_val = String::new();
            let mut chars = rest.chars();
            let mut closed = false;
            while let Some(c) = chars.next() {
                match c {
                    '\\' => match chars.next() {
                        Some('n') => out_val.push('\n'),
                        Some('r') => out_val.push('\r'),
                        Some('t') => out_val.push('\t'),
                        Some('"') => out_val.push('"'),
                        Some('\\') => out_val.push('\\'),
                        Some(other) => {
                            out_val.push('\\');
                            out_val.push(other);
                        }
                        None => return bad(format!(".env line {}: trailing backslash", idx + 1)),
                    },
                    '"' => {
                        closed = true;
                        break;
                    }
                    other => out_val.push(other),
                }
            }
            if !closed {
                return bad(format!(".env line {}: unclosed double quote", idx + 1));
            }
            out_val
        } else if let Some(rest) = v.strip_prefix('\'') {
            let Some((inner, _)) = rest.split_once('\'') else {
                return bad(format!(".env line {}: unclosed single quote", idx + 1));
            };
            inner.to_owned()
        } else {
            // Strip unquoted inline `# comment` preceded by whitespace
            match v.find(" #") {
                Some(pos) => v[..pos].trim_end().to_owned(),
                None => v.to_owned(),
            }
        };
        out.insert(key.to_owned(), val);
    }
    Ok(out)
}

// ============================================================================
// Surface AST (strict decoding)
// ============================================================================

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeArg {
    #[allow(dead_code)]
    description: Option<String>,
    default: Option<String>,
    required: Option<bool>,
    #[serde(rename = "enum")]
    enum_values: Option<Vec<String>>,
    pattern: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum CommandField {
    Shell(String),
    Exec(Vec<String>),
}

impl CommandField {
    fn into_argv(self) -> Vec<String> {
        match self {
            Self::Exec(v) => v,
            Self::Shell(s) => vec!["/bin/sh".into(), "-c".into(), s],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum WorkspaceField {
    Path(String),
    Full(WorkspaceFull),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceFull {
    path: String,
    target: Option<String>,
    #[serde(default)]
    mode: osbx_spec::WorkspaceMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DiskField {
    Root(String),
    Full(DiskFull),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskFull {
    root: Option<String>,
    docker: Option<String>,
    clone: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum VolumeEntry {
    Short(String),
    Long(VolumeLong),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeLong {
    #[serde(rename = "type")]
    kind: String,
    source: String,
    target: String,
    #[serde(default)]
    read_only: bool,
    mode: Option<String>,
    kit: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeVolume {
    driver: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum EnvField {
    Map(BTreeMap<String, Value>),
    List(Vec<String>),
}

impl Default for EnvField {
    fn default() -> Self {
        Self::Map(BTreeMap::new())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum PortEntry {
    Short(String),
    Number(u16),
    Long(PortLong),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortLong {
    target: u32,
    host: Option<u32>,
    host_ip: Option<String>,
    protocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum BoolOrToggle {
    Bool(bool),
    Full(ToggleFull),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToggleFull {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_true")]
    required: bool,
}

fn default_true() -> bool {
    true
}

impl BoolOrToggle {
    fn to_spec(&self) -> osbx_spec::CapabilityToggle {
        match self {
            Self::Bool(b) => osbx_spec::CapabilityToggle::new(*b, *b),
            Self::Full(f) => osbx_spec::CapabilityToggle::new(f.enabled, f.required),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum SshAgentField {
    Bool(bool),
    Full(SshAgentFull),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshAgentFull {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_true")]
    required: bool,
    #[serde(default)]
    unrestricted: bool,
    #[serde(default)]
    sign_namespaces: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeCapabilities {
    kvm: Option<BoolOrToggle>,
    docker: Option<BoolOrToggle>,
    privileged: Option<BoolOrToggle>,
    nested: Option<bool>,
    gpu: Option<bool>,
    display: Option<bool>,
    fuse: Option<bool>,
    #[serde(default)]
    usb: Vec<String>,
    ssh_agent: Option<SshAgentField>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ComposeKitEntry {
    Ref(String),
    Full(ComposeKitFull),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeKitFull {
    source: String,
    digest: Option<String>,
    #[serde(default)]
    args: BTreeMap<String, String>,
    #[serde(default)]
    mounts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum FirewallRuleEntry {
    Dest(String),
    Http(FirewallHttpRule),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FirewallHttpRule {
    hosts: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    query: BTreeMap<String, String>,
    #[serde(default)]
    phase: osbx_spec::FirewallPhase,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeFirewall {
    default: Option<osbx_spec::FirewallDefault>,
    #[serde(default)]
    extends: Vec<String>,
    #[serde(default)]
    allow: Vec<FirewallRuleEntry>,
    #[serde(default)]
    deny: Vec<FirewallRuleEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DomainsList {
    List(Vec<String>),
    Obj(DomainsObj),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainsObj {
    #[serde(default)]
    domains: Vec<String>,
}

impl DomainsList {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::List(v) => v,
            Self::Obj(o) => o.domains,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeBindings {
    api_key: Option<DomainsList>,
    oauth: Option<DomainsList>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeInjectRule {
    domain: String,
    header: Option<String>,
    format: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeSecretInject {
    env: Option<String>,
    #[serde(default)]
    rules: Vec<ComposeInjectRule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeSecretValue {
    value: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    command: Option<String>,
    #[serde(default)]
    no_verify: bool,
    refresh: Option<String>,
    backend: Option<String>,
    #[serde(default)]
    snapshot: bool,
}

impl ComposeSecretValue {
    fn has_any_source(&self) -> bool {
        self.value.is_some() || self.reference.is_some() || self.command.is_some()
    }

    fn to_spec(&self, name: &str) -> Result<osbx_spec::SecretValueSpec, ComposeError> {
        let count = [
            self.value.is_some(),
            self.reference.is_some(),
            self.command.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if count != 1 {
            return bad(format!(
                "secret {name:?}: exactly one of value/ref/command is required"
            ));
        }
        let source = if let Some(v) = &self.value {
            osbx_spec::SecretSource::Value(v.clone())
        } else if let Some(r) = &self.reference {
            osbx_spec::SecretSource::Ref(r.clone())
        } else {
            osbx_spec::SecretSource::Command(self.command.clone().unwrap())
        };
        let backend = self
            .backend
            .as_deref()
            .map(|b| b.parse::<osbx_spec::SecretBackend>())
            .transpose()
            .map_err(|e| ComposeError(format!("secret {name:?}: {e}")))?;
        let spec = osbx_spec::SecretValueSpec {
            source,
            no_verify: self.no_verify,
            refresh: self.refresh.clone(),
            backend,
            snapshot: self.snapshot,
        };
        spec.validate(name).map_err(|e| ComposeError(e.0))?;
        Ok(spec)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeSecret {
    value: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    command: Option<String>,
    #[serde(default)]
    no_verify: bool,
    refresh: Option<String>,
    backend: Option<String>,
    #[serde(default)]
    snapshot: bool,
    bindings: Option<ComposeBindings>,
    inject: Option<ComposeSecretInject>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum SandboxSecretRef {
    Name(String),
    Full(SandboxSecretRefFull),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxSecretRefFull {
    source: String,
    #[serde(default = "default_true")]
    required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeRegistry {
    secret: ComposeSecretValue,
    username: Option<ComposeSecretValue>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeMcpServer {
    url: Option<String>,
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeHostCommand {
    name: Option<String>,
    command: String,
    workdir: Option<String>,
    timeout: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeGuestFile {
    path: String,
    content: String,
    mode: Option<String>,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeGuestCommand {
    command: String,
    user: Option<String>,
    #[serde(default)]
    background: bool,
    description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeGuestHooks {
    #[serde(default)]
    files: Vec<ComposeGuestFile>,
    #[serde(default)]
    install: Vec<ComposeGuestCommand>,
    #[serde(default)]
    startup: Vec<ComposeGuestCommand>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeHooks {
    #[serde(default)]
    initialize: Vec<ComposeHostCommand>,
    #[serde(default)]
    post_create: Vec<ComposeHostCommand>,
    #[serde(default)]
    pre_remove: Vec<ComposeHostCommand>,
    guest: Option<ComposeGuestHooks>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeSandbox {
    sandbox_name: Option<String>,
    #[serde(default)]
    profiles: Vec<String>,
    #[allow(dead_code)]
    extends: Option<String>,
    agent: Option<String>,
    image: Option<String>,
    template: Option<String>,
    pull_policy: Option<osbx_spec::PullPolicy>,
    entrypoint: Option<CommandField>,
    command: Option<CommandField>,
    workspace: Option<WorkspaceField>,
    cpus: Option<u32>,
    memory: Option<String>,
    disk: Option<DiskField>,
    #[serde(default)]
    volumes: Vec<VolumeEntry>,
    env_file: Option<StringOrList>,
    #[serde(default)]
    environment: EnvField,
    #[serde(default)]
    ports: Vec<PortEntry>,
    #[serde(default)]
    capabilities: ComposeCapabilities,
    skills: Option<osbx_spec::SkillsMode>,
    writable_env_files: Option<bool>,
    #[serde(default)]
    kits: Vec<ComposeKitEntry>,
    firewall: Option<ComposeFirewall>,
    #[serde(default)]
    secrets: Vec<SandboxSecretRef>,
    #[serde(default)]
    registries: Vec<String>,
    #[serde(default)]
    mcp: Vec<String>,
    #[serde(default)]
    hooks: ComposeHooks,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeFile {
    version: Option<String>,
    name: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    args: BTreeMap<String, ComposeArg>,
    #[serde(default)]
    secrets: Option<BTreeMap<String, Option<ComposeSecret>>>,
    #[serde(default)]
    volumes: Option<BTreeMap<String, Option<ComposeVolume>>>,
    #[serde(default)]
    firewalls: Option<BTreeMap<String, ComposeFirewall>>,
    #[serde(default)]
    registries: Option<BTreeMap<String, ComposeRegistry>>,
    #[serde(default)]
    mcp: Option<BTreeMap<String, ComposeMcpServer>>,
    #[serde(default)]
    sandboxes: BTreeMap<String, ComposeSandbox>,
}

// ============================================================================
// Layering, `x-*` stripping, `extends:`, and interpolation
// ============================================================================

/// Merge `top` over `base`: deep-merges maps, replaces scalars and lists, and concatenates
/// `hooks` lists (base first).
pub fn layer(base: Value, top: Value) -> Value {
    match (base, top) {
        (Value::Mapping(mut b), Value::Mapping(t)) => {
            for (k, v) in t {
                let merged = match b.remove(&k) {
                    Some(old) if k.as_str() == Some("hooks") => layer_hooks(old, v),
                    Some(old) => layer(old, v),
                    None => v,
                };
                b.insert(k, merged);
            }
            Value::Mapping(b)
        }
        (b, Value::Null) => b,
        (_, t) => t,
    }
}

fn layer_hooks(base: Value, top: Value) -> Value {
    match (base, top) {
        (Value::Mapping(mut b), Value::Mapping(t)) => {
            for (k, v) in t {
                let joined = match (b.remove(&k), v) {
                    (Some(Value::Sequence(mut x)), Value::Sequence(y)) => {
                        x.extend(y);
                        Value::Sequence(x)
                    }
                    (Some(old), v) if k.as_str() == Some("guest") => layer_hooks(old, v),
                    (_, v) => v,
                };
                b.insert(k, joined);
            }
            Value::Mapping(b)
        }
        (_, other) => other,
    }
}

fn strip_extensions(doc: &mut Value) {
    if let Value::Mapping(m) = doc {
        m.retain(|k, _| !k.as_str().is_some_and(|s| s.starts_with("x-")));
    }
}

fn resolve_extends(doc: &mut Value) -> Result<(), ComposeError> {
    let Some(sandboxes) = doc.get("sandboxes").and_then(Value::as_mapping).cloned() else {
        return Ok(());
    };
    let mut resolved = Mapping::new();
    for (k, _) in &sandboxes {
        let mut visiting = Vec::new();
        let val = resolve_one_sandbox(k, &sandboxes, &mut visiting)?;
        resolved.insert(k.clone(), val);
    }
    if let Value::Mapping(top) = doc {
        top.insert(Value::String("sandboxes".into()), Value::Mapping(resolved));
    }
    Ok(())
}

fn resolve_one_sandbox(
    key: &Value,
    all: &Mapping,
    visiting: &mut Vec<String>,
) -> Result<Value, ComposeError> {
    let name = key.as_str().unwrap_or("?").to_owned();
    if visiting.contains(&name) {
        return bad(format!("circular extends detected at sandbox {name:?}"));
    }
    let Some(raw) = all.get(key) else {
        return bad(format!("extends: unknown sandbox {name:?}"));
    };
    let Some(map) = raw.as_mapping() else {
        return Ok(raw.clone());
    };
    let Some(parent_name) = map.get("extends").and_then(Value::as_str) else {
        return Ok(raw.clone());
    };
    visiting.push(name);
    let parent_key = Value::String(parent_name.to_owned());
    let parent_val = resolve_one_sandbox(&parent_key, all, visiting)?;
    visiting.pop();
    let mut child = map.clone();
    child.remove("extends");
    Ok(layer(parent_val, Value::Mapping(child)))
}

fn resolve_args(
    declared: &BTreeMap<String, ComposeArg>,
    supplied: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ComposeError> {
    if let Some(n) = supplied.keys().find(|n| !declared.contains_key(*n)) {
        return bad(format!("--arg {n:?} is not declared in args:"));
    }
    let mut out = BTreeMap::new();
    for (n, a) in declared {
        if !NAME_RE.is_match(n) {
            return bad(format!("arg name {n:?} is invalid"));
        }
        let v = match (supplied.get(n), &a.default) {
            (Some(v), _) => v.clone(),
            (None, Some(d)) => d.clone(),
            (None, None) if a.required == Some(true) => {
                return bad(format!("required arg {n:?} not supplied (use --arg {n}=...)"));
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
                .map_err(|e| ComposeError(format!("arg {n:?}: bad pattern: {e}")))?;
            if !re.is_match(&v) {
                return bad(format!("arg {n:?}: {v:?} does not match {p:?}"));
            }
        }
        out.insert(n.clone(), v);
    }
    Ok(out)
}

/// Expand `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `${VAR:?err}`, `${VAR?err}`, and `$$`
/// in a single string scalar.
fn interpolate_str(s: &str, vars: &BTreeMap<String, String>) -> Result<String, ComposeError> {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
                out.push('$');
                i += 2;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                let start = i + 2;
                let Some(rel_end) = find_closing_brace(&s[start..]) else {
                    return bad(format!("unclosed interpolation in {s:?}"));
                };
                let expr = &s[start..start + rel_end];
                let val = eval_expr(expr, vars)?;
                out.push_str(&val);
                i = start + rel_end + 1;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

fn find_closing_brace(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] == b'$' && i + 1 < b.len() && b[i + 1] == b'{' {
            depth += 1;
            i += 2;
            continue;
        }
        if b[i] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn eval_expr(expr: &str, vars: &BTreeMap<String, String>) -> Result<String, ComposeError> {
    // Find operator: :-, -, :?, ?
    let name_end = expr
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(expr.len());
    let name = &expr[..name_end];
    if name.is_empty() || !NAME_RE.is_match(name) {
        return bad(format!("invalid variable name in interpolation: ${{{expr}}}"));
    }
    let rest = &expr[name_end..];
    let val = vars.get(name);
    if rest.is_empty() {
        return val
            .cloned()
            .ok_or_else(|| ComposeError(format!("variable {name:?} is not set")));
    }
    if let Some(default) = rest.strip_prefix(":-") {
        return match val {
            Some(v) if !v.is_empty() => Ok(v.clone()),
            _ => interpolate_str(default, vars),
        };
    }
    if let Some(default) = rest.strip_prefix('-') {
        return match val {
            Some(v) => Ok(v.clone()),
            None => interpolate_str(default, vars),
        };
    }
    if let Some(err_msg) = rest.strip_prefix(":?") {
        return match val {
            Some(v) if !v.is_empty() => Ok(v.clone()),
            _ => {
                let msg = if err_msg.is_empty() {
                    format!("required variable {name:?} is unset or empty")
                } else {
                    format!("{name}: {err_msg}")
                };
                bad(msg)
            }
        };
    }
    if let Some(err_msg) = rest.strip_prefix('?') {
        return match val {
            Some(v) => Ok(v.clone()),
            None => {
                let msg = if err_msg.is_empty() {
                    format!("required variable {name:?} is unset")
                } else {
                    format!("{name}: {err_msg}")
                };
                bad(msg)
            }
        };
    }
    bad(format!("unsupported interpolation syntax: ${{{expr}}}"))
}

fn walk_interpolate(v: &Value, vars: &BTreeMap<String, String>) -> Result<Value, ComposeError> {
    match v {
        Value::String(s) => Ok(Value::String(interpolate_str(s, vars)?)),
        Value::Sequence(seq) => seq
            .iter()
            .map(|i| walk_interpolate(i, vars))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Sequence),
        Value::Mapping(m) => m
            .iter()
            .map(|(k, x)| Ok((k.clone(), walk_interpolate(x, vars)?)))
            .collect::<Result<Mapping, ComposeError>>()
            .map(Value::Mapping),
        other => Ok(other.clone()),
    }
}

// ============================================================================
// Short-syntax parsers (ports, volumes)
// ============================================================================

/// Parse Compose short port syntax: `[HOST_IP:][HOST_PORT:]TARGET[/PROTO]`.
fn parse_short_port(raw: &str) -> Result<osbx_spec::PortSpec, ComposeError> {
    let (addr_part, proto) = match raw.rsplit_once('/') {
        Some((a, p)) => (
            a,
            p.parse::<osbx_spec::PortProtocol>()
                .map_err(|e| ComposeError(format!("port {raw:?}: {e}")))?,
        ),
        None => (raw, osbx_spec::PortProtocol::Tcp4),
    };

    // Handle IPv6 bracketed host IP: `[::1]:8080:3000`
    let (host_ip, host, target_str) = if let Some(rest) = addr_part.strip_prefix('[') {
        let Some((ip, after)) = rest.split_once("]:") else {
            return bad(format!("port {raw:?}: malformed IPv6 host address"));
        };
        let parts: Vec<&str> = after.split(':').collect();
        match parts.as_slice() {
            [h, t] => {
                let host: u16 = if h.is_empty() {
                    0
                } else {
                    h.parse()
                        .map_err(|_| ComposeError(format!("port {raw:?}: invalid host port {h:?}")))?
                };
                (ip.to_owned(), host, *t)
            }
            _ => {
                return bad(format!(
                    "port {raw:?}: expected [IP]:HOST:TARGET for IPv6 bind"
                ));
            }
        }
    } else {
        let parts: Vec<&str> = addr_part.split(':').collect();
        match parts.as_slice() {
            [t] => ("127.0.0.1".to_owned(), 0, *t),
            [h, t] => {
                let host: u16 = if h.is_empty() {
                    0
                } else {
                    h.parse()
                        .map_err(|_| ComposeError(format!("port {raw:?}: invalid host port {h:?}")))?
                };
                ("127.0.0.1".to_owned(), host, *t)
            }
            [ip, h, t] => {
                let host_ip = if ip.is_empty() { "127.0.0.1" } else { ip }.to_owned();
                let host: u16 = if h.is_empty() {
                    0
                } else {
                    h.parse()
                        .map_err(|_| ComposeError(format!("port {raw:?}: invalid host port {h:?}")))?
                };
                (host_ip, host, *t)
            }
            _ => {
                return bad(format!(
                    "port {raw:?}: expected [HOST_IP:][HOST_PORT:]TARGET[/PROTO]"
                ));
            }
        }
    };

    let target: u16 = target_str
        .parse()
        .map_err(|_| ComposeError(format!("port {raw:?}: invalid target port {target_str:?}")))?;
    if target == 0 {
        return bad(format!("port {raw:?}: target port must be 1..=65535"));
    }
    Ok(osbx_spec::PortSpec {
        host_ip,
        host,
        target,
        protocol: proto,
    })
}

/// Split a Compose short volume string `SOURCE:TARGET[:FLAGS]`, preserving a Windows drive prefix
/// like `C:\path` in `SOURCE`.
fn parse_short_volume(raw: &str) -> Result<osbx_spec::MountSpec, ComposeError> {
    let bytes = raw.as_bytes();
    let search_from = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        2
    } else {
        0
    };
    let Some(first_rel) = raw[search_from..].find(':') else {
        return bad(format!(
            "volume {raw:?}: expected SOURCE:TARGET[:ro|rw|clone]"
        ));
    };
    let first = search_from + first_rel;
    let source = &raw[..first];
    let rest = &raw[first + 1..];
    let (target, flag) = match rest.split_once(':') {
        Some((t, f)) => (t, Some(f)),
        None => (rest, None),
    };
    if source.is_empty() || target.is_empty() {
        return bad(format!(
            "volume {raw:?}: source and target must not be empty"
        ));
    }
    let is_path = source == "."
        || source == ".."
        || source.starts_with("./")
        || source.starts_with("../")
        || source.starts_with('/')
        || source.starts_with("~/")
        || source.contains('/')
        || source.contains('\\')
        || (source.len() >= 2 && source.as_bytes()[1] == b':');

    let (kind, read_only) = match flag {
        None | Some("rw") => (
            if is_path {
                osbx_spec::MountKind::Bind
            } else {
                osbx_spec::MountKind::Volume
            },
            false,
        ),
        Some("ro") => (
            if is_path {
                osbx_spec::MountKind::Bind
            } else {
                osbx_spec::MountKind::Volume
            },
            true,
        ),
        Some("clone") => {
            if !is_path {
                return bad(format!(
                    "volume {raw:?}: :clone mode requires a host directory path"
                ));
            }
            (osbx_spec::MountKind::Clone, false)
        }
        Some(other) => {
            return bad(format!(
                "volume {raw:?}: unknown mount option {other:?} (expected rw|ro|clone)"
            ));
        }
    };

    Ok(osbx_spec::MountSpec {
        kind,
        source: source.to_owned(),
        target: target.to_owned(),
        read_only,
        mode: None,
        kit: None,
    })
}

fn scalar_to_string(v: &Value) -> Result<String, ComposeError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Null => Ok(String::new()),
        _ => bad("environment variable value must be a scalar"),
    }
}

fn lower_firewall_entries(
    action: osbx_spec::FirewallAction,
    entries: &[FirewallRuleEntry],
    out: &mut Vec<osbx_spec::FirewallRule>,
) -> Result<(), ComposeError> {
    for entry in entries {
        match entry {
            FirewallRuleEntry::Dest(dest) => {
                out.push(osbx_spec::FirewallRule {
                    action,
                    dest: dest.clone(),
                    phase: osbx_spec::FirewallPhase::Runtime,
                    http: None,
                });
            }
            FirewallRuleEntry::Http(h) => {
                if h.hosts.is_empty() {
                    return bad("HTTP firewall rule requires at least one host");
                }
                for host in &h.hosts {
                    if h.paths.is_empty() {
                        let http = (!h.methods.is_empty() || !h.query.is_empty()).then(|| {
                            osbx_spec::HttpMatchSpec {
                                methods: h.methods.clone(),
                                path: None,
                                query: h.query.clone(),
                            }
                        });
                        out.push(osbx_spec::FirewallRule {
                            action,
                            dest: host.clone(),
                            phase: h.phase,
                            http,
                        });
                    } else {
                        for p in &h.paths {
                            out.push(osbx_spec::FirewallRule {
                                action,
                                dest: host.clone(),
                                phase: h.phase,
                                http: Some(osbx_spec::HttpMatchSpec {
                                    methods: h.methods.clone(),
                                    path: Some(p.clone()),
                                    query: h.query.clone(),
                                }),
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn compile_firewall(
    fw: &ComposeFirewall,
    named: &BTreeMap<String, ComposeFirewall>,
    visiting: &mut Vec<String>,
) -> Result<osbx_spec::FirewallSpec, ComposeError> {
    let mut default = None;
    let mut rules = Vec::new();
    for parent in &fw.extends {
        if visiting.contains(parent) {
            return bad(format!("circular firewall extends detected at {parent:?}"));
        }
        let Some(pfw) = named.get(parent) else {
            return bad(format!("firewall extends unknown profile {parent:?}"));
        };
        visiting.push(parent.clone());
        let compiled = compile_firewall(pfw, named, visiting)?;
        visiting.pop();
        if compiled.default.is_some() {
            default = compiled.default;
        }
        rules.extend(compiled.rules);
    }
    if fw.default.is_some() {
        default = fw.default;
    }
    lower_firewall_entries(osbx_spec::FirewallAction::Allow, &fw.allow, &mut rules)?;
    lower_firewall_entries(osbx_spec::FirewallAction::Deny, &fw.deny, &mut rules)?;
    Ok(osbx_spec::FirewallSpec { default, rules })
}

// ============================================================================
// Public entry points
// ============================================================================

/// Parse, layer, interpolate, validate, and compile one or more `osbx-compose.yml` documents
/// (lowest priority first) into the canonical [`osbx_spec::ProjectSpec`] IR.
pub fn compile(files: &[&str], ctx: &Context) -> Result<osbx_spec::ProjectSpec, ComposeError> {
    if files.is_empty() {
        return bad("no compose files provided");
    }
    let mut merged = Value::Mapping(Mapping::new());
    for raw in files {
        let mut doc: Value =
            serde_yaml_ng::from_str(raw).map_err(|e| ComposeError(e.to_string()))?;
        doc.apply_merge()
            .map_err(|e| ComposeError(format!("YAML merge key error: {e}")))?;
        strip_extensions(&mut doc);
        if matches!(doc, Value::Null) {
            continue;
        }
        if !doc.is_mapping() {
            return bad("compose file must be a YAML mapping");
        }
        merged = layer(merged, doc);
    }

    // Resolve `extends:` between sandboxes before arg validation & interpolation.
    resolve_extends(&mut merged)?;

    // Read declared `args:` before interpolation (args definitions are never interpolated).
    let declared_args: BTreeMap<String, ComposeArg> = match merged.get("args") {
        Some(v) if !v.is_null() => serde_yaml_ng::from_value(v.clone())
            .map_err(|e| ComposeError(format!("args: {e}")))?,
        _ => BTreeMap::new(),
    };
    let resolved_args = resolve_args(&declared_args, &ctx.args)?;

    // Build variable table: ambient vars < built-ins < declared args.
    let mut vars = ctx.vars.clone();
    if !ctx.project_dir.is_empty() {
        vars.insert("OSBX_PROJECT_DIR".into(), ctx.project_dir.clone());
    }
    if !ctx.file_dir.is_empty() {
        vars.insert("OSBX_FILE_DIR".into(), ctx.file_dir.clone());
    }
    for (k, v) in resolved_args {
        vars.insert(k, v);
    }

    // Structurally interpolate all string scalars except the `args` block.
    let Value::Mapping(top) = merged else {
        return bad("compose file must be a YAML mapping");
    };
    let mut expanded = Mapping::new();
    for (k, v) in top {
        let out_v = if k.as_str() == Some("args") {
            v
        } else {
            walk_interpolate(&v, &vars)?
        };
        expanded.insert(k, out_v);
    }

    let file: ComposeFile = serde_yaml_ng::from_value(Value::Mapping(expanded))
        .map_err(|e| ComposeError(e.to_string()))?;
    lower_file(file, ctx, &vars)
}

/// Read one or more compose files from disk (lowest priority first), automatically loading a
/// sibling `.env` file (if present next to the primary file) and any sandbox `env_file:` entries
/// relative to the primary file's directory, then compile into [`osbx_spec::ProjectSpec`].
pub fn compile_files(
    paths: &[&std::path::Path],
    ctx: &Context,
) -> Result<osbx_spec::ProjectSpec, ComposeError> {
    if paths.is_empty() {
        return bad("no compose files provided");
    }
    let mut texts = Vec::with_capacity(paths.len());
    for p in paths {
        let content = std::fs::read_to_string(p)
            .map_err(|e| ComposeError(format!("{}: {e}", p.display())))?;
        texts.push(content);
    }
    let primary_dir = paths
        .last()
        .and_then(|p| p.parent())
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));

    let mut effective_ctx = ctx.clone();
    // Auto-load sibling `.env` into ambient vars (caller-provided `ctx.vars` wins).
    let dotenv_path = primary_dir.join(".env");
    if let Ok(dotenv_src) = std::fs::read_to_string(&dotenv_path) {
        let mut parsed = parse_dotenv(&dotenv_src)?;
        parsed.extend(effective_ctx.vars);
        effective_ctx.vars = parsed;
    }

    // Scan merged documents for any `env_file:` entries and load them relative to `primary_dir`.
    for raw in &texts {
        if let Ok(Value::Mapping(top)) = serde_yaml_ng::from_str::<Value>(raw)
            && let Some(Value::Mapping(sandboxes)) = top.get("sandboxes")
        {
            for (_, sb) in sandboxes {
                let Some(ef) = sb.get("env_file") else {
                    continue;
                };
                let entries: Vec<String> = match ef {
                    Value::String(s) => vec![s.clone()],
                    Value::Sequence(seq) => seq
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect(),
                    _ => Vec::new(),
                };
                for rel in entries {
                    if effective_ctx.env_files.contains_key(&rel) {
                        continue;
                    }
                    let full = primary_dir.join(&rel);
                    let src = std::fs::read_to_string(&full)
                        .map_err(|e| ComposeError(format!("env_file {}: {e}", full.display())))?;
                    let parsed = parse_dotenv(&src)?;
                    effective_ctx.env_files.insert(rel, parsed);
                }
            }
        }
    }

    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    compile(&refs, &effective_ctx)
}

fn lower_file(
    file: ComposeFile,
    ctx: &Context,
    vars: &BTreeMap<String, String>,
) -> Result<osbx_spec::ProjectSpec, ComposeError> {
    if let Some(v) = &file.version
        && v != "1"
    {
        return bad(format!("version must be \"1\", got {v:?}"));
    }
    if file.sandboxes.is_empty() {
        return bad("sandboxes: at least one sandbox must be defined");
    }

    // Top-level named volumes
    let mut volumes = BTreeMap::new();
    for (vname, vdef) in file.volumes.unwrap_or_default() {
        let vdef = vdef.unwrap_or_default();
        let driver = match vdef.driver.as_deref() {
            None | Some("managed") => {
                if vdef.path.is_some() {
                    return bad(format!(
                        "volume {vname:?}: path requires driver: host"
                    ));
                }
                osbx_spec::VolumeDriver::Managed
            }
            Some("host") => {
                let Some(path) = vdef.path else {
                    return bad(format!("volume {vname:?}: driver: host requires path"));
                };
                osbx_spec::VolumeDriver::Host { path }
            }
            Some(other) => {
                return bad(format!(
                    "volume {vname:?}: unknown driver {other:?} (expected managed|host)"
                ));
            }
        };
        volumes.insert(vname, osbx_spec::VolumeSpec { driver });
    }

    let top_secrets = file.secrets.unwrap_or_default();
    let top_firewalls = file.firewalls.unwrap_or_default();
    let top_registries = file.registries.unwrap_or_default();
    let top_mcp = file.mcp.unwrap_or_default();

    let mut sandboxes = BTreeMap::new();
    for (key, sb) in file.sandboxes {
        let agent = match (sb.agent, &sb.image, &sb.template) {
            (Some(a), _, _) => a,
            (None, Some(_), _) | (None, _, Some(_)) => "shell".into(),
            (None, None, None) => {
                return bad(format!(
                    "sandbox {key:?}: agent (or image/template) is required"
                ));
            }
        };

        // Workspace: `/abs/path` -> guest workdir; `none` -> None; relative path or object -> primary workspace
        let (workdir, workspace) = match sb.workspace {
            None => (None, None),
            Some(WorkspaceField::Path(p)) => {
                if p.eq_ignore_ascii_case("none") {
                    (None, None)
                } else if p.starts_with('/') {
                    (Some(p), None)
                } else {
                    (
                        None,
                        Some(osbx_spec::WorkspaceSpec {
                            host_path: p,
                            guest_path: None,
                            mode: osbx_spec::WorkspaceMode::Direct,
                        }),
                    )
                }
            }
            Some(WorkspaceField::Full(w)) => (
                w.target.clone(),
                Some(osbx_spec::WorkspaceSpec {
                    host_path: w.path,
                    guest_path: w.target,
                    mode: w.mode,
                }),
            ),
        };

        // Volumes / mounts
        let mut mounts = Vec::with_capacity(sb.volumes.len());
        for v in sb.volumes {
            let m = match v {
                VolumeEntry::Short(s) => parse_short_volume(&s)?,
                VolumeEntry::Long(l) => {
                    let kind = match l.kind.as_str() {
                        "bind" => osbx_spec::MountKind::Bind,
                        "volume" => osbx_spec::MountKind::Volume,
                        "clone" => osbx_spec::MountKind::Clone,
                        "kit-mount" | "kit_mount" => osbx_spec::MountKind::KitMount,
                        other => {
                            return bad(format!(
                                "sandbox {key:?}: unknown volume type {other:?} (expected bind|volume|clone|kit-mount)"
                            ));
                        }
                    };
                    osbx_spec::MountSpec {
                        kind,
                        source: l.source,
                        target: l.target,
                        read_only: l.read_only,
                        mode: l.mode,
                        kit: l.kit,
                    }
                }
            };
            mounts.push(m);
        }

        // Environment: load env_files first, then explicit environment overrides
        let mut env = BTreeMap::new();
        if let Some(ef) = sb.env_file {
            for path in ef.into_vec() {
                if let Some(loaded) = ctx.env_files.get(&path) {
                    env.extend(loaded.clone());
                } else {
                    return bad(format!(
                        "sandbox {key:?}: env_file {path:?} was not loaded in context"
                    ));
                }
            }
        }
        match sb.environment {
            EnvField::Map(map) => {
                for (ek, ev) in map {
                    env.insert(ek, scalar_to_string(&ev)?);
                }
            }
            EnvField::List(list) => {
                for item in list {
                    if let Some((ek, ev)) = item.split_once('=') {
                        env.insert(ek.to_owned(), ev.to_owned());
                    } else if let Some(ev) = vars.get(&item) {
                        env.insert(item, ev.clone());
                    }
                }
            }
        }

        // Resources (`cpus`, `memory`, `disk`)
        let memory_mib = sb
            .memory
            .as_deref()
            .map(|s| {
                osbx_spec::parse_size_mib(s)
                    .map_err(|e| ComposeError(format!("sandbox {key:?}: memory: {e}")))
            })
            .transpose()?;
        let disks = match sb.disk {
            None => osbx_spec::DisksSpec::default(),
            Some(DiskField::Root(s)) => osbx_spec::DisksSpec {
                root_mib: Some(
                    osbx_spec::parse_size_mib(&s)
                        .map_err(|e| ComposeError(format!("sandbox {key:?}: disk: {e}")))?,
                ),
                ..Default::default()
            },
            Some(DiskField::Full(d)) => {
                let parse_d = |f: &str, v: Option<&str>| -> Result<Option<u64>, ComposeError> {
                    v.map(|s| {
                        osbx_spec::parse_size_mib(s)
                            .map_err(|e| ComposeError(format!("sandbox {key:?}: disk.{f}: {e}")))
                    })
                    .transpose()
                };
                osbx_spec::DisksSpec {
                    root_mib: parse_d("root", d.root.as_deref())?,
                    docker_mib: parse_d("docker", d.docker.as_deref())?,
                    cloned_workspace_mib: parse_d("clone", d.clone.as_deref())?,
                }
            }
        };
        let resources = osbx_spec::ResourcesSpec {
            cpus: sb.cpus,
            memory_mib,
            disks,
        };

        // Capabilities
        let ssh_agent = sb.capabilities.ssh_agent.map(|s| match s {
            SshAgentField::Bool(b) => osbx_spec::SshAgentSpec {
                enabled: b,
                required: b,
                unrestricted: false,
                sign_namespaces: Vec::new(),
            },
            SshAgentField::Full(f) => osbx_spec::SshAgentSpec {
                enabled: f.enabled,
                required: f.required,
                unrestricted: f.unrestricted,
                sign_namespaces: f.sign_namespaces,
            },
        });
        let capabilities = osbx_spec::CapabilitiesSpec {
            kvm: sb.capabilities.kvm.as_ref().map(BoolOrToggle::to_spec),
            docker: sb.capabilities.docker.as_ref().map(BoolOrToggle::to_spec),
            privileged: sb
                .capabilities
                .privileged
                .as_ref()
                .map(BoolOrToggle::to_spec),
            nested: sb.capabilities.nested,
            gpu: sb.capabilities.gpu,
            display: sb.capabilities.display,
            fuse: sb.capabilities.fuse,
            usb: sb.capabilities.usb,
            ssh_agent,
        };

        let agent_options = osbx_spec::AgentOptionsSpec {
            skills: sb.skills,
            writable_env_files: sb.writable_env_files,
        };

        // Kits
        let kits = sb
            .kits
            .into_iter()
            .map(|k| match k {
                ComposeKitEntry::Ref(s) => {
                    osbx_spec::KitSpec::from_source(s, None, BTreeMap::new(), BTreeMap::new())
                }
                ComposeKitEntry::Full(f) => {
                    osbx_spec::KitSpec::from_source(f.source, f.digest, f.args, f.mounts)
                }
            })
            .collect();

        // Ports
        let mut ports = Vec::with_capacity(sb.ports.len());
        for p in sb.ports {
            let spec = match p {
                PortEntry::Short(s) => parse_short_port(&s)?,
                PortEntry::Number(n) => {
                    if n == 0 {
                        return bad(format!("sandbox {key:?}: port must be 1..=65535"));
                    }
                    osbx_spec::PortSpec {
                        host_ip: "127.0.0.1".into(),
                        host: 0,
                        target: n,
                        protocol: osbx_spec::PortProtocol::Tcp4,
                    }
                }
                PortEntry::Long(l) => {
                    let target = u16::try_from(l.target)
                        .ok()
                        .filter(|t| *t > 0)
                        .ok_or_else(|| {
                            ComposeError(format!(
                                "sandbox {key:?}: port target {} out of range",
                                l.target
                            ))
                        })?;
                    let host = match l.host {
                        Some(h) => u16::try_from(h).map_err(|_| {
                            ComposeError(format!("sandbox {key:?}: port host {h} out of range"))
                        })?,
                        None => 0,
                    };
                    let protocol = match l.protocol.as_deref() {
                        None => osbx_spec::PortProtocol::Tcp4,
                        Some(s) => s
                            .parse()
                            .map_err(|e: osbx_spec::SpecError| ComposeError(e.0))?,
                    };
                    let host_ip = l
                        .host_ip
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("127.0.0.1")
                        .to_owned();
                    osbx_spec::PortSpec {
                        host_ip,
                        host,
                        target,
                        protocol,
                    }
                }
            };
            ports.push(spec);
        }

        // Firewall
        let firewall = match sb.firewall {
            None => osbx_spec::FirewallSpec::default(),
            Some(fw) => compile_firewall(&fw, &top_firewalls, &mut Vec::new())?,
        };

        // Secrets (resolved against top-level `secrets:`)
        let mut secrets = BTreeMap::new();
        for sref in sb.secrets {
            let (sname, required) = match sref {
                SandboxSecretRef::Name(n) => (n, true),
                SandboxSecretRef::Full(f) => (f.source, f.required),
            };
            let Some(opt_def) = top_secrets.get(&sname) else {
                return bad(format!(
                    "sandbox {key:?}: secret {sname:?} is not declared in top-level secrets:"
                ));
            };
            let def = opt_def.clone().unwrap_or_default();
            let val_helper = ComposeSecretValue {
                value: def.value,
                reference: def.reference,
                command: def.command,
                no_verify: def.no_verify,
                refresh: def.refresh,
                backend: def.backend,
                snapshot: def.snapshot,
            };
            let value = if val_helper.has_any_source() {
                Some(val_helper.to_spec(&sname)?)
            } else {
                None
            };
            let bindings = match def.bindings {
                None => osbx_spec::BindingSpec::default(),
                Some(b) => osbx_spec::BindingSpec {
                    api_key_domains: b.api_key.map(DomainsList::into_vec).unwrap_or_default(),
                    oauth_domains: b.oauth.map(DomainsList::into_vec).unwrap_or_default(),
                },
            };
            let inject = def.inject.map(|inj| osbx_spec::SecretInjectSpec {
                env: inj.env,
                rules: inj
                    .rules
                    .into_iter()
                    .map(|r| osbx_spec::SecretInjectRule {
                        domain: r.domain,
                        header: r.header.unwrap_or_else(|| "Authorization".into()),
                        format: r.format.unwrap_or_else(|| "%s".into()),
                    })
                    .collect(),
            });
            secrets.insert(
                sname,
                osbx_spec::SecretSpec {
                    value,
                    required,
                    bindings,
                    inject,
                },
            );
        }

        // Registries
        let mut registries = BTreeMap::new();
        for rname in sb.registries {
            let Some(rdef) = top_registries.get(&rname) else {
                return bad(format!(
                    "sandbox {key:?}: registry {rname:?} is not declared in top-level registries:"
                ));
            };
            let secret = rdef.secret.to_spec(&rname)?;
            let username = rdef
                .username
                .as_ref()
                .map(|u| u.to_spec(&rname))
                .transpose()?;
            registries.insert(rname, osbx_spec::RegistrySpec { username, secret });
        }

        // MCP servers
        let mut mcp = Vec::with_capacity(sb.mcp.len());
        for mname in sb.mcp {
            let Some(mdef) = top_mcp.get(&mname) else {
                return bad(format!(
                    "sandbox {key:?}: mcp server {mname:?} is not declared in top-level mcp:"
                ));
            };
            let transport = match (&mdef.url, &mdef.command) {
                (Some(url), None) => osbx_spec::McpTransport::Remote { url: url.clone() },
                (None, Some(command)) => osbx_spec::McpTransport::Stdio {
                    command: command.clone(),
                    args: mdef.args.clone(),
                },
                _ => {
                    return bad(format!(
                        "mcp server {mname:?}: exactly one of url/command is required"
                    ));
                }
            };
            mcp.push(osbx_spec::McpServerSpec {
                name: mname,
                transport,
            });
        }

        // Hooks
        let to_host = |c: ComposeHostCommand| osbx_spec::HostCommandSpec {
            name: c.name,
            command: c.command,
            workdir: c.workdir,
            timeout: c.timeout,
        };
        let guest = sb.hooks.guest.unwrap_or_default();
        let hooks = osbx_spec::HooksSpec {
            initialize: sb.hooks.initialize.into_iter().map(to_host).collect(),
            post_create: sb.hooks.post_create.into_iter().map(to_host).collect(),
            pre_remove: sb.hooks.pre_remove.into_iter().map(to_host).collect(),
            guest_files: guest
                .files
                .into_iter()
                .map(|f| osbx_spec::GuestFileSpec {
                    path: f.path,
                    content: f.content,
                    mode: f.mode,
                    overwrite: f.overwrite,
                })
                .collect(),
            guest_install: guest
                .install
                .into_iter()
                .map(|c| osbx_spec::GuestCommandSpec {
                    command: c.command,
                    user: c.user,
                    background: false,
                    description: c.description,
                })
                .collect(),
            guest_startup: guest
                .startup
                .into_iter()
                .map(|c| osbx_spec::GuestCommandSpec {
                    command: c.command,
                    user: c.user,
                    background: c.background,
                    description: c.description,
                })
                .collect(),
        };

        sandboxes.insert(
            key,
            osbx_spec::SandboxSpec {
                name: sb.sandbox_name,
                profiles: sb.profiles,
                agent,
                image: sb.image,
                template: sb.template,
                pull_policy: sb.pull_policy,
                entrypoint: sb.entrypoint.map(CommandField::into_argv),
                command: sb.command.map(CommandField::into_argv),
                workdir,
                workspace,
                mounts,
                env,
                resources,
                capabilities,
                agent_options,
                kits,
                ports,
                firewall,
                secrets,
                registries,
                mcp,
                hooks,
            },
        );
    }

    let project = osbx_spec::ProjectSpec {
        name: file.name,
        volumes,
        sandboxes,
    };
    project.validate().map_err(|e| ComposeError(e.0))?;
    Ok(project)
}

#[cfg(test)]
mod tests {
    use super::*;
    use osbx_spec::*;

    fn ctx() -> Context {
        Context {
            project_dir: "/proj".into(),
            file_dir: "/proj".into(),
            ..Default::default()
        }
    }

    #[test]
    fn minimal_user_draft_compiles() {
        let yaml = r#"
secrets:

volumes:

sandboxes:
  synergy-plus:
    agent: claude
    workspace: /workspace
    cpus: 8
    memory: 8G
    disk: 128G
    volumes:
      - ./osbx:/workspace/osbx
    kits:
      - source: sbx/claude-sessions:1.0.0
        mounts:
          /home/agent/claude-history: ./.sessions
    firewall:
      default: deny
      allow:
        - google.com
      deny:
        - "*.evil.com"
"#;
        let p = compile(&[yaml], &ctx()).unwrap();
        let sb = &p.sandboxes["synergy-plus"];
        assert_eq!(sb.agent, "claude");
        assert_eq!(sb.workdir.as_deref(), Some("/workspace"));
        assert_eq!(sb.resources.cpus, Some(8));
        assert_eq!(sb.resources.memory_mib, Some(8 * 1024));
        assert_eq!(sb.resources.disks.root_mib, Some(128 * 1024));
        assert_eq!(sb.mounts.len(), 1);
        assert_eq!(sb.mounts[0].kind, MountKind::Bind);
        assert_eq!(sb.mounts[0].source, "./osbx");
        assert_eq!(sb.mounts[0].target, "/workspace/osbx");
        assert!(!sb.mounts[0].read_only);
        assert_eq!(sb.kits[0].handle, "claude-sessions");
        assert_eq!(
            sb.kits[0].mounts["/home/agent/claude-history"],
            "./.sessions"
        );
        assert_eq!(sb.firewall.default, Some(FirewallDefault::Deny));
        assert_eq!(sb.firewall.rules.len(), 2);
        assert_eq!(sb.firewall.rules[0].action, FirewallAction::Allow);
        assert_eq!(sb.firewall.rules[0].dest, "google.com");
        assert_eq!(sb.firewall.rules[1].action, FirewallAction::Deny);
        assert_eq!(sb.firewall.rules[1].dest, "*.evil.com");
    }

    #[test]
    fn full_featured_compose_file() {
        let yaml = r#"
version: "1"
name: osbx
args:
  model:
    default: opus
    enum: [opus, sonnet]

x-base: &base
  agent: claude
  workspace: /workspace
  environment:
    MODEL: "${model}"
    ESCAPED: "$$HOME"

secrets:
  anthropic:
    ref: "op://Dev/Anthropic/key"
    backend: cli
    refresh: 55m
    bindings:
      api_key: [api.anthropic.com]
      oauth: [claude.ai, api.anthropic.com]
  custom:
    command: "echo tok"
    inject:
      env: CUSTOM_TOKEN
      rules:
        - domain: api.custom.dev
          header: X-Api-Key
          format: "Key %s"

volumes:
  cargo-registry: {}
  host-cache:
    driver: host
    path: ./cache

firewalls:
  rust:
    allow: [crates.io, static.crates.io]

registries:
  ghcr.io:
    username: { value: me }
    secret: { command: "gh auth token" }

mcp:
  docs:
    command: npx
    args: ["-y", "docs-mcp", "${OSBX_FILE_DIR}/docs"]

sandboxes:
  dev:
    <<: *base
    cpus: 4
    memory: 4G
    disk:
      root: 40G
      docker: 20G
      clone: 10G
    volumes:
      - ./repo:/workspace/repo:clone
      - ./ro:/workspace/ro:ro
      - cargo-registry:/home/agent/.cargo/registry
      - type: kit-mount
        source: ./sessions
        target: /home/agent/claude-history
        mode: "0700"
    ports:
      - "127.0.0.1:8080:3000/tcp"
      - "5173"
      - target: 6080
        host: 6080
        protocol: tcp4
    capabilities:
      kvm: { enabled: true, required: false }
      docker: true
      ssh_agent:
        enabled: true
        required: false
        sign_namespaces: [git]
    skills: readonly
    writable_env_files: false
    firewall:
      default: balanced
      extends: [rust]
      allow:
        - hosts: [api.github.com]
          methods: [GET]
          paths: ["/repos/org/*"]
          query: { per_page: "100" }
          phase: runtime
      deny:
        - "169.254.169.254"
    secrets:
      - anthropic
      - source: custom
        required: false
    registries: [ghcr.io]
    mcp: [docs]
    hooks:
      initialize:
        - name: prep
          command: mkdir -p ./sessions
          timeout: 1m
      guest:
        files:
          - path: /home/agent/.gitconfig
            content: "[user]\nname = Bot\n"
            mode: "0644"
        install:
          - command: echo install
            user: agent
        startup:
          - command: echo startup
            background: true

  dev-kvm:
    extends: dev
    profiles: [kvm]
    capabilities:
      kvm: true
"#;
        let p = compile(&[yaml], &ctx()).unwrap();
        assert_eq!(p.name.as_deref(), Some("osbx"));
        assert_eq!(p.volumes.len(), 2);
        assert_eq!(p.active_sandboxes(&[]).len(), 1);
        assert_eq!(p.active_sandboxes(&["kvm".into()]).len(), 2);

        let dev = &p.sandboxes["dev"];
        assert_eq!(dev.env["MODEL"], "opus");
        assert_eq!(dev.env["ESCAPED"], "$HOME");
        assert_eq!(dev.resources.disks.root_mib, Some(40 * 1024));
        assert_eq!(dev.resources.disks.docker_mib, Some(20 * 1024));
        assert_eq!(dev.resources.disks.cloned_workspace_mib, Some(10 * 1024));
        assert_eq!(dev.mounts[0].kind, MountKind::Clone);
        assert!(dev.mounts[1].read_only);
        assert_eq!(dev.mounts[2].kind, MountKind::Volume);
        assert_eq!(dev.mounts[3].kind, MountKind::KitMount);
        assert_eq!(dev.ports.len(), 3);
        assert_eq!(dev.ports[0].host, 8080);
        assert_eq!(dev.ports[0].target, 3000);
        assert_eq!(dev.ports[1].host, 0);
        assert_eq!(dev.ports[1].target, 5173);
        assert_eq!(
            dev.capabilities.kvm,
            Some(CapabilityToggle::new(true, false))
        );
        assert_eq!(
            dev.capabilities.docker,
            Some(CapabilityToggle::new(true, true))
        );
        assert_eq!(dev.firewall.rules.len(), 4);
        assert!(dev.firewall.rules[2].http.is_some());
        assert_eq!(dev.secrets["anthropic"].bindings.api_key_domains, ["api.anthropic.com"]);
        assert!(!dev.secrets["custom"].required);
        assert_eq!(dev.mcp.len(), 1);
        assert_eq!(dev.hooks.initialize.len(), 1);
        assert_eq!(dev.hooks.guest_files.len(), 1);

        // `dev-kvm` inherited `dev` via `extends:` and overrode `kvm: true` (required)
        let kvm = &p.sandboxes["dev-kvm"];
        assert_eq!(kvm.agent, "claude");
        assert_eq!(
            kvm.capabilities.kvm,
            Some(CapabilityToggle::new(true, true))
        );
    }

    #[test]
    fn interpolation_and_dotenv() {
        let env = parse_dotenv(
            r#"
            # comment
            FOO=bar
            export QUOTED="hello world" # ignored inside quotes
            SINGLE='a b'
            INLINE=val # trailing comment
            "#,
        )
        .unwrap();
        assert_eq!(env["FOO"], "bar");
        assert_eq!(env["QUOTED"], "hello world");
        assert_eq!(env["SINGLE"], "a b");
        assert_eq!(env["INLINE"], "val");

        let yaml = r#"
sandboxes:
  s:
    agent: shell
    environment:
      A: "${FOO}"
      B: "${MISSING:-fallback}"
      C: "${EMPTY:-nonempty}"
"#;
        let mut c = ctx();
        c.vars.insert("FOO".into(), "from-env".into());
        c.vars.insert("EMPTY".into(), "".into());
        let p = compile(&[yaml], &c).unwrap();
        assert_eq!(p.sandboxes["s"].env["A"], "from-env");
        assert_eq!(p.sandboxes["s"].env["B"], "fallback");
        assert_eq!(p.sandboxes["s"].env["C"], "nonempty");

        // `:?` errors cleanly when unset
        let req = "sandboxes:\n  s:\n    agent: shell\n    environment:\n      X: \"${NEEDED:?must set NEEDED}\"\n";
        assert!(
            compile(&[req], &ctx())
                .unwrap_err()
                .to_string()
                .contains("must set NEEDED")
        );
    }

    #[test]
    fn strict_decoding_and_validation_errors() {
        // Unknown key
        let bad_key = "sandboxes:\n  s:\n    agent: shell\n    cpu: 4\n";
        assert!(
            compile(&[bad_key], &ctx())
                .unwrap_err()
                .to_string()
                .contains("unknown field `cpu`")
        );

        // Undeclared secret reference
        let bad_sec = "sandboxes:\n  s:\n    agent: shell\n    secrets: [missing]\n";
        assert!(
            compile(&[bad_sec], &ctx())
                .unwrap_err()
                .to_string()
                .contains("not declared")
        );

        // Undeclared volume reference
        let bad_vol = "sandboxes:\n  s:\n    agent: shell\n    volumes: [cache:/cache]\n";
        assert!(
            compile(&[bad_vol], &ctx())
                .unwrap_err()
                .to_string()
                .contains("undeclared top-level volume")
        );

        // Invalid version
        let bad_ver = "version: \"2\"\nsandboxes:\n  s:\n    agent: shell\n";
        assert!(
            compile(&[bad_ver], &ctx())
                .unwrap_err()
                .to_string()
                .contains("version")
        );
    }

    #[test]
    fn windows_path_in_short_volume() {
        let m = parse_short_volume(r"C:\src\osbx:/workspace/osbx:ro").unwrap();
        assert_eq!(m.kind, MountKind::Bind);
        assert_eq!(m.source, r"C:\src\osbx");
        assert_eq!(m.target, "/workspace/osbx");
        assert!(m.read_only);
    }

    #[test]
    fn layering_merges_and_concatenates_hooks() {
        let base = r#"
sandboxes:
  dev:
    agent: claude
    cpus: 4
    memory: 4G
    environment:
      A: base
      B: base
    hooks:
      initialize:
        - command: echo base
"#;
        let over = r#"
sandboxes:
  dev:
    cpus: 8
    environment:
      B: override
    hooks:
      initialize:
        - command: echo override
"#;
        let p = compile(&[base, over], &ctx()).unwrap();
        let dev = &p.sandboxes["dev"];
        assert_eq!(dev.resources.cpus, Some(8));
        assert_eq!(dev.resources.memory_mib, Some(4096));
        assert_eq!(dev.env["A"], "base");
        assert_eq!(dev.env["B"], "override");
        let cmds: Vec<_> = dev
            .hooks
            .initialize
            .iter()
            .map(|c| c.command.as_str())
            .collect();
        assert_eq!(cmds, ["echo base", "echo override"]);
    }
}
