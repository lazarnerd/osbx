//! Descriptor validation (spec §11). Collects every independent failure.
//!
//! Typed config checks exist for `network-policy@1`, `credential@1`, `host-mount@1`
//! and `volume@1` (the types the cross-entry rules need). All other well-known types
//! are checked for grammar, arity and config-lessness only; their config is carried
//! opaquely until their pages are implemented.

use crate::descriptor::{Capability, Descriptor, Kind};
use crate::version::{
    Provide, RESERVED_NAMESPACES, Requirement, Version, normalize_name, validate_name,
};
use regex::Regex;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;

/// One validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Dotted path of the offending element.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Singleton capability types (spec §7.1).
pub const SINGLETONS: &[&str] = &[
    "network-policy@1",
    "network-policy@2",
    "resources@1",
    "privileged@1",
    "kvm@1",
    "dockerd@1",
    "kit-registry@1",
    "agent-sessions@1",
    "agent-sessions@2",
    "agent-interactive-sessions@1",
    "lifecycle@1",
    "sbx@1",
    "long-running@1",
    "auto-restart@1",
    "open-url@1",
    "git-identity@1",
];
/// Types that reject any config.
pub const CONFIG_LESS: &[&str] = &[
    "privileged@1",
    "kvm@1",
    "kit-registry@1",
    "sbx@1",
    "long-running@1",
    "auto-restart@1",
    "git-identity@1",
];
/// Pairs that must not both appear.
const EXCLUSIVE: &[(&str, &str)] = &[
    ("network-policy@1", "network-policy@2"),
    ("agent-sessions@1", "agent-sessions@2"),
];
const NS: &str = "com.docker.sandbox/";

static CAP_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?/[a-z0-9]([a-z0-9-]*[a-z0-9])?@[1-9][0-9]*$")
        .unwrap()
});
static ARG_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());
static ARG_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{\{\s*kit\.args\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").unwrap());
static DIGEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^sha256:[0-9a-f]{64}$").unwrap());

struct Ctx(Vec<Issue>);
impl Ctx {
    fn err(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(Issue {
            path: path.into(),
            message: message.into(),
        });
    }
}

/// Validate an authored descriptor. Returns all issues (empty = valid).
pub fn validate(d: &Descriptor) -> Vec<Issue> {
    validate_form(d, false)
}

/// Validate a published descriptor (as read from a kit image). Differences from the authored
/// form (spec §11): `deb/` and `apk/` provides are expected (publishing derives them), and
/// `providesFrom` and `kind: set` must be gone.
pub fn validate_published(d: &Descriptor) -> Vec<Issue> {
    let mut issues = validate_form(d, true);
    if d.provides_from.is_some() {
        issues.push(Issue {
            path: "providesFrom".into(),
            message: "must not appear in a published descriptor".into(),
        });
    }
    if d.kind == Kind::Set {
        issues.push(Issue {
            path: "kind".into(),
            message: "a published kit is a workload or a mixin, never a set".into(),
        });
    }
    issues
}

fn validate_form(d: &Descriptor, published: bool) -> Vec<Issue> {
    let mut c = Ctx(Vec::new());
    top_level(d, &mut c);
    kit_lists(d, &mut c, published);
    args(d, &mut c);
    capabilities(d, &mut c);
    c.0
}

fn top_level(d: &Descriptor, c: &mut Ctx) {
    if d.schema_version != "3" {
        c.err(
            "schemaVersion",
            format!("must be \"3\", got {:?}", d.schema_version),
        );
    }
    if d.kind == Kind::Sandbox {
        c.err(
            "kind",
            "`sandbox` is the pre-rename spelling of `workload`; authors must not write it",
        );
    }
    let recipes = [
        d.build.is_some(),
        d.dockerfile.is_some(),
        !d.kits.is_empty(),
    ];
    if recipes.iter().filter(|b| **b).count() > 1 {
        c.err("build/dockerfile/kits", "mutually exclusive");
    }
    if let Some(p) = &d.dockerfile
        && (p.starts_with('/') || p.split('/').any(|s| s == ".."))
    {
        c.err(
            "dockerfile",
            "must be relative and stay inside the descriptor's directory",
        );
    }
    if d.kind == Kind::Set && d.kits.is_empty() {
        c.err("kits", "a kind: set descriptor must list at least one kit");
    }
    if let Some(v) = &d.version
        && !ARG_REF.is_match(v)
        && let Err(e) = Version::parse(v)
    {
        c.err("version", e);
    }
    if let Some(u) = &d.icon_url
        && !u.starts_with("https://")
    {
        c.err("iconUrl", "must be an absolute https URL");
    }
    if let Some(pf) = &d.provides_from {
        if d.kind != Kind::Workload {
            c.err("providesFrom", "workload only");
        }
        if !d.kits.is_empty() {
            c.err("providesFrom", "never beside kits");
        }
        for (name, path) in pf {
            if let Err(e) = validate_name(name) {
                c.err(format!("providesFrom.{name}"), e);
            }
            if name
                .split_once('/')
                .is_some_and(|(ns, _)| RESERVED_NAMESPACES.contains(&ns))
            {
                c.err(format!("providesFrom.{name}"), "reserved namespace");
            }
            if !canonical_abs_path(path) {
                c.err(
                    format!("providesFrom.{name}"),
                    "value must be an absolute canonical path",
                );
            }
        }
    }
}

fn kit_lists(d: &Descriptor, c: &mut Ctx, published: bool) {
    for (i, p) in d.provides.iter().enumerate() {
        // Arg references are only legal here; check the remainder after masking them.
        let masked = ARG_REF.replace_all(p, "1");
        match Provide::parse(&masked) {
            Ok(pv) => {
                if !published
                    && pv
                        .name
                        .split_once('/')
                        .is_some_and(|(ns, _)| RESERVED_NAMESPACES.contains(&ns))
                {
                    c.err(
                        format!("provides[{i}]"),
                        "deb/ and apk/ are derived by publishing and must not be authored",
                    );
                }
            }
            Err(e) => c.err(format!("provides[{i}]"), e),
        }
    }
    for (field, list) in [("requires", &d.requires), ("integrates", &d.integrates)] {
        for (i, r) in list.iter().enumerate() {
            if r.contains("${{") {
                c.err(
                    format!("{field}[{i}]"),
                    "must be literal: no arg references",
                );
            } else if let Err(e) = Requirement::parse(r) {
                c.err(format!("{field}[{i}]"), e);
            }
        }
    }
    for (i, n) in d.conflicts.iter().enumerate() {
        if n.contains("${{") {
            c.err(
                format!("conflicts[{i}]"),
                "must be literal: no arg references",
            );
        } else if let Err(e) = validate_name(n) {
            c.err(format!("conflicts[{i}]"), e);
        }
    }
    let mut seen = BTreeSet::new();
    for (i, k) in d.kits.iter().enumerate() {
        let r = &k.reference;
        if r.is_empty()
            || r.starts_with(['.', '/'])
            || r.contains("://")
            || r.starts_with("git+")
            || r.ends_with(".zip")
        {
            c.err(
                format!("kits[{i}].ref"),
                "must be a registry reference (no path, URL or git source)",
            );
        }
        if let Some(dg) = &k.digest
            && !DIGEST.is_match(dg)
        {
            c.err(
                format!("kits[{i}].digest"),
                "must be sha256:<64 lowercase hex>",
            );
        }
        if !seen.insert(r.clone()) {
            c.err(format!("kits[{i}].ref"), "kit listed twice");
        }
    }
}

fn args(d: &Descriptor, c: &mut Ctx) {
    for (name, a) in &d.args {
        let p = format!("args.{name}");
        if !ARG_KEY.is_match(name) {
            c.err(&p, "name must match ^[A-Za-z_][A-Za-z0-9_]*$");
        }
        if a.default.is_some() && a.required == Some(true) {
            c.err(&p, "default and required are mutually exclusive");
        }
        if a.enum_values.is_some() && a.pattern.is_some() {
            c.err(&p, "enum and pattern are mutually exclusive");
        }
        let delivery = [
            a.env.is_some(),
            a.build_arg.is_some(),
            a.build_secret.is_some(),
        ];
        if delivery.iter().filter(|b| **b).count() > 1 {
            c.err(&p, "env, buildArg and buildSecret are mutually exclusive");
        }
        for (f, v) in [("env", &a.env), ("buildArg", &a.build_arg)] {
            if let Some(v) = v
                && !ARG_KEY.is_match(v)
            {
                c.err(format!("{p}.{f}"), "invalid name");
            }
        }
        if let Some(pat) = &a.pattern {
            match Regex::new(&format!("^(?:{pat})$")) {
                Err(e) => c.err(format!("{p}.pattern"), format!("does not compile: {e}")),
                Ok(re) => {
                    if let Some(def) = &a.default
                        && !re.is_match(def)
                    {
                        c.err(format!("{p}.default"), "does not match its own pattern");
                    }
                }
            }
        }
        if let (Some(en), Some(def)) = (&a.enum_values, &a.default)
            && !en.contains(def)
        {
            c.err(format!("{p}.default"), "not in enum");
        }
    }
    // every reference must be declared (build secrets cannot be referenced)
    let mut texts = Vec::new();
    collect_strings(
        &serde_yaml_ng::to_value(&d.provides).unwrap_or(Value::Null),
        &mut texts,
    );
    for t in d.version.iter().chain(d.description.iter()) {
        texts.push(t.clone());
    }
    for (_, cap) in d.requests() {
        if let Some(cfg) = &cap.config {
            collect_strings(cfg, &mut texts);
        }
    }
    for t in texts {
        for m in ARG_REF.captures_iter(&t) {
            match d.args.get(&m[1]) {
                None => c.err("args", format!("reference to undeclared arg {:?}", &m[1])),
                Some(a) if a.build_secret.is_some() => c.err(
                    "args",
                    format!("build secret {:?} cannot be referenced", &m[1]),
                ),
                Some(_) => {}
            }
        }
    }
}

fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Sequence(s) => s.iter().for_each(|x| collect_strings(x, out)),
        Value::Mapping(m) => m.iter().for_each(|(k, x)| {
            collect_strings(k, out);
            collect_strings(x, out);
        }),
        _ => {}
    }
}

fn has_ref(v: &Value) -> bool {
    let mut s = Vec::new();
    collect_strings(v, &mut s);
    s.iter().any(|t| t.contains("${{"))
}

fn canonical_abs_path(p: &str) -> bool {
    p.starts_with('/')
        && p != "/"
        && !p.ends_with('/')
        && !p.contains('\0')
        && !p.contains("//")
        && p.split('/').skip(1).all(|s| s != "." && s != "..")
}

fn valid_size_string(s: &str) -> bool {
    let t = s.trim().to_ascii_lowercase();
    let num = t
        .strip_suffix("gib")
        .or_else(|| t.strip_suffix("mib"))
        .or_else(|| t.strip_suffix("kib"))
        .or_else(|| t.strip_suffix("gb"))
        .or_else(|| t.strip_suffix("mb"))
        .or_else(|| t.strip_suffix("kb"))
        .or_else(|| t.strip_suffix(['g', 'm', 'k', 'b']))
        .unwrap_or(&t);
    !num.is_empty() && num.parse::<u64>().is_ok_and(|n| n > 0)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PhaseLists {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetPolicy1 {
    install: Option<PhaseLists>,
    runtime: Option<PhaseLists>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HttpRuleEntry {
    hosts: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    query: std::collections::BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum NetPolicy2Entry {
    Host(String),
    Http(HttpRuleEntry),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PhaseLists2 {
    #[serde(default)]
    allow: Vec<NetPolicy2Entry>,
    #[serde(default)]
    deny: Vec<NetPolicy2Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetPolicy2 {
    install: Option<PhaseLists2>,
    runtime: Option<PhaseLists2>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Phases {
    One(String),
    Many(Vec<String>),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inject {
    domain: String,
    #[allow(dead_code)]
    header: Option<String>,
    #[allow(dead_code)]
    format: Option<String>,
    #[allow(dead_code)]
    scheme: Option<String>,
    #[allow(dead_code)]
    username: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApiKey {
    name: Option<String>,
    #[allow(dead_code)]
    proxy_managed: Option<bool>,
    #[serde(default)]
    inject: Vec<Inject>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredConfig {
    service: String,
    phase: Phases,
    api_key: Option<ApiKey>,
    oauth: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MountConfig {
    path: String,
    #[allow(dead_code)]
    mode: Option<String>,
    #[allow(dead_code)]
    size: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortConfig {
    #[allow(dead_code)]
    name: Option<String>,
    container: u16,
    transport: Option<String>,
    family: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourcesConfig {
    cpu: Option<f64>,
    memory: Option<String>,
    #[allow(dead_code)]
    gpu: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshAgentConfig {
    phase: Option<Phases>,
    unrestricted: Option<bool>,
    #[serde(default)]
    sign: Vec<String>,
    #[serde(default)]
    authenticate: Vec<String>,
}

fn short_type(ty: &str) -> Option<&str> {
    ty.strip_prefix(NS)
}

fn decode<T: for<'de> Deserialize<'de>>(cfg: &Option<Value>, path: &str, c: &mut Ctx) -> Option<T> {
    let v = cfg.clone().unwrap_or(Value::Mapping(Default::default()));
    match serde_yaml_ng::from_value(v) {
        Ok(t) => Some(t),
        Err(e) => {
            c.err(format!("{path}.config"), e.to_string());
            None
        }
    }
}

/// Does a network-policy allow entry cover `domain`? (`*`/`**` cover everything; ports ignored.)
fn allow_covers(entry: &str, domain: &str) -> bool {
    let host = entry
        .rsplit_once(':')
        .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
        .map_or(entry, |(h, _)| h);
    if host == "*" || host == "**" || host.eq_ignore_ascii_case(domain) {
        return true;
    }
    match host.strip_prefix("*.") {
        Some(suffix) => domain
            .strip_suffix(suffix)
            .and_then(|p| p.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => false,
    }
}

fn capabilities(d: &Descriptor, c: &mut Ctx) {
    for (i, item) in d.capabilities.iter().enumerate() {
        if let crate::descriptor::CapabilityItem::Group(g) = item {
            if g.capabilities.is_empty() {
                c.err(format!("capabilities[{i}].group"), "empty group");
            }
            for (j, m) in g.capabilities.iter().enumerate() {
                if m.optional.is_some() {
                    c.err(
                        format!("capabilities[{i}].group.capabilities[{j}]"),
                        "members must not state `optional`, even false",
                    );
                }
            }
        }
    }
    // block id -> types seen; for arity
    let mut singles: std::collections::BTreeMap<(Option<usize>, String), usize> =
        Default::default();
    let mut all_types: BTreeSet<String> = BTreeSet::new();
    let mut storage: std::collections::BTreeMap<String, String> = Default::default();
    let mut cred_keys: BTreeSet<(Option<usize>, String, String)> = BTreeSet::new();
    let mut exact: Vec<(Option<usize>, &Capability)> = Vec::new();
    let mut policy: Option<(usize, PolicyLists)> = None;
    let mut creds: Vec<(usize, String, Vec<String>, Vec<String>)> = Vec::new(); // (idx, service, phases, domains)
    let mut has_dockerd = false;

    for (idx, (block, cap)) in d.requests().enumerate() {
        let path = format!("capabilities[{idx}]");
        if let Some(n) = &cap.name
            && n.contains('\0')
        {
            c.err(format!("{path}.name"), "NUL");
        }
        if !CAP_TYPE.is_match(&cap.ty) {
            c.err(
                format!("{path}.type"),
                format!("{:?} is not <namespace>/<name>@<version>", cap.ty),
            );
            continue;
        }
        if exact.iter().any(|(b, o)| *b == block && *o == cap) {
            c.err(&path, "exact duplicate entry");
        }
        exact.push((block, cap));
        all_types.insert(cap.ty.clone());
        let Some(short) = short_type(&cap.ty) else {
            continue;
        };
        let deferred = cap.config.as_ref().is_some_and(has_ref);

        if SINGLETONS.contains(&short) {
            let n = singles.entry((block, short.to_owned())).or_default();
            *n += 1;
            if *n > 1 {
                c.err(
                    &path,
                    format!("{short} is a singleton: at most one per declaration block"),
                );
            }
        }
        if CONFIG_LESS.contains(&short)
            && cap
                .config
                .as_ref()
                .is_some_and(|v| !v.is_null() && v.as_mapping().is_none_or(|m| !m.is_empty()))
        {
            c.err(format!("{path}.config"), format!("{short} takes no config"));
        }
        if deferred {
            continue; // typed checks run on the effective (expanded) form
        }
        match short {
            "network-policy@1" => {
                if let Some(np) = decode::<NetPolicy1>(&cap.config, &path, c) {
                    let lists =
                        |p: Option<PhaseLists>| p.map(|p| (p.allow, p.deny)).unwrap_or_default();
                    policy = Some((
                        idx,
                        PolicyLists {
                            install: lists(np.install),
                            runtime: lists(np.runtime),
                        },
                    ));
                }
            }
            "network-policy@2" => {
                if let Some(np) = decode::<NetPolicy2>(&cap.config, &path, c) {
                    let mut extract = |phase_name: &str, p: Option<PhaseLists2>| {
                        let Some(p) = p else {
                            return (Vec::new(), Vec::new());
                        };
                        let mut collect = |list_name: &str, entries: Vec<NetPolicy2Entry>| {
                            let mut hosts = Vec::new();
                            for (i, entry) in entries.into_iter().enumerate() {
                                match entry {
                                    NetPolicy2Entry::Host(h) => {
                                        if h.trim().is_empty() {
                                            c.err(
                                                format!(
                                                    "{path}.config.{phase_name}.{list_name}[{i}]"
                                                ),
                                                "host must not be empty",
                                            );
                                        } else {
                                            hosts.push(h);
                                        }
                                    }
                                    NetPolicy2Entry::Http(r) => {
                                        let ep =
                                            format!("{path}.config.{phase_name}.{list_name}[{i}]");
                                        if r.hosts.is_empty() {
                                            c.err(
                                                format!("{ep}.hosts"),
                                                "must list at least one host",
                                            );
                                        }
                                        for m in &r.methods {
                                            if m.is_empty()
                                                || !m.chars().all(|ch| ch.is_ascii_alphabetic())
                                            {
                                                c.err(
                                                    format!("{ep}.methods"),
                                                    format!("invalid HTTP method {m:?}"),
                                                );
                                            }
                                        }
                                        for pth in &r.paths {
                                            if !pth.starts_with('/') && pth != "*" {
                                                c.err(
                                                    format!("{ep}.paths"),
                                                    format!("path {pth:?} must start with '/'"),
                                                );
                                            }
                                        }
                                        let _ = &r.query;
                                        hosts.extend(r.hosts);
                                    }
                                }
                            }
                            hosts
                        };
                        (collect("allow", p.allow), collect("deny", p.deny))
                    };
                    let install = extract("install", np.install);
                    let runtime = extract("runtime", np.runtime);
                    policy = Some((idx, PolicyLists { install, runtime }));
                }
            }
            "credential@1" => {
                if let Some(cc) = decode::<CredConfig>(&cap.config, &path, c) {
                    let phases = match cc.phase {
                        Phases::One(p) => vec![p],
                        Phases::Many(v) => v,
                    };
                    if phases.is_empty() {
                        c.err(format!("{path}.config.phase"), "must not be empty");
                    }
                    for p in &phases {
                        if p != "install" && p != "runtime" {
                            c.err(
                                format!("{path}.config.phase"),
                                format!("unknown phase {p:?}"),
                            );
                        } else if !cred_keys.insert((block, cc.service.clone(), p.clone())) {
                            c.err(
                                &path,
                                format!("(service {:?}, phase {p:?}) declared twice", cc.service),
                            );
                        }
                    }
                    if phases.iter().collect::<BTreeSet<_>>().len() != phases.len() {
                        c.err(format!("{path}.config.phase"), "phases must be distinct");
                    }
                    if cc.api_key.is_none() && cc.oauth.is_none() {
                        c.err(
                            format!("{path}.config"),
                            "at least one of apiKey/oauth is required",
                        );
                    }
                    let mut domains = Vec::new();
                    if let Some(k) = &cc.api_key {
                        if k.name.as_deref().unwrap_or("").is_empty() && k.inject.is_empty() {
                            c.err(
                                format!("{path}.config.apiKey"),
                                "at least one of name/inject is required",
                            );
                        }
                        domains = k.inject.iter().map(|i| i.domain.clone()).collect();
                    }
                    creds.push((idx, cc.service, phases, domains));
                }
            }
            "host-mount@1" | "volume@1" => {
                if let Some(m) = decode::<MountConfig>(&cap.config, &path, c) {
                    if !canonical_abs_path(&m.path) {
                        c.err(
                            format!("{path}.config.path"),
                            "must be absolute and canonical (no ., .., //, trailing / or root)",
                        );
                    } else if let Some(prev) = storage.insert(m.path.clone(), cap.ty.clone()) {
                        c.err(
                            &path,
                            format!("storage path {} already declared by {prev}", m.path),
                        );
                    }
                }
            }
            "port@1" => {
                if let Some(p) = decode::<PortConfig>(&cap.config, &path, c) {
                    if p.container == 0 {
                        c.err(format!("{path}.config.container"), "must be 1..=65535");
                    }
                    if let Some(t) = &p.transport
                        && t != "tcp"
                        && t != "udp"
                    {
                        c.err(
                            format!("{path}.config.transport"),
                            format!("unknown transport {t:?} (tcp | udp)"),
                        );
                    }
                    if let Some(f) = &p.family
                        && !matches!(f.as_str(), "ipv4" | "ipv6" | "dual")
                    {
                        c.err(
                            format!("{path}.config.family"),
                            format!("unknown family {f:?} (ipv4 | ipv6 | dual)"),
                        );
                    }
                }
            }
            "resources@1" => {
                if let Some(r) = decode::<ResourcesConfig>(&cap.config, &path, c) {
                    if let Some(cpu) = r.cpu
                        && (!cpu.is_finite() || cpu < 0.0)
                    {
                        c.err(format!("{path}.config.cpu"), "must be a finite number >= 0");
                    }
                    if let Some(mem) = &r.memory
                        && !valid_size_string(mem)
                    {
                        c.err(
                            format!("{path}.config.memory"),
                            format!("invalid memory size {mem:?}"),
                        );
                    }
                }
            }
            "ssh-agent@1" => {
                if let Some(sa) = decode::<SshAgentConfig>(&cap.config, &path, c) {
                    if let Some(ph) = sa.phase {
                        let phases = match ph {
                            Phases::One(p) => vec![p],
                            Phases::Many(v) => v,
                        };
                        if phases.is_empty() {
                            c.err(format!("{path}.config.phase"), "must not be empty");
                        }
                        for p in &phases {
                            if p != "install" && p != "runtime" {
                                c.err(
                                    format!("{path}.config.phase"),
                                    format!("unknown phase {p:?}"),
                                );
                            }
                        }
                        if phases.iter().collect::<BTreeSet<_>>().len() != phases.len() {
                            c.err(format!("{path}.config.phase"), "phases must be distinct");
                        }
                    }
                    if sa.unrestricted == Some(false)
                        && sa.sign.is_empty()
                        && sa.authenticate.is_empty()
                    {
                        c.err(
                            format!("{path}.config"),
                            "unrestricted: false requires at least one of sign/authenticate",
                        );
                    }
                }
            }
            "dockerd@1" => has_dockerd = true,
            _ => {}
        }
    }
    for (a, b) in EXCLUSIVE {
        if all_types.contains(&format!("{NS}{a}")) && all_types.contains(&format!("{NS}{b}")) {
            c.err("capabilities", format!("{a} and {b} are exclusive"));
        }
    }
    if has_dockerd {
        for p in storage.keys() {
            if p == "/var/lib/docker" || p.starts_with("/var/lib/docker/") {
                c.err("capabilities", format!("{p} is owned by dockerd@1"));
            }
        }
    }
    // cross-entry: every credential inject domain is in the matching phase's allow list
    if let Some((_, np)) = &policy {
        for (idx, service, phases, domains) in &creds {
            for ph in phases {
                let allow = if ph == "install" {
                    &np.install.0
                } else {
                    &np.runtime.0
                };
                for dom in domains {
                    if !allow.iter().any(|e| allow_covers(e, dom)) {
                        c.err(
                            format!("capabilities[{idx}]"),
                            format!("credential {service:?} injects {dom} in phase {ph} but network-policy allows no such host"),
                        );
                    }
                }
            }
        }
    }
}

struct PolicyLists {
    install: (Vec<String>, Vec<String>),
    runtime: (Vec<String>, Vec<String>),
}

/// Convenience: set of normalized names a descriptor provides, after validation.
pub fn provided_names(d: &Descriptor) -> Vec<String> {
    d.provides
        .iter()
        .filter_map(|p| Provide::parse(p).ok())
        .map(|p| p.name)
        .collect()
}

/// Normalized form of a conflicts/requires name (re-export for callers).
pub fn norm(name: &str) -> String {
    normalize_name(name)
}
