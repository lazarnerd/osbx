//! Kits at runtime: load, validate, resolve and select at create; apply at start.

use osbx_kit::{Capability, ConfigValue, Descriptor, Kind, KitInput};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// Capability types this runtime implements.
pub const SUPPORTED: &[&str] = &[
    "com.docker.sandbox/network-policy@1",
    "com.docker.sandbox/network-policy@2",
    "com.docker.sandbox/credential@1",
    "com.docker.sandbox/lifecycle@1",
    "com.docker.sandbox/host-mount@1",
    "com.docker.sandbox/volume@1",
    "com.docker.sandbox/port@1",
    "com.docker.sandbox/resources@1",
    "com.docker.sandbox/ssh-agent@1",
    "com.docker.sandbox/kvm@1",
    "com.docker.sandbox/dockerd@1",
    "com.docker.sandbox/privileged@1",
    "com.docker.sandbox/sbx@1",
];

/// A kit as recorded in the sandbox definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KitRecord {
    /// Where it came from (path or image reference).
    pub source: String,
    /// Handle (directory name or last repository segment).
    pub handle: String,
    /// `workload` or `mixin`.
    pub kind: String,
    /// The descriptor text (YAML or the published JSON).
    pub descriptor: String,
    /// Image carrying the kit's content (OCI kits only).
    #[serde(default)]
    pub image: Option<String>,
    /// Capability types granted for this kit.
    #[serde(default)]
    pub granted: Vec<String>,
    /// Optional capability types skipped (unsupported or unavailable here).
    #[serde(default)]
    pub skipped: Vec<String>,
    /// Environment variables delivered by resolved create-phase kit args (`arg.env`).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl KitRecord {
    /// Parse the stored descriptor.
    pub fn descriptor(&self) -> Result<Descriptor, String> {
        Descriptor::from_yaml(&self.descriptor)
    }

    /// Granted capability requests (groups flattened), in declaration order.
    pub fn granted_requests(&self) -> Vec<Capability> {
        let Ok(d) = self.descriptor() else {
            return Vec::new();
        };
        d.requests()
            .map(|(_, c)| c.clone())
            .filter(|c| self.granted.contains(&c.ty))
            .collect()
    }
}

fn handle_of(source: &str) -> String {
    let s = source.trim_end_matches(['/', '\\']);
    if Path::new(s).exists() {
        // a directory (any separator style): its last component
        return Path::new(s)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
    }
    let last = s.rsplit('/').next().unwrap_or(s);
    // image reference: drop digest and tag
    let no_digest = last.split('@').next().unwrap_or(last);
    no_digest.split(':').next().unwrap_or(no_digest).to_owned()
}

fn is_local(source: &str) -> bool {
    source.starts_with('.')
        || source.starts_with('/')
        || Path::new(source).is_absolute()
        || Path::new(source).is_dir()
}

/// Supplied create-phase kit arguments, either scoped to one kit handle (`kit.arg=val`) or
/// unscoped (`arg=val`, delivered to every kit that declares `arg`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuppliedKitArgs {
    /// Handle -> (arg name -> value).
    pub by_kit: BTreeMap<String, BTreeMap<String, String>>,
    /// Unscoped (arg name -> value).
    pub unscoped: BTreeMap<String, String>,
}

impl SuppliedKitArgs {
    /// Parse `--kit-arg` strings (`KIT.NAME=VALUE` or `NAME=VALUE`).
    pub fn parse(raw: &[String]) -> io::Result<Self> {
        let mut out = Self::default();
        for entry in raw {
            let (lhs, val) = entry.split_once('=').ok_or_else(|| {
                io::Error::other(format!(
                    "--kit-arg {entry:?}: expected KIT.NAME=VALUE or NAME=VALUE"
                ))
            })?;
            if let Some((handle, name)) = lhs.split_once('.') {
                if handle.is_empty() || name.is_empty() {
                    return Err(io::Error::other(format!(
                        "--kit-arg {entry:?}: empty kit handle or arg name"
                    )));
                }
                out.by_kit
                    .entry(handle.to_owned())
                    .or_default()
                    .insert(name.to_owned(), val.to_owned());
            } else {
                if lhs.is_empty() {
                    return Err(io::Error::other(format!(
                        "--kit-arg {entry:?}: empty arg name"
                    )));
                }
                out.unscoped.insert(lhs.to_owned(), val.to_owned());
            }
        }
        Ok(out)
    }
}

/// Load a kit's descriptor: a local directory (`<dir>/<dir>.yaml`) or an image reference
/// (descriptor staged at `/usr/share/sandbox/kit/<stem>/kit.yaml`), expanding create-phase args.
pub fn load(source: &str, supplied: &SuppliedKitArgs) -> io::Result<(KitRecord, BTreeSet<String>)> {
    let handle = handle_of(source);
    let (text, image) = if is_local(source) {
        let dir = PathBuf::from(source);
        let yaml = dir.join(format!("{handle}.yaml"));
        let text = std::fs::read_to_string(&yaml)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", yaml.display())))?;
        if dir.join(format!("{handle}.dockerfile")).exists()
            || text.contains("\nbuild:")
            || text.contains("\ndockerfile:")
        {
            return Err(io::Error::other(format!(
                "kit {source}: local kits with a content recipe must be built first (docker buildx build -f {handle}.yaml ...); declaration-only kits work directly"
            )));
        }
        (text, None)
    } else {
        let staged = read_staged_descriptor(source)?.ok_or_else(|| {
            io::Error::other(format!(
                "{source} carries no kit descriptor (/usr/share/sandbox/kit)"
            ))
        })?;
        (staged, Some(source.to_owned()))
    };
    finish_load(source, handle, text, image, supplied)
}

/// The workload kit an agent image carries, if it is one (e.g. `docker.io/sbx/claude`).
pub fn workload_for_image(
    image: &str,
    supplied: &SuppliedKitArgs,
) -> io::Result<Option<(KitRecord, BTreeSet<String>)>> {
    match read_staged_descriptor(image)? {
        Some(text) => {
            let (k, used) = finish_load(
                image,
                handle_of(image),
                text,
                Some(image.to_owned()),
                supplied,
            )?;
            Ok((k.kind == "workload").then_some((k, used)))
        }
        None => Ok(None),
    }
}

fn finish_load(
    source: &str,
    handle: String,
    text: String,
    image: Option<String>,
    supplied: &SuppliedKitArgs,
) -> io::Result<(KitRecord, BTreeSet<String>)> {
    let d =
        Descriptor::from_yaml(&text).map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    // image kits carry the published form (derived provides allowed); directories are authored
    let issues = if image.is_some() {
        osbx_kit::validate_published(&d)
    } else {
        osbx_kit::validate(&d)
    };
    if !issues.is_empty() {
        let list: Vec<String> = issues.iter().map(ToString::to_string).collect();
        return Err(io::Error::other(format!(
            "kit {source} is invalid:\n  {}",
            list.join("\n  ")
        )));
    }
    let kind = match d.kind {
        Kind::Workload | Kind::Sandbox => "workload",
        Kind::Mixin => "mixin",
        Kind::Set => {
            return Err(io::Error::other(format!(
                "kit {source}: kind set is authoring-only; publish it first"
            )));
        }
    };
    // create-phase expansion: supplied kit args (else defaults), kit.env from the image's env
    let env = match &image {
        Some(img) => image_env(img).unwrap_or_default(),
        None => BTreeMap::new(),
    };
    // build-phase args were baked in when the kit was published; only create-phase args resolve here
    let create_args: BTreeMap<String, osbx_kit::Arg> = d
        .args
        .iter()
        .filter(|(_, a)| a.build_arg.is_none() && a.build_secret.is_none())
        .map(|(k, a)| (k.clone(), a.clone()))
        .collect();
    let mut kit_supplied = BTreeMap::new();
    let mut used_unscoped = BTreeSet::new();
    for (k, v) in &supplied.unscoped {
        if create_args.contains_key(k) {
            kit_supplied.insert(k.clone(), v.clone());
            used_unscoped.insert(k.clone());
        }
    }
    if let Some(scoped) = supplied.by_kit.get(&handle) {
        for (k, v) in scoped {
            kit_supplied.insert(k.clone(), v.clone());
        }
    }
    let args = osbx_kit::expand::resolve_args(&create_args, &kit_supplied)
        .map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    let mut arg_env = BTreeMap::new();
    for (name, arg) in &create_args {
        if let (Some(var), Some(val)) = (&arg.env, args.get(name)) {
            arg_env.insert(var.clone(), val.clone());
        }
    }
    let doc: ConfigValue = serde_yaml_ng::from_str(&text)
        .map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    let expanded = osbx_kit::expand::expand(&doc, &args, &env)
        .map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    let text = serde_yaml_ng::to_string(&expanded).map_err(io::Error::other)?;
    // re-validate the effective (expanded) descriptor so deferred typed capability checks run
    let effective =
        Descriptor::from_yaml(&text).map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    let post_issues = if image.is_some() {
        osbx_kit::validate_published(&effective)
    } else {
        osbx_kit::validate(&effective)
    };
    if !post_issues.is_empty() {
        let list: Vec<String> = post_issues.iter().map(ToString::to_string).collect();
        return Err(io::Error::other(format!(
            "kit {source} is invalid after arg expansion:\n  {}",
            list.join("\n  ")
        )));
    }
    Ok((
        KitRecord {
            source: source.to_owned(),
            handle,
            kind: kind.into(),
            descriptor: text,
            image,
            granted: vec![],
            skipped: vec![],
            env: arg_env,
        },
        used_unscoped,
    ))
}

/// The image's final environment for `${{ kit.env.* }}` (see [`crate::images::image_env`]).
#[cfg(any(target_os = "linux", windows))]
fn image_env(image: &str) -> io::Result<std::collections::BTreeMap<String, String>> {
    crate::images::image_env(image)
}
#[cfg(not(any(target_os = "linux", windows)))]
fn image_env(_: &str) -> io::Result<std::collections::BTreeMap<String, String>> {
    Ok(Default::default())
}

/// The descriptor staged in an image at `/usr/share/sandbox/kit/<stem>/kit.yaml` (pulls the image
/// if needed). `None` when the image is not a kit.
#[cfg(any(target_os = "linux", windows))]
fn read_staged_descriptor(image: &str) -> io::Result<Option<String>> {
    crate::images::staged_descriptor(image)
}
#[cfg(not(any(target_os = "linux", windows)))]
fn read_staged_descriptor(image: &str) -> io::Result<Option<String>> {
    Err(io::Error::other(format!(
        "image kits ({image}) need a supported host"
    )))
}

/// Host's `SSH_AUTH_SOCK`, if present and pointing at a live path (Unix only).
pub fn host_ssh_auth_sock() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("SSH_AUTH_SOCK")
            .map(PathBuf::from)
            .filter(|p| p.exists())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Resolve the composition and select capabilities. `base_provides` stands in for a base image
/// that is not itself a kit. Fills `granted`/`skipped`; errors name what cannot be satisfied.
pub fn plan(
    kits: &mut [KitRecord],
    kvm_available: bool,
    ssh_agent_available: bool,
) -> io::Result<()> {
    let mut inputs = Vec::new();
    if !kits.iter().any(|k| k.kind == "workload") {
        // the base image plays the workload; it offers no kit capabilities
        inputs.push(KitInput {
            reference: "(base image)".into(),
            ref_version: None,
            descriptor: Descriptor::from_yaml("schemaVersion: \"3\"\nkind: workload\n")
                .expect("static"),
        });
    }
    for k in kits.iter() {
        let version = k
            .source
            .rsplit_once(':')
            .map(|(_, t)| t.to_owned())
            .filter(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()));
        inputs.push(KitInput {
            reference: k.source.clone(),
            ref_version: version,
            descriptor: k.descriptor().map_err(io::Error::other)?,
        });
    }
    if let Err(errs) = osbx_kit::resolve(&inputs) {
        let list: Vec<String> = errs.iter().map(ToString::to_string).collect();
        return Err(io::Error::other(format!(
            "the kits do not compose:\n  {}",
            list.join("\n  ")
        )));
    }
    let mut supported: BTreeSet<String> = SUPPORTED.iter().map(|s| (*s).to_owned()).collect();
    if !kvm_available {
        supported.remove("com.docker.sandbox/kvm@1");
    }
    if !ssh_agent_available {
        supported.remove("com.docker.sandbox/ssh-agent@1");
    }
    for k in kits.iter_mut() {
        let d = k.descriptor().map_err(io::Error::other)?;
        match osbx_kit::select(&d, &supported) {
            Ok(sel) => {
                k.granted = sel.granted;
                k.skipped = sel.skipped.into_iter().map(|(t, _)| t).collect();
            }
            Err(e) => {
                let why = if e.ty.ends_with("/kvm@1") {
                    "this host cannot give a sandbox KVM (no usable /dev/kvm or nested virtualization off)".to_owned()
                } else if e.ty.ends_with("/ssh-agent@1") {
                    "no host SSH agent socket available (set SSH_AUTH_SOCK)".to_owned()
                } else {
                    e.message.clone()
                };
                return Err(io::Error::other(format!(
                    "kit {}: required capability {} refused: {why}",
                    k.source, e.ty
                )));
            }
        }
        // Fail closed for unsupported sub-options of supported capabilities
        for (_, cap) in d.requests() {
            if cap.ty.ends_with("/port@1")
                && k.granted.contains(&cap.ty)
                && cap
                    .config
                    .as_ref()
                    .and_then(|v| v.get("transport"))
                    .and_then(|v| v.as_str())
                    == Some("udp")
            {
                if cap.is_optional() {
                    k.skipped.push("com.docker.sandbox/port@1 (udp)".to_owned());
                } else {
                    return Err(io::Error::other(format!(
                        "kit {}: required capability com.docker.sandbox/port@1 refused: UDP port forwarding is not supported",
                        k.source
                    )));
                }
            }
            if cap.ty.ends_with("/ssh-agent@1")
                && k.granted.contains(&cap.ty)
                && let Some(cfg) = &cap.config
                && cfg.get("unrestricted").and_then(|b| b.as_bool()) == Some(false)
                && !strings(cfg, "authenticate").is_empty()
            {
                if cap.is_optional() {
                    k.granted.retain(|t| t != &cap.ty);
                    k.skipped
                        .push("com.docker.sandbox/ssh-agent@1 (authenticate)".to_owned());
                } else {
                    return Err(io::Error::other(format!(
                        "kit {}: required capability com.docker.sandbox/ssh-agent@1 refused: host-restricted authenticate filtering is not supported yet",
                        k.source
                    )));
                }
            }
        }
    }
    Ok(())
}

/// A network rule from a kit (`network-policy@1` or `network-policy@2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitNetRule {
    /// Kit handle (`Origin::Kit`).
    pub kit: String,
    /// `"runtime"` or `"install"`.
    pub phase: &'static str,
    /// `true` = allow, `false` = deny.
    pub allow: bool,
    /// Destination pattern (host, wildcard, IP, CIDR, optional `:port`).
    pub dest: String,
    /// Optional HTTP-level constraints (`network-policy@2`).
    pub http: Option<osbx_policy::HttpMatch>,
}

fn strings(v: &ConfigValue, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_sequence())
        .map(|s| {
            s.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn push_v2_entries(
    out: &mut Vec<KitNetRule>,
    kit: &str,
    phase: &'static str,
    allow: bool,
    list: Option<&ConfigValue>,
) {
    let Some(entries) = list.and_then(|v| v.as_sequence()) else {
        return;
    };
    for entry in entries {
        if let Some(d) = entry.as_str() {
            out.push(KitNetRule {
                kit: kit.to_owned(),
                phase,
                allow,
                dest: d.to_owned(),
                http: None,
            });
            continue;
        }
        let hosts = strings(entry, "hosts");
        let methods = strings(entry, "methods");
        let paths = strings(entry, "paths");
        let query: Vec<(String, String)> = entry
            .get("query")
            .and_then(|q| q.as_mapping())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.as_str()?.to_owned(), v.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        for host in hosts {
            if paths.is_empty() {
                let http =
                    (!methods.is_empty() || !query.is_empty()).then(|| osbx_policy::HttpMatch {
                        methods: methods.clone(),
                        path: None,
                        query: query.clone(),
                    });
                out.push(KitNetRule {
                    kit: kit.to_owned(),
                    phase,
                    allow,
                    dest: host,
                    http,
                });
            } else {
                for p in &paths {
                    out.push(KitNetRule {
                        kit: kit.to_owned(),
                        phase,
                        allow,
                        dest: host.clone(),
                        http: Some(osbx_policy::HttpMatch {
                            methods: methods.clone(),
                            path: Some(p.clone()),
                            query: query.clone(),
                        }),
                    });
                }
            }
        }
    }
}

/// Network rules granted by kits (`network-policy@1` and `network-policy@2`), per phase.
pub fn network_rules(kits: &[KitRecord]) -> Vec<KitNetRule> {
    let mut out = Vec::new();
    for k in kits {
        for c in k.granted_requests().iter() {
            let Some(cfg) = &c.config else { continue };
            if c.ty.ends_with("/network-policy@1") {
                for (phase, key) in [("runtime", "runtime"), ("install", "install")] {
                    if let Some(p) = cfg.get(key) {
                        for d in strings(p, "allow") {
                            out.push(KitNetRule {
                                kit: k.handle.clone(),
                                phase,
                                allow: true,
                                dest: d,
                                http: None,
                            });
                        }
                        for d in strings(p, "deny") {
                            out.push(KitNetRule {
                                kit: k.handle.clone(),
                                phase,
                                allow: false,
                                dest: d,
                                http: None,
                            });
                        }
                    }
                }
            } else if c.ty.ends_with("/network-policy@2") {
                for (phase, key) in [("runtime", "runtime"), ("install", "install")] {
                    if let Some(p) = cfg.get(key) {
                        push_v2_entries(&mut out, &k.handle, phase, true, p.get("allow"));
                        push_v2_entries(&mut out, &k.handle, phase, false, p.get("deny"));
                    }
                }
            }
        }
    }
    out
}

/// A credential a kit asks the proxy to present: service, env var for the sentinel, and
/// `(domain, header, format)` rules. Runtime phase only.
#[derive(Debug, Clone, PartialEq)]
pub struct KitCredential {
    /// Service name in the credential store.
    pub service: String,
    /// Whether the capability declaration was marked `optional: true`.
    pub optional: bool,
    /// Env var that carries the sentinel inside the sandbox, if any.
    pub env_name: Option<String>,
    /// Presentation rules.
    pub inject: Vec<(String, String, String)>,
    /// OAuth presentation, if declared.
    pub oauth: Option<KitOAuth>,
}

/// A credential's OAuth presentation (`credential@1` `oauth`).
#[derive(Debug, Clone, PartialEq)]
pub struct KitOAuth {
    /// Token endpoint host.
    pub token_host: String,
    /// Token endpoint path.
    pub token_path: String,
    /// Hosts where the bearer is used (default: the API-key inject domains).
    pub resource_hosts: Vec<String>,
    /// Placeholder access token.
    pub access_sentinel: String,
    /// Placeholder refresh token.
    pub refresh_sentinel: String,
    /// File the agent reads its login from (may start with `~/`).
    pub file_path: Option<String>,
    /// Its structure, with `{{.AccessToken}}`-style placeholders.
    pub file_structure: Option<ConfigValue>,
}

/// Credentials declared by kits.
pub fn credentials(kits: &[KitRecord]) -> Vec<KitCredential> {
    let mut out = Vec::new();
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/credential@1"))
        {
            let Some(cfg) = &c.config else { continue };
            let phases: Vec<String> = match cfg.get("phase") {
                Some(ConfigValue::String(p)) => vec![p.clone()],
                Some(v) => v
                    .as_sequence()
                    .map(|s| {
                        s.iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                None => vec![],
            };
            if !phases.iter().any(|p| p == "runtime") {
                continue;
            }
            let Some(service) = cfg.get("service").and_then(|s| s.as_str()) else {
                continue;
            };
            let empty = ConfigValue::Null;
            let api = cfg.get("apiKey").unwrap_or(&empty);
            let inject: Vec<(String, String, String)> = api
                .get("inject")
                .and_then(|i| i.as_sequence())
                .map(|rules| {
                    rules
                        .iter()
                        .filter_map(|r| {
                            let domain = r.get("domain")?.as_str()?.to_owned();
                            let header = r
                                .get("header")
                                .and_then(|h| h.as_str())
                                .unwrap_or("Authorization")
                                .to_owned();
                            let format = r
                                .get("format")
                                .and_then(|f| f.as_str())
                                .unwrap_or("%s")
                                .to_owned();
                            Some((domain, header, format))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let env_name = api
                .get("name")
                .and_then(|n| n.as_str())
                .filter(|n| !n.is_empty())
                .map(str::to_owned);
            let oauth = cfg.get("oauth").and_then(|o| {
                let ep = o.get("tokenEndpoint")?;
                let s = |v: Option<&ConfigValue>| v.and_then(|x| x.as_str()).map(str::to_owned);
                let resource_hosts = {
                    let declared = strings(o, "resourceHosts");
                    if declared.is_empty() {
                        inject.iter().map(|(d, _, _)| d.clone()).collect()
                    } else {
                        declared
                    }
                };
                Some(KitOAuth {
                    token_host: s(ep.get("host"))?,
                    token_path: s(ep.get("path")).unwrap_or_else(|| "/oauth/token".into()),
                    resource_hosts,
                    access_sentinel: s(o.get("sentinels").and_then(|x| x.get("accessToken")))
                        .unwrap_or_else(|| "proxy-managed-access".into()),
                    refresh_sentinel: s(o.get("sentinels").and_then(|x| x.get("refreshToken")))
                        .unwrap_or_else(|| "proxy-managed-refresh".into()),
                    file_path: s(o.get("credentialFile").and_then(|f| f.get("path"))),
                    file_structure: o
                        .get("credentialFile")
                        .and_then(|f| f.get("structure"))
                        .cloned(),
                })
            });
            if inject.is_empty() && env_name.is_none() && oauth.is_none() {
                continue;
            }
            out.push(KitCredential {
                service: service.to_owned(),
                optional: c.is_optional(),
                env_name,
                inject,
                oauth,
            });
        }
    }
    out
}

/// Verify that every required `credential@1` in `kits` has an approved binding in `bindings`.
/// Optional credentials without bindings are allowed (and withheld at runtime).
pub fn check_credential_bindings(
    kits: &[KitRecord],
    bindings: &osbx_secrets::Bindings,
) -> Result<(), String> {
    use osbx_secrets::Mechanism;
    for kc in credentials(kits) {
        if kc.optional {
            continue;
        }
        let api_ok = !kc.inject.is_empty()
            && kc
                .inject
                .iter()
                .all(|(d, _, _)| bindings.allows(&kc.service, Mechanism::ApiKey, d));
        let oauth_ok = kc.oauth.as_ref().is_some_and(|o| {
            bindings.allows(&kc.service, Mechanism::Oauth, &o.token_host)
                && o.resource_hosts
                    .iter()
                    .all(|h| bindings.allows(&kc.service, Mechanism::Oauth, h))
        });
        if kc.inject.is_empty() && kc.oauth.is_none() {
            continue;
        }
        if !api_ok && !oauth_ok {
            let mut domains: Vec<&str> = kc.inject.iter().map(|(d, _, _)| d.as_str()).collect();
            if let Some(o) = &kc.oauth {
                domains.push(&o.token_host);
                for h in &o.resource_hosts {
                    domains.push(h);
                }
            }
            domains.sort_unstable();
            domains.dedup();
            return Err(format!(
                "required credential {:?} has no approved binding for [{}] (approve with: osbx secret bind {} {})",
                kc.service,
                domains.join(", "),
                kc.service,
                domains
                    .iter()
                    .map(|d| format!("--domain {d}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
    }
    Ok(())
}

/// Host-mount paths requested by kits: (kit handle, absolute guest path).
pub fn host_mounts(kits: &[KitRecord]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/host-mount@1"))
        {
            if let Some(p) = c
                .config
                .as_ref()
                .and_then(|v| v.get("path"))
                .and_then(|p| p.as_str())
            {
                out.push((k.handle.clone(), p.to_owned()));
            }
        }
    }
    out
}

/// Persistent sandbox-private volume requested by a kit (`volume@1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitVolume {
    /// Kit handle.
    pub kit: String,
    /// Absolute canonical path inside the sandbox.
    pub path: String,
    /// Optional octal mode (e.g. `"0700"`).
    pub mode: Option<String>,
}

/// Persistent volumes requested by kits (`volume@1`).
pub fn volumes(kits: &[KitRecord]) -> Vec<KitVolume> {
    let mut out = Vec::new();
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/volume@1"))
        {
            let Some(cfg) = &c.config else { continue };
            let Some(path) = cfg.get("path").and_then(|p| p.as_str()) else {
                continue;
            };
            out.push(KitVolume {
                kit: k.handle.clone(),
                path: path.to_owned(),
                mode: cfg.get("mode").and_then(|m| m.as_str()).map(str::to_owned),
            });
        }
    }
    out
}

/// Inbound guest port requested by a kit (`port@1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitPort {
    /// Optional informational label.
    pub name: Option<String>,
    /// Guest port number (`1..=65535`).
    pub container: u16,
    /// Transport (`"tcp"` or `"udp"`).
    pub transport: String,
}

/// Inbound TCP ports requested by kits (`port@1`).
pub fn ports(kits: &[KitRecord]) -> Vec<KitPort> {
    let mut out = Vec::new();
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/port@1"))
        {
            let Some(cfg) = &c.config else { continue };
            let Some(port) = cfg
                .get("container")
                .and_then(|p| p.as_u64())
                .and_then(|p| u16::try_from(p).ok())
                .filter(|&p| p > 0)
            else {
                continue;
            };
            let transport = cfg
                .get("transport")
                .and_then(|t| t.as_str())
                .unwrap_or("tcp")
                .to_owned();
            if transport != "tcp" {
                continue;
            }
            out.push(KitPort {
                name: cfg.get("name").and_then(|n| n.as_str()).map(str::to_owned),
                container: port,
                transport,
            });
        }
    }
    out
}

/// Combined resource floor requested by granted `resources@1` capabilities (maximum across kits).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KitResources {
    /// Minimum vCPUs (rounded up from fractional cores, clamped to `1..=32`).
    pub cpus: Option<u8>,
    /// Minimum RAM in MiB.
    pub mem_mib: Option<usize>,
}

fn parse_mem_mib(s: &str) -> Option<usize> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult_bytes): (&str, u64) = if let Some(n) = t
        .strip_suffix("gib")
        .or_else(|| t.strip_suffix("gb"))
        .or_else(|| t.strip_suffix('g'))
    {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = t
        .strip_suffix("mib")
        .or_else(|| t.strip_suffix("mb"))
        .or_else(|| t.strip_suffix('m'))
    {
        (n, 1024 * 1024)
    } else if let Some(n) = t
        .strip_suffix("kib")
        .or_else(|| t.strip_suffix("kb"))
        .or_else(|| t.strip_suffix('k'))
    {
        (n, 1024)
    } else if let Some(n) = t.strip_suffix('b') {
        (n, 1)
    } else {
        (t.as_str(), 1024 * 1024)
    };
    let n = num.parse::<u64>().ok()?;
    let bytes = n.checked_mul(mult_bytes)?;
    usize::try_from(bytes.div_ceil(1024 * 1024)).ok()
}

/// Resource requirements across all kits (`resources@1`, reconciled by maximum).
pub fn resources(kits: &[KitRecord]) -> KitResources {
    let mut out = KitResources::default();
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/resources@1"))
        {
            let Some(cfg) = &c.config else { continue };
            if let Some(cpu) = cfg.get("cpu").and_then(|v| v.as_f64())
                && cpu.is_finite()
                && cpu > 0.0
            {
                let vcpus = (cpu.ceil() as u64).clamp(1, 32) as u8;
                out.cpus = Some(out.cpus.map_or(vcpus, |prev| prev.max(vcpus)));
            }
            if let Some(mem) = cfg
                .get("memory")
                .and_then(|v| v.as_str())
                .and_then(parse_mem_mib)
                .filter(|&m| m > 0)
            {
                out.mem_mib = Some(out.mem_mib.map_or(mem, |prev| prev.max(mem)));
            }
        }
    }
    out
}

/// Does any kit hold a `dockerd@1` grant (Docker Engine started by the runtime)?
pub fn wants_docker(kits: &[KitRecord]) -> bool {
    kits.iter()
        .any(|k| k.granted.iter().any(|t| t.ends_with("/dockerd@1")))
}

/// Does the workload target the sandbox agent platform (`sbx@1`)?
pub fn sbx_platform(kits: &[KitRecord]) -> bool {
    kits.iter()
        .any(|k| k.granted.iter().any(|t| t.ends_with("/sbx@1")))
}

/// Does any kit hold a `kvm@1` grant?
pub fn wants_kvm(kits: &[KitRecord]) -> bool {
    kits.iter()
        .any(|k| k.granted.iter().any(|t| t.ends_with("/kvm@1")))
}

/// Combined SSH agent forwarding request across granted `ssh-agent@1` capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitSshAgent {
    /// Expose `SSH_AUTH_SOCK` during install hooks.
    pub install: bool,
    /// Expose `SSH_AUTH_SOCK` at runtime.
    pub runtime: bool,
    /// Forward unrestricted (else restricted to `sign` namespaces via `SSHSIG`).
    pub unrestricted: bool,
    /// Allowed `SSHSIG` signing namespaces when `unrestricted == false`.
    pub sign: Vec<String>,
}

/// Combined `ssh-agent@1` request across kits (`None` if no kit was granted `ssh-agent@1`).
pub fn ssh_agent(kits: &[KitRecord]) -> Option<KitSshAgent> {
    let mut found = false;
    let mut install = false;
    let mut runtime = false;
    let mut unrestricted = false;
    let mut sign = BTreeSet::new();
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/ssh-agent@1"))
        {
            found = true;
            let cfg = c.config.as_ref();
            let phases: Vec<String> = match cfg.and_then(|v| v.get("phase")) {
                Some(ConfigValue::String(p)) => vec![p.clone()],
                Some(v) => v
                    .as_sequence()
                    .map(|s| {
                        s.iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                None => vec!["runtime".into()],
            };
            if phases.iter().any(|p| p == "install") {
                install = true;
            }
            if phases.iter().any(|p| p == "runtime") {
                runtime = true;
            }
            let unres = cfg
                .and_then(|v| v.get("unrestricted"))
                .and_then(|b| b.as_bool())
                .unwrap_or(true);
            if unres {
                unrestricted = true;
            } else if let Some(cfg) = cfg {
                for ns in strings(cfg, "sign") {
                    sign.insert(ns);
                }
            }
        }
    }
    found.then(|| KitSshAgent {
        install,
        runtime,
        unrestricted,
        sign: sign.into_iter().collect(),
    })
}

/// One hook to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    /// argv (a string command becomes `sh -c <string>`).
    pub argv: Vec<String>,
    /// User, if given.
    pub user: Option<String>,
    /// Env names the hook may see.
    pub env: Vec<String>,
    /// Detach (startup only).
    pub background: bool,
}

/// A file a kit writes at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitFile {
    /// Absolute path.
    pub path: String,
    /// Body.
    pub content: String,
    /// Octal mode.
    pub mode: Option<String>,
    /// Replace an existing file.
    pub overwrite: bool,
}

/// Lifecycle hooks and files of all kits: (install, startup, files), in kit order.
pub fn lifecycle(kits: &[KitRecord]) -> (Vec<Hook>, Vec<Hook>, Vec<KitFile>) {
    let (mut install, mut startup, mut files) = (Vec::new(), Vec::new(), Vec::new());
    let hooks = |v: Option<&ConfigValue>| -> Vec<Hook> {
        v.and_then(|x| x.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|h| {
                        let argv = match h.get("command")? {
                            ConfigValue::String(c) => {
                                vec!["/bin/sh".to_owned(), "-c".to_owned(), c.clone()]
                            }
                            v => v
                                .as_sequence()?
                                .iter()
                                .filter_map(|a| a.as_str().map(str::to_owned))
                                .collect(),
                        };
                        Some(Hook {
                            argv,
                            user: h.get("user").and_then(|u| {
                                u.as_str()
                                    .map(str::to_owned)
                                    .or_else(|| u.as_u64().map(|n| n.to_string()))
                            }),
                            env: strings(h, "env"),
                            background: h
                                .get("background")
                                .and_then(|b| b.as_bool())
                                .unwrap_or(false),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/lifecycle@1"))
        {
            let Some(cfg) = &c.config else { continue };
            install.extend(hooks(cfg.get("install")));
            startup.extend(hooks(cfg.get("startup")));
            for f in cfg
                .get("files")
                .and_then(|x| x.as_sequence())
                .into_iter()
                .flatten()
            {
                let (Some(path), content) = (
                    f.get("path").and_then(|p| p.as_str()),
                    f.get("content").and_then(|c| c.as_str()).unwrap_or(""),
                ) else {
                    continue;
                };
                files.push(KitFile {
                    path: path.to_owned(),
                    content: content.to_owned(),
                    mode: f.get("mode").and_then(|m| m.as_str()).map(str::to_owned),
                    overwrite: f.get("overwrite").and_then(|o| o.as_bool()).unwrap_or(true),
                });
            }
        }
    }
    (install, startup, files)
}

/// The `interactive` argv tail of the workload kit's lifecycle, if declared.
pub fn interactive_tail(kits: &[KitRecord]) -> Option<Vec<String>> {
    kits.iter().filter(|k| k.kind == "workload").find_map(|k| {
        k.granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/lifecycle@1"))
            .find_map(|c| {
                c.config
                    .as_ref()?
                    .get("interactive")?
                    .as_sequence()
                    .map(|s| {
                        s.iter()
                            .filter_map(|a| a.as_str().map(str::to_owned))
                            .collect()
                    })
            })
    })
}

/// Every capability item, for display.
pub fn describe(k: &KitRecord) -> String {
    let skipped = if k.skipped.is_empty() {
        String::new()
    } else {
        format!("; skipped {}", k.skipped.join(", "))
    };
    format!(
        "{} ({}): grants {}{skipped}",
        k.handle,
        k.kind,
        if k.granted.is_empty() {
            "nothing".into()
        } else {
            k.granted.join(", ")
        }
    )
}

/// Render a credential file structure: placeholders become the sentinels and the stored token
/// metadata; a leaf using `{{.PrimaryApiKey}}` is dropped (no key is captured).
pub fn render_credential_file(
    structure: &ConfigValue,
    o: &KitOAuth,
    expires_at_ms: Option<u64>,
    scopes: &[String],
) -> Option<serde_json::Value> {
    use serde_json::Value as J;
    fn conv(v: &ConfigValue, o: &KitOAuth, exp: Option<u64>, scopes: &[String]) -> Option<J> {
        Some(match v {
            ConfigValue::Mapping(m) => {
                let mut out = serde_json::Map::new();
                for (k, x) in m {
                    if let (Some(k), Some(x)) = (k.as_str(), conv(x, o, exp, scopes)) {
                        out.insert(k.to_owned(), x);
                    }
                }
                J::Object(out)
            }
            ConfigValue::Sequence(s) => {
                J::Array(s.iter().filter_map(|x| conv(x, o, exp, scopes)).collect())
            }
            ConfigValue::String(t) => {
                let norm: String = t.chars().filter(|c| !c.is_whitespace()).collect();
                match norm.as_str() {
                    "{{.AccessToken}}" => J::String(o.access_sentinel.clone()),
                    "{{.RefreshToken}}" => J::String(o.refresh_sentinel.clone()),
                    "{{.ExpiresAt}}" => J::from(exp.unwrap_or(0)),
                    "{{.Scopes}}" => {
                        J::Array(scopes.iter().map(|s| J::String(s.clone())).collect())
                    }
                    _ if norm.contains("{{.PrimaryApiKey}}") => return None,
                    _ => J::String(
                        t.replace("{{.AccessToken}}", &o.access_sentinel)
                            .replace("{{.RefreshToken}}", &o.refresh_sentinel),
                    ),
                }
            }
            ConfigValue::Bool(b) => J::Bool(*b),
            ConfigValue::Number(n) => serde_json::to_value(n).ok()?,
            _ => J::Null,
        })
    }
    conv(structure, o, expires_at_ms, scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kit(handle: &str, yaml: &str) -> KitRecord {
        KitRecord {
            source: format!("./{handle}"),
            handle: handle.into(),
            kind: "mixin".into(),
            descriptor: format!("schemaVersion: \"3\"\nkind: mixin\n{yaml}"),
            image: None,
            granted: vec![],
            skipped: vec![],
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn plan_grants_selects_and_extracts() {
        let mut kits = vec![kit(
            "tools",
            "capabilities:\n  - type: com.docker.sandbox/network-policy@1\n    config:\n      runtime: {allow: [api.example.com], deny: [bad.example.com]}\n      install: {allow: [registry.npmjs.org]}\n  - type: com.docker.sandbox/credential@1\n    config:\n      service: example\n      phase: runtime\n      apiKey: {name: EX_TOKEN, inject: [{domain: api.example.com, header: Authorization, format: \"Bearer %s\"}]}\n  - type: com.docker.sandbox/lifecycle@1\n    config:\n      install: [{command: \"echo hi\", user: \"0\"}]\n      startup: [{command: [true], background: true}]\n      files: [{path: /etc/x, content: hello, overwrite: false}]\n  - type: com.docker.sandbox/agent-context@2\n    optional: true\n    config: {content: hi}\n",
        )];
        plan(&mut kits, true, true).unwrap();
        assert_eq!(kits[0].granted.len(), 3);
        assert_eq!(kits[0].skipped, ["com.docker.sandbox/agent-context@2"]);
        let rules = network_rules(&kits);
        assert!(rules.contains(&KitNetRule {
            kit: "tools".into(),
            phase: "runtime",
            allow: true,
            dest: "api.example.com".into(),
            http: None,
        }));
        assert!(rules.contains(&KitNetRule {
            kit: "tools".into(),
            phase: "runtime",
            allow: false,
            dest: "bad.example.com".into(),
            http: None,
        }));
        assert!(rules.contains(&KitNetRule {
            kit: "tools".into(),
            phase: "install",
            allow: true,
            dest: "registry.npmjs.org".into(),
            http: None,
        }));
        let creds = credentials(&kits);
        assert_eq!(creds[0].service, "example");
        assert_eq!(creds[0].env_name.as_deref(), Some("EX_TOKEN"));
        assert_eq!(
            creds[0].inject[0],
            (
                "api.example.com".into(),
                "Authorization".into(),
                "Bearer %s".into()
            )
        );
        let (install, startup, files) = lifecycle(&kits);
        assert_eq!(install[0].argv, ["/bin/sh", "-c", "echo hi"]);
        assert_eq!(install[0].user.as_deref(), Some("0"));
        assert!(startup[0].background);
        assert_eq!(files[0].path, "/etc/x");
        assert!(!files[0].overwrite);
    }

    #[test]
    fn required_unsupported_or_unavailable_capabilities_refuse() {
        let mut kits = vec![kit(
            "k",
            "capabilities:\n  - type: com.docker.sandbox/kvm@1\n",
        )];
        let e = plan(&mut kits.clone(), false, true)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("kvm@1") && e.contains("cannot give a sandbox KVM"),
            "{e}"
        );
        plan(&mut kits, true, true).unwrap();
        assert!(wants_kvm(&kits));
        let mut unknown = vec![kit("u", "capabilities:\n  - type: com.example/thing@1\n")];
        assert!(
            plan(&mut unknown, true, true)
                .unwrap_err()
                .to_string()
                .contains("com.example/thing@1")
        );
        // ssh-agent@1 fails cleanly when host agent is absent or authenticate filtering is required
        let mut sa = vec![kit(
            "sa",
            "capabilities:\n  - type: com.docker.sandbox/ssh-agent@1\n    config: {phase: [install, runtime], unrestricted: false, sign: [git]}\n",
        )];
        assert!(
            plan(&mut sa.clone(), true, false)
                .unwrap_err()
                .to_string()
                .contains("SSH_AUTH_SOCK")
        );
        plan(&mut sa, true, true).unwrap();
        let req = ssh_agent(&sa).unwrap();
        assert!(req.install && req.runtime && !req.unrestricted && req.sign == ["git"]);
        let mut sa_auth = vec![kit(
            "saa",
            "capabilities:\n  - type: com.docker.sandbox/ssh-agent@1\n    config: {unrestricted: false, authenticate: [git@github.com]}\n",
        )];
        assert!(
            plan(&mut sa_auth, true, true)
                .unwrap_err()
                .to_string()
                .contains("authenticate")
        );
    }

    #[test]
    fn composition_rules_are_enforced() {
        // a mixin that needs the claude workload cannot run on a plain base image
        let mut kits = vec![kit("needs", "requires: [claude]\n")];
        assert!(
            plan(&mut kits, true, true)
                .unwrap_err()
                .to_string()
                .contains("claude")
        );
    }

    #[test]
    fn credential_bindings_enforce_required_and_allow_optional() {
        let mut req_kit = vec![kit(
            "gh",
            "capabilities:\n  - type: com.docker.sandbox/network-policy@1\n    config: {runtime: {allow: [api.github.com]}}\n  - type: com.docker.sandbox/credential@1\n    config:\n      service: github\n      phase: runtime\n      apiKey: {name: GH_TOKEN, inject: [{domain: api.github.com, header: Authorization, format: \"Bearer %s\"}]}\n",
        )];
        plan(&mut req_kit, true, true).unwrap();
        let mut b = osbx_secrets::Bindings::default();
        assert!(
            check_credential_bindings(&req_kit, &b)
                .unwrap_err()
                .contains("osbx secret bind github")
        );
        b.approve(
            "github",
            osbx_secrets::Mechanism::ApiKey,
            &["api.github.com"],
        );
        check_credential_bindings(&req_kit, &b).unwrap();

        let mut opt_kit = vec![kit(
            "opt",
            "capabilities:\n  - type: com.docker.sandbox/credential@1\n    optional: true\n    config:\n      service: github\n      phase: runtime\n      apiKey: {name: GH_TOKEN, inject: [{domain: api.github.com}]}\n",
        )];
        plan(&mut opt_kit, true, true).unwrap();
        check_credential_bindings(&opt_kit, &osbx_secrets::Bindings::default()).unwrap();
    }

    #[test]
    fn credential_file_renders_placeholders_only() {
        let structure: ConfigValue = serde_yaml_ng::from_str(
            "claudeAiOauth:\n  accessToken: '{{.AccessToken}}'\n  refreshToken: '{{.RefreshToken}}'\n  expiresAt: '{{.ExpiresAt}}'\n  scopes: '{{.Scopes}}'\nprimaryApiKey: '{{.PrimaryApiKey}}'\n",
        )
        .unwrap();
        let o = KitOAuth {
            token_host: "platform.claude.com".into(),
            token_path: "/v1/oauth/token".into(),
            resource_hosts: vec!["api.anthropic.com".into()],
            access_sentinel: "sk-ant-oat01-proxy-managed".into(),
            refresh_sentinel: "sk-ant-ort01-proxy-managed".into(),
            file_path: Some("~/.claude/.credentials.json".into()),
            file_structure: None,
        };
        let v = render_credential_file(
            &structure,
            &o,
            Some(1_800_000_000_000),
            &["user:inference".into()],
        )
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"claudeAiOauth": {"accessToken": "sk-ant-oat01-proxy-managed", "refreshToken": "sk-ant-ort01-proxy-managed", "expiresAt": 1_800_000_000_000u64, "scopes": ["user:inference"]}})
        );
    }

    #[test]
    fn network_policy_v2_extracts_http_rules() {
        let mut kits = vec![kit(
            "gh",
            "capabilities:\n  - type: com.docker.sandbox/network-policy@2\n    config:\n      runtime:\n        allow:\n          - github.com\n          - hosts: [api.github.com]\n            methods: [GET, POST]\n            paths: [\"/repos/**\", \"/user\"]\n        deny:\n          - hosts: [api.github.com]\n            methods: [DELETE]\n            paths: [\"/repos/**\"]\n",
        )];
        plan(&mut kits, true, true).unwrap();
        let rules = network_rules(&kits);
        assert_eq!(rules.len(), 4);
        assert!(
            rules
                .iter()
                .any(|r| r.dest == "github.com" && r.allow && r.http.is_none())
        );
        assert!(rules.iter().any(|r| r.dest == "api.github.com"
            && r.allow
            && r.http.as_ref().is_some_and(
                |h| h.methods == ["GET", "POST"] && h.path.as_deref() == Some("/repos/**")
            )));
        assert!(rules.iter().any(|r| r.dest == "api.github.com"
            && !r.allow
            && r.http.as_ref().is_some_and(
                |h| h.methods == ["DELETE"] && h.path.as_deref() == Some("/repos/**")
            )));
    }

    #[test]
    fn kit_args_expand_deliver_env_and_revalidate() {
        let dir = std::env::temp_dir().join(format!("osbx-kit-arg-{}", std::process::id()));
        let kdir = dir.join("mykit");
        std::fs::create_dir_all(&kdir).unwrap();
        std::fs::write(
            kdir.join("mykit.yaml"),
            "schemaVersion: \"3\"\nkind: mixin\nargs:\n  mount_path:\n    required: true\n  region:\n    default: eu\n    env: MY_REGION\ncapabilities:\n  - type: com.docker.sandbox/host-mount@1\n    config:\n      path: \"${{ kit.args.mount_path }}\"\n",
        )
        .unwrap();
        // missing required arg fails
        assert!(load(&kdir.to_string_lossy(), &SuppliedKitArgs::default()).is_err());
        // scoped + unscoped arg works and delivers Arg.env
        let supplied =
            SuppliedKitArgs::parse(&["mykit.mount_path=/data/custom".into(), "region=us".into()])
                .unwrap();
        let (rec, used) = load(&kdir.to_string_lossy(), &supplied).unwrap();
        assert!(used.contains("region"));
        assert_eq!(rec.env.get("MY_REGION").map(String::as_str), Some("us"));
        let mut recs = vec![rec];
        plan(&mut recs, true, true).unwrap();
        assert_eq!(
            host_mounts(&recs),
            vec![("mykit".into(), "/data/custom".into())]
        );
        // invalid value after expansion is caught by re-validation
        let bad = SuppliedKitArgs::parse(&["mykit.mount_path=relative/bad".into()]).unwrap();
        assert!(load(&kdir.to_string_lossy(), &bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn port_volume_and_resources_extraction() {
        let mut kits = vec![
            kit(
                "a",
                "capabilities:\n  - type: com.docker.sandbox/port@1\n    config: {name: web, container: 3000}\n  - type: com.docker.sandbox/volume@1\n    config: {path: /var/cache/tool, mode: \"0700\"}\n  - type: com.docker.sandbox/resources@1\n    config: {cpu: 2.5, memory: 4gib}\n",
            ),
            kit(
                "b",
                "capabilities:\n  - type: com.docker.sandbox/resources@1\n    config: {cpu: 4, memory: 2048m}\n",
            ),
        ];
        plan(&mut kits, true, true).unwrap();
        let ps = ports(&kits);
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].container, 3000);
        assert_eq!(ps[0].name.as_deref(), Some("web"));
        let vs = volumes(&kits);
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].path, "/var/cache/tool");
        assert_eq!(vs[0].mode.as_deref(), Some("0700"));
        let res = resources(&kits);
        assert_eq!(res.cpus, Some(4));
        assert_eq!(res.mem_mib, Some(4096));
    }
}
