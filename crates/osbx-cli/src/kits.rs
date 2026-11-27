//! Kits at runtime: load, validate, resolve and select at create; apply at start.

use osbx_kit::{Capability, ConfigValue, Descriptor, Kind, KitInput};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

/// Capability types this runtime implements.
pub const SUPPORTED: &[&str] = &[
    "com.docker.sandbox/network-policy@1",
    "com.docker.sandbox/credential@1",
    "com.docker.sandbox/lifecycle@1",
    "com.docker.sandbox/host-mount@1",
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

/// Load a kit's descriptor: a local directory (`<dir>/<dir>.yaml`) or an image reference
/// (descriptor staged at `/usr/share/sandbox/kit/<stem>/kit.yaml`).
pub fn load(source: &str) -> io::Result<KitRecord> {
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
    finish_load(source, handle, text, image)
}

/// The workload kit an agent image carries, if it is one (e.g. `docker.io/sbx/claude`).
pub fn workload_for_image(image: &str) -> io::Result<Option<KitRecord>> {
    match read_staged_descriptor(image)? {
        Some(text) => {
            let k = finish_load(image, handle_of(image), text, Some(image.to_owned()))?;
            Ok((k.kind == "workload").then_some(k))
        }
        None => Ok(None),
    }
}

fn finish_load(
    source: &str,
    handle: String,
    text: String,
    image: Option<String>,
) -> io::Result<KitRecord> {
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
    // create-phase expansion: kit args at their defaults, kit.env from the image's environment
    let env = match &image {
        Some(img) => image_env(img).unwrap_or_default(),
        None => std::collections::BTreeMap::new(),
    };
    // build-phase args were baked in when the kit was published; only create-phase args resolve here
    let create_args: std::collections::BTreeMap<String, osbx_kit::Arg> = d
        .args
        .iter()
        .filter(|(_, a)| a.build_arg.is_none() && a.build_secret.is_none())
        .map(|(k, a)| (k.clone(), a.clone()))
        .collect();
    let args = osbx_kit::expand::resolve_args(&create_args, &std::collections::BTreeMap::new())
        .map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    let doc: ConfigValue = serde_yaml_ng::from_str(&text)
        .map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    let expanded = osbx_kit::expand::expand(&doc, &args, &env)
        .map_err(|e| io::Error::other(format!("kit {source}: {e}")))?;
    let text = serde_yaml_ng::to_string(&expanded).map_err(io::Error::other)?;
    Ok(KitRecord {
        source: source.to_owned(),
        handle,
        kind: kind.into(),
        descriptor: text,
        image,
        granted: vec![],
        skipped: vec![],
    })
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

/// Resolve the composition and select capabilities. `base_provides` stands in for a base image
/// that is not itself a kit. Fills `granted`/`skipped`; errors name what cannot be satisfied.
pub fn plan(kits: &mut [KitRecord], kvm_available: bool) -> io::Result<()> {
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
                } else {
                    e.message.clone()
                };
                return Err(io::Error::other(format!(
                    "kit {}: required capability {} refused: {why}",
                    k.source, e.ty
                )));
            }
        }
    }
    Ok(())
}

/// A network rule from a kit: (allow?, destination, phase).
pub type KitRule = (bool, String, &'static str);

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

/// Network rules granted by kits, per phase.
pub fn network_rules(kits: &[KitRecord]) -> Vec<(String, KitRule)> {
    let mut out = Vec::new();
    for k in kits {
        for c in k
            .granted_requests()
            .iter()
            .filter(|c| c.ty.ends_with("/network-policy@1"))
        {
            let Some(cfg) = &c.config else { continue };
            for (phase, key) in [("runtime", "runtime"), ("install", "install")] {
                if let Some(p) = cfg.get(key) {
                    for d in strings(p, "allow") {
                        out.push((k.handle.clone(), (true, d, phase)));
                    }
                    for d in strings(p, "deny") {
                        out.push((k.handle.clone(), (false, d, phase)));
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
                env_name,
                inject,
                oauth,
            });
        }
    }
    out
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
        }
    }

    #[test]
    fn plan_grants_selects_and_extracts() {
        let mut kits = vec![kit(
            "tools",
            "capabilities:\n  - type: com.docker.sandbox/network-policy@1\n    config:\n      runtime: {allow: [api.example.com], deny: [bad.example.com]}\n      install: {allow: [registry.npmjs.org]}\n  - type: com.docker.sandbox/credential@1\n    config:\n      service: example\n      phase: runtime\n      apiKey: {name: EX_TOKEN, inject: [{domain: api.example.com, header: Authorization, format: \"Bearer %s\"}]}\n  - type: com.docker.sandbox/lifecycle@1\n    config:\n      install: [{command: \"echo hi\", user: \"0\"}]\n      startup: [{command: [true], background: true}]\n      files: [{path: /etc/x, content: hello, overwrite: false}]\n  - type: com.docker.sandbox/agent-context@2\n    optional: true\n    config: {content: hi}\n",
        )];
        plan(&mut kits, true).unwrap();
        assert_eq!(kits[0].granted.len(), 3);
        assert_eq!(kits[0].skipped, ["com.docker.sandbox/agent-context@2"]);
        let rules = network_rules(&kits);
        assert!(rules.contains(&("tools".into(), (true, "api.example.com".into(), "runtime"))));
        assert!(rules.contains(&("tools".into(), (false, "bad.example.com".into(), "runtime"))));
        assert!(rules.contains(&(
            "tools".into(),
            (true, "registry.npmjs.org".into(), "install")
        )));
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
        let e = plan(&mut kits.clone(), false).unwrap_err().to_string();
        assert!(
            e.contains("kvm@1") && e.contains("cannot give a sandbox KVM"),
            "{e}"
        );
        plan(&mut kits, true).unwrap();
        assert!(wants_kvm(&kits));
        let mut unknown = vec![kit("u", "capabilities:\n  - type: com.example/thing@1\n")];
        assert!(
            plan(&mut unknown, true)
                .unwrap_err()
                .to_string()
                .contains("com.example/thing@1")
        );
    }

    #[test]
    fn composition_rules_are_enforced() {
        // a mixin that needs the claude workload cannot run on a plain base image
        let mut kits = vec![kit("needs", "requires: [claude]\n")];
        assert!(
            plan(&mut kits, true)
                .unwrap_err()
                .to_string()
                .contains("claude")
        );
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
}
