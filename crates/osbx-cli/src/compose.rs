//! Shared `osbx compose` loading, default file discovery, and offline `check`/`config`/`plan`
//! helpers (platform-independent: works on Linux, Windows, and macOS).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Default filenames checked in the current directory when `-f` is omitted.
pub const DEFAULT_FILES: &[&str] = &["osbx-compose.yml", "osbx-compose.yaml"];
const OVERRIDE_FILES: &[&str] = &["osbx-compose.override.yml", "osbx-compose.override.yaml"];
const USER_BASE_FILES: &[&str] = &[".osbx-compose.yml", ".osbx-compose.yaml"];

/// Loaded compose project together with its primary file directory.
pub struct LoadedCompose {
    /// Compiled canonical internal specification IR.
    pub project: osbx_spec::ProjectSpec,
    /// Canonicalized directory of the primary compose file.
    pub dir: PathBuf,
}

/// Discover the ordered list of compose files (lowest priority first):
/// optional `~/.osbx-compose.yml|yaml` (unless `no_user_base`), then explicit `-f` files
/// (or auto-discovered `osbx-compose.yml|yaml` + optional `osbx-compose.override.yml|yaml`).
pub fn resolve_files(explicit: &[PathBuf], no_user_base: bool) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    if !no_user_base
        && let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
    {
        for name in USER_BASE_FILES {
            let p = Path::new(&home).join(name);
            if p.is_file() {
                paths.push(p);
                break;
            }
        }
    }
    if explicit.is_empty() {
        let primary = DEFAULT_FILES
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or_else(|| {
                "no osbx-compose.yml or osbx-compose.yaml found in current directory (pass -f FILE)"
                    .to_owned()
            })?;
        paths.push(primary);
        for name in OVERRIDE_FILES {
            let p = PathBuf::from(name);
            if p.is_file() {
                paths.push(p);
                break;
            }
        }
    } else {
        paths.extend(explicit.iter().cloned());
    }
    Ok(paths)
}

/// Parse `--arg name=value` flags into a map.
pub fn parse_kv_args(raw: &[String], flag: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for item in raw {
        let (k, v) = item
            .split_once('=')
            .ok_or_else(|| format!("{flag} {item:?}: expected name=value"))?;
        out.insert(k.to_owned(), v.to_owned());
    }
    Ok(out)
}

/// Load and compile compose files into the canonical [`osbx_spec::ProjectSpec`].
pub fn load(
    explicit_files: &[PathBuf],
    cli_args: &[String],
    no_user_base: bool,
) -> Result<LoadedCompose, String> {
    let paths = resolve_files(explicit_files, no_user_base)?;
    let primary = paths
        .last()
        .ok_or_else(|| "no compose files to load".to_owned())?;
    let parent = primary
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = crate::state::plain_path(
        &std::fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))?,
    );
    let dir_str = dir.to_string_lossy().into_owned();
    let args = parse_kv_args(cli_args, "--arg")?;
    let vars: BTreeMap<String, String> = std::env::vars().collect();
    let ctx = osbx_compose::Context {
        project_dir: dir_str.clone(),
        file_dir: dir_str,
        args,
        vars,
        env_files: BTreeMap::new(),
    };
    let refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
    let project = osbx_compose::compile_files(&refs, &ctx).map_err(|e| e.to_string())?;
    Ok(LoadedCompose { project, dir })
}

/// Select the target sandboxes from `project`, respecting `--profile` and optional explicit names.
pub fn select_sandboxes<'a>(
    project: &'a osbx_spec::ProjectSpec,
    profiles: &[String],
    requested: &[String],
) -> Result<Vec<(&'a str, &'a osbx_spec::SandboxSpec)>, String> {
    if requested.is_empty() {
        let active = project.active_sandboxes(profiles);
        if active.is_empty() {
            return Err(
                "no active sandboxes (all declared sandboxes require --profile)".to_owned(),
            );
        }
        return Ok(active);
    }
    let mut out = Vec::with_capacity(requested.len());
    for name in requested {
        let Some((k, sb)) = project.sandboxes.get_key_value(name) else {
            let known: Vec<&str> = project.sandboxes.keys().map(String::as_str).collect();
            return Err(format!(
                "unknown sandbox {name:?} (declared: {})",
                known.join(", ")
            ));
        };
        out.push((k.as_str(), sb));
    }
    Ok(out)
}

/// Resolve the runtime sandbox name for a compose sandbox entry.
pub fn runtime_name(project_name: Option<&str>, key: &str, spec: &osbx_spec::SandboxSpec) -> String {
    if let Some(explicit) = &spec.name {
        return explicit.clone();
    }
    match project_name {
        Some(p) if !p.is_empty() && p != key => format!("{p}-{key}"),
        _ => key.to_owned(),
    }
}

/// Render a human-readable plan/check summary for a compiled [`osbx_spec::ProjectSpec`].
pub fn format_plan(project: &osbx_spec::ProjectSpec, profiles: &[String]) -> String {
    let mut out = String::new();
    if let Some(name) = &project.name {
        out += &format!("project: {name}\n");
    }
    if !project.volumes.is_empty() {
        let names: Vec<&str> = project.volumes.keys().map(String::as_str).collect();
        out += &format!("volumes: {}\n", names.join(", "));
    }
    let active: std::collections::BTreeSet<&str> = project
        .active_sandboxes(profiles)
        .into_iter()
        .map(|(k, _)| k)
        .collect();

    for (key, sb) in &project.sandboxes {
        let status = if active.contains(key.as_str()) {
            "active"
        } else {
            "inactive (profile)"
        };
        let rname = runtime_name(project.name.as_deref(), key, sb);
        out += &format!(
            "\nsandbox {key} -> {rname} [{status}]\n  agent: {}\n",
            sb.agent
        );
        if let Some(img) = &sb.image {
            out += &format!("  image: {img}\n");
        }
        if let Some(tpl) = &sb.template {
            out += &format!("  template: {tpl}\n");
        }
        if let Some(wd) = &sb.workdir {
            out += &format!("  workspace (cwd): {wd}\n");
        }
        if let Some(ws) = &sb.workspace {
            out += &format!("  workspace: {} ({:?})\n", ws.host_path, ws.mode);
        }
        if sb.resources.cpus.is_some()
            || sb.resources.memory_mib.is_some()
            || sb.resources.disks.root_mib.is_some()
        {
            out += &format!(
                "  resources: cpus={} mem={}MiB root={}MiB\n",
                sb.resources
                    .cpus
                    .map_or("default".into(), |c| c.to_string()),
                sb.resources
                    .memory_mib
                    .map_or("default".into(), |m| m.to_string()),
                sb.resources
                    .disks
                    .root_mib
                    .map_or("default".into(), |d| d.to_string()),
            );
        }
        for m in &sb.mounts {
            let ro = if m.read_only { " (ro)" } else { "" };
            out += &format!("  mount [{:?}]: {} -> {}{ro}\n", m.kind, m.source, m.target);
        }
        for k in &sb.kits {
            out += &format!("  kit: {} -> handle {:?} ({:?})\n", k.source, k.handle, k.kind);
            for (guest, host) in &k.mounts {
                out += &format!("    kit mount: {host} -> {guest}\n");
            }
        }
        for p in &sb.ports {
            out += &format!(
                "  port: {}:{} -> {} ({:?})\n",
                p.host_ip, p.host, p.target, p.protocol
            );
        }
        if sb.capabilities.kvm.is_some_and(|c| c.enabled) {
            out += "  capability: kvm@1\n";
        }
        if sb.capabilities.docker.is_some_and(|c| c.enabled) {
            out += "  capability: dockerd@1\n";
        }
        if sb.firewall.default.is_some() || !sb.firewall.rules.is_empty() {
            out += &format!(
                "  firewall: default={:?}, {} rule(s)\n",
                sb.firewall.default,
                sb.firewall.rules.len()
            );
        }
        for (sname, sec) in &sb.secrets {
            if sec.is_literal() {
                out += &format!(
                    "  WARNING: secret {sname:?} embeds a literal value; use ref: or command:\n"
                );
            }
        }
        if sb.hooks.has_host_hooks() {
            out += "  NOTE: host lifecycle hooks run on the host with your privileges\n";
        }
    }
    out
}

/// Serialize a compiled [`osbx_spec::ProjectSpec`] as canonical YAML or JSON.
pub fn format_config(project: &osbx_spec::ProjectSpec, json: bool) -> Result<String, String> {
    if json {
        serde_json::to_string_pretty(project).map_err(|e| e.to_string())
    } else {
        serde_yaml_ng::to_string(project).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_name_rules() {
        let p = osbx_compose::compile(
            &["name: demo\nsandboxes:\n  dev:\n    agent: shell\n  demo:\n    agent: shell\n  custom:\n    sandbox_name: exact\n    agent: shell\n"],
            &osbx_compose::Context::default(),
        )
        .unwrap();
        assert_eq!(runtime_name(p.name.as_deref(), "dev", &p.sandboxes["dev"]), "demo-dev");
        assert_eq!(runtime_name(p.name.as_deref(), "demo", &p.sandboxes["demo"]), "demo");
        assert_eq!(runtime_name(p.name.as_deref(), "custom", &p.sandboxes["custom"]), "exact");
    }

    #[test]
    fn config_outputs_valid_yaml_and_json() {
        let p = osbx_compose::compile(
            &["sandboxes:\n  s:\n    agent: claude\n    cpus: 4\n    memory: 4G\n"],
            &osbx_compose::Context::default(),
        )
        .unwrap();
        let yaml = format_config(&p, false).unwrap();
        let back: osbx_spec::ProjectSpec = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(back, p);
        let json = format_config(&p, true).unwrap();
        let back_json: osbx_spec::ProjectSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back_json, p);
    }
}
