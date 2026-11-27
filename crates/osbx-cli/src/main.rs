//! `osbx` command line: sandbox lifecycle (Linux/KVM and Windows/WHP hosts), persistent policy and secrets,
//! and offline tools for policies, kits, sbxenv.yaml and the hypervisor.

// On hosts without a hypervisor backend (e.g. macOS), `kits` and `state` stay compiled so their
// unit tests run even though `lifecycle`/`supervisor`/`client` are cfg-gated out.
#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]

#[cfg(any(target_os = "linux", windows))]
mod client;
#[cfg(any(target_os = "linux", windows))]
mod images;
mod kits;
#[cfg(any(target_os = "linux", windows))]
mod lifecycle;
mod state;
#[cfg(any(target_os = "linux", windows))]
mod supervisor;
#[cfg(any(target_os = "linux", windows))]
mod sys;

use clap::{Args, Parser, Subcommand};
use osbx_policy::{
    Action, Decision, Destination, Origin, PolicySet, Preset, Request, Rule, balanced_baseline,
};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "osbx",
    version,
    about = "Open sandbox runtime for coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

/// Flags shared by `create` and `run`.
#[derive(Args, Clone, Debug)]
struct CreateArgs {
    /// Sandbox name (default: <agent>-<workspace dir>)
    #[arg(long)]
    name: Option<String>,
    /// Image to build the root filesystem from (default: the agent's image; shell = ubuntu:24.04)
    #[arg(long)]
    image: Option<String>,
    /// Workspace directory (default: the current directory)
    #[arg(long, short = 'w')]
    workspace: Option<std::path::PathBuf>,
    /// Do not mount any workspace
    #[arg(long, conflicts_with_all = ["workspace", "clone"])]
    no_workspace: bool,
    /// Mount the repository read-only and let the agent work on a private clone
    #[arg(long)]
    clone: bool,
    /// Environment variable for every command, KEY=VALUE (repeatable)
    #[arg(long = "env", short = 'e')]
    env: Vec<String>,
    /// Guest RAM in MiB
    #[arg(long, default_value_t = 2048)]
    mem: usize,
    /// Number of vCPUs (1-32)
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=32))]
    cpus: u8,
    /// Kit to compose: a local directory or an image reference (repeatable)
    #[arg(long = "kit")]
    kits: Vec<String>,
    /// Argument for a kit: `KIT.NAME=VALUE` or `NAME=VALUE` (repeatable)
    #[arg(long = "kit-arg")]
    kit_args: Vec<String>,
    /// Give the sandbox usable /dev/kvm and /dev/vhost-vsock (a kvm@1 grant; needs nested virtualization)
    #[arg(long)]
    kvm: bool,
    /// Run Docker Engine inside the sandbox (started at boot when the image has dockerd)
    #[arg(long)]
    docker: bool,
    /// Start from a template saved with `osbx save`
    #[arg(long, conflicts_with = "image")]
    template: Option<String>,
    /// Root disk size, e.g. 40g or 20480m (default: image size + headroom, at least 2 GiB)
    #[arg(long, value_parser = parse_size)]
    disk: Option<u64>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a sandbox (does not start it)
    Create {
        #[command(flatten)]
        args: CreateArgs,
        /// Agent (shell, claude, ...) or image reference
        #[arg(default_value = "shell")]
        agent: String,
    },
    /// Create (if needed), start (if needed) and attach to a sandbox's agent
    Run {
        #[command(flatten)]
        args: CreateArgs,
        /// Agent (shell, claude, ...) or image reference
        #[arg(default_value = "shell")]
        agent: String,
        /// Command to run instead of the agent's default
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Start a stopped sandbox
    Start {
        /// Sandbox name
        name: String,
    },
    /// Stop a running sandbox (its disk is kept)
    Stop {
        /// Sandbox name
        name: String,
    },
    /// Remove a sandbox and its disk (the host workspace is not touched)
    Rm {
        /// Stop it first if it is running
        #[arg(long, short = 'f')]
        force: bool,
        /// Sandbox names
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// List sandboxes
    Ls,
    /// Run a command in a running sandbox
    Exec {
        /// Keep stdin open and forward it
        #[arg(short = 'i', long)]
        interactive: bool,
        /// Allocate a terminal
        #[arg(short = 't', long)]
        tty: bool,
        /// Run as this user
        #[arg(short = 'u', long)]
        user: Option<String>,
        /// Working directory
        #[arg(short = 'w', long)]
        workdir: Option<String>,
        /// Environment variable, KEY=VALUE (repeatable)
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        /// Sandbox name
        name: String,
        /// Command and arguments
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Copy files between the host and a sandbox (one side is NAME:/absolute/path)
    Cp {
        /// Source
        src: String,
        /// Destination
        dst: String,
    },
    /// List or publish ports of a running sandbox
    Ports {
        /// Sandbox name
        name: String,
        /// Publish `[IP:]HOST:GUEST` or `GUEST` (host port chosen)
        #[arg(long)]
        publish: Option<String>,
    },
    /// Save a stopped sandbox's root disk as a template (`create --template`)
    Save {
        /// Sandbox name
        name: String,
        /// Template name
        template: String,
    },
    /// List saved templates
    Templates,
    /// Show a sandbox's guest console
    Logs {
        /// Sandbox name
        name: String,
    },
    /// Manage stored credentials (injected by the proxy, never placed in the sandbox)
    Secret {
        #[command(subcommand)]
        command: SecretCmd,
    },
    /// Internal: the per-sandbox supervisor
    #[command(name = "__supervise", hide = true)]
    Supervise {
        /// Sandbox name
        name: String,
    },
    /// Network policy tools
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    /// Kit v3 tools
    Kit {
        #[command(subcommand)]
        command: KitCmd,
    },
    /// sbxenv.yaml tools
    Env {
        #[command(subcommand)]
        command: EnvCmd,
    },
    /// Hypervisor tools
    Vmm {
        #[command(subcommand)]
        command: VmmCmd,
    },
}

#[derive(Subcommand)]
enum VmmCmd {
    /// Boot a Linux kernel in a fresh microVM on this host (Linux/KVM only)
    ///
    /// Exit status: 0 if the guest shut itself down, 1 on crash/timeout/error.
    Boot {
        /// bzImage kernel
        #[arg(long)]
        kernel: std::path::PathBuf,
        /// initramfs (cpio, optionally gzip)
        #[arg(long)]
        initrd: Option<std::path::PathBuf>,
        /// Extra kernel arguments, appended to the defaults (console on COM1, no ACPI/PCI probing)
        #[arg(long, default_value = "")]
        append: String,
        /// Guest RAM in MiB
        #[arg(long, default_value_t = 256)]
        mem: usize,
        /// Kill the guest after this many seconds (0 = never)
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        /// Interactive: forward stdin to the guest console (adds osbx.mode=shell)
        #[arg(long)]
        interactive: bool,
    },
    /// Check whether this host can grant the `kvm@1` capability (exit 0 = yes)
    ///
    /// Follows the spec's usability contract: /dev/kvm opens read-write, KVM_GET_API_VERSION is
    /// 12, KVM_CREATE_VM succeeds, /dev/vhost-vsock opens and answers VHOST_GET_FEATURES. Also
    /// reports whether a sandbox could run its own KVM (nested virtualization).
    Probe {
        /// Additionally boot a tiny guest and check it runs (a device node alone proves little)
        #[arg(long)]
        run_guest: bool,
        /// Exit non-zero unless a sandbox could also run its own KVM
        #[arg(long)]
        require_nested: bool,
    },
}

#[derive(Subcommand)]
enum KitCmd {
    /// Decode (strictly) and validate Kit v3 descriptors. Exit status 1 if any has problems.
    Validate {
        /// Descriptor files
        #[arg(required = true)]
        files: Vec<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum EnvCmd {
    /// Create/start the environment's sandbox and attach to its agent
    Run {
        /// Environment file
        #[arg(default_value = "sbxenv.yaml")]
        file: std::path::PathBuf,
        /// Value for a declared env arg, `name=value` (repeatable)
        #[arg(long = "env-arg")]
        env_args: Vec<String>,
        /// Start without attaching
        #[arg(long, short = 'd')]
        detach: bool,
    },
    /// Parse and validate an sbxenv.yaml (layered over ~/.sbxenv.yaml unless --no-user-base)
    Check {
        /// Project file
        #[arg(default_value = "sbxenv.yaml")]
        file: std::path::PathBuf,
        /// Value for a declared env arg, `name=value` (repeatable)
        #[arg(long = "env-arg")]
        env_args: Vec<String>,
        /// Do not merge ~/.sbxenv.yaml
        #[arg(long)]
        no_user_base: bool,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a credential (value read from stdin unless --command or --ref)
    Set {
        /// Service (anthropic, openai, github, ...)
        service: String,
        /// Only for this sandbox (overrides the global value there)
        #[arg(long)]
        sandbox: Option<String>,
        /// Host command printing the secret (resolved at use, cached 55 min)
        #[arg(long)]
        command: Option<String>,
        /// Vault reference (op://... or an AWS Secrets Manager ARN)
        #[arg(long = "ref")]
        reference: Option<String>,
    },
    /// List stored credentials (names and scopes only)
    Ls,
    /// Remove a credential
    Rm {
        /// Service
        service: String,
        /// Sandbox scope
        #[arg(long)]
        sandbox: Option<String>,
    },
    /// Approve credential injection for a service and domain(s) in credentials.yaml
    Bind {
        /// Service
        service: String,
        /// Mechanism (api-key | oauth)
        #[arg(long, default_value = "api-key")]
        mechanism: String,
        /// Allowed domain pattern (repeatable; defaults to built-in domains for built-in API-key services)
        #[arg(long = "domain")]
        domains: Vec<String>,
    },
    /// Revoke an approved credential binding from credentials.yaml
    Unbind {
        /// Service
        service: String,
        /// Only this mechanism (api-key | oauth); omit to remove all
        #[arg(long)]
        mechanism: Option<String>,
    },
    /// List approved credential bindings in credentials.yaml
    Bindings,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Show the stored preset and rules
    Ls,
    /// Set the preset (allow-all | balanced | deny-all)
    Init {
        /// Preset
        preset: String,
    },
    /// Allow destinations (host, host:port, *.domain, IP, CIDR; comma-separated or repeated)
    Allow {
        /// Only for this sandbox
        #[arg(long)]
        sandbox: Option<String>,
        /// Destinations
        #[arg(required = true)]
        dests: Vec<String>,
    },
    /// Deny destinations (a deny always wins over an allow)
    Deny {
        /// Only for this sandbox
        #[arg(long)]
        sandbox: Option<String>,
        /// Destinations
        #[arg(required = true)]
        dests: Vec<String>,
    },
    /// List destinations a running sandbox tried to reach that no rule decides (refused, awaiting approval)
    Pending {
        /// Sandbox name
        name: String,
    },
    /// Approve destinations for a sandbox (adds sandbox-scoped allow rules; takes effect immediately)
    Approve {
        /// Allow for all sandboxes instead of just this one
        #[arg(long)]
        all_sandboxes: bool,
        /// Sandbox name
        name: String,
        /// Destinations (as shown by `policy pending`)
        #[arg(required = true)]
        dests: Vec<String>,
    },
    /// Remove a stored rule
    Rm {
        /// Only the rule scoped to this sandbox
        #[arg(long)]
        sandbox: Option<String>,
        /// Destination as written in the rule
        dest: String,
    },
    /// List the baseline destinations of the `balanced` preset
    Baseline,
    /// Evaluate one connection against a preset plus extra rules (offline)
    ///
    /// Exit status: 0 allowed, 1 denied, 2 needs approval, 64 usage error.
    Check {
        /// allow-all | balanced | deny-all
        #[arg(long, default_value = "balanced")]
        preset: String,
        /// Extra allow rule (repeatable), e.g. `myhost:22`
        #[arg(long)]
        allow: Vec<String>,
        /// Extra deny rule (repeatable)
        #[arg(long)]
        deny: Vec<String>,
        /// Sandbox name used for sandbox-scoped rules
        #[arg(long, default_value = "default")]
        sandbox: String,
        /// Target as `host` or `host:port` (port defaults to 443)
        target: String,
    },
}

/// `40g`, `512m` or a plain number of MiB.
fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult) = match t.chars().last() {
        Some('g') => (&t[..t.len() - 1], 1024),
        Some('m') => (&t[..t.len() - 1], 1),
        _ => (t.as_str(), 1),
    };
    num.parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("{s:?}: expected a size like 40g or 20480m"))
}

fn done(r: std::io::Result<()>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn code(r: std::io::Result<i32>) -> ExitCode {
    match r {
        Ok(c) => ExitCode::from(u8::try_from(c).unwrap_or(1)),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
fn create_opts(a: CreateArgs, agent: String) -> lifecycle::CreateOpts {
    lifecycle::CreateOpts {
        agent,
        image: a.image,
        name: a.name,
        workspace: a.workspace,
        no_workspace: a.no_workspace,
        clone: a.clone,
        env: a.env,
        mem_mib: a.mem,
        cpus: a.cpus,
        kits: a.kits,
        kit_args: a.kit_args,
        kvm: a.kvm,
        docker: a.docker,
        template: a.template,
        root_size_mib: a.disk,
        mounts: Default::default(),
    }
}

#[cfg(any(target_os = "linux", windows))]
fn lifecycle_cmd(cmd: Cmd) -> ExitCode {
    use lifecycle as l;
    match cmd {
        Cmd::Create { args, agent } => match l::create(&create_opts(args, agent)) {
            Ok(name) => {
                println!("{name}");
                ExitCode::SUCCESS
            }
            Err(e) => done(Err(e)),
        },
        Cmd::Run {
            args,
            agent,
            command,
        } => code(l::run(&create_opts(args, agent), &command)),
        Cmd::Start { name } => done(l::start(&name)),
        Cmd::Stop { name } => done(l::stop(&name)),
        Cmd::Rm { force, names } => done(names.iter().try_for_each(|n| l::rm(n, force))),
        Cmd::Ls => done(l::ls()),
        Cmd::Exec {
            interactive,
            tty,
            user,
            workdir,
            env,
            name,
            command,
        } => {
            let env = env
                .iter()
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            // like the agent itself, commands start in the workspace unless told otherwise
            let cwd = workdir.or_else(|| {
                state::Record::load(&name)
                    .ok()
                    .and_then(|r| r.workspace)
                    .map(|w| state::guest_path(&w.host))
            });
            let req = osbx_proto::ExecRequest {
                argv: command,
                env,
                cwd,
                user,
                ..Default::default()
            };
            code(client::exec(
                &name,
                req,
                client::Attach {
                    stdin: interactive,
                    tty,
                },
            ))
        }
        Cmd::Cp { src, dst } => done(client::cp(&src, &dst)),
        Cmd::Ports { name, publish } => done(l::ports(&name, publish.as_deref())),
        Cmd::Logs { name } => done(l::logs(&name)),
        Cmd::Save { name, template } => done(l::save(&name, &template)),
        Cmd::Templates => done(l::templates()),
        Cmd::Secret {
            command:
                SecretCmd::Set {
                    service,
                    sandbox,
                    command,
                    reference,
                },
        } => done(l::secret_set(&service, sandbox, command, reference)),
        Cmd::Secret {
            command: SecretCmd::Ls,
        } => done(l::secret_ls()),
        Cmd::Secret {
            command: SecretCmd::Rm { service, sandbox },
        } => done(l::secret_rm(&service, sandbox)),
        Cmd::Secret {
            command:
                SecretCmd::Bind {
                    service,
                    mechanism,
                    domains,
                },
        } => done(l::secret_bind(&service, &mechanism, &domains)),
        Cmd::Secret {
            command: SecretCmd::Unbind { service, mechanism },
        } => done(l::secret_unbind(&service, mechanism.as_deref())),
        Cmd::Secret {
            command: SecretCmd::Bindings,
        } => done(l::secret_bindings()),
        Cmd::Supervise { name } => done(supervisor::supervise(&name)),
        Cmd::Policy {
            command: PolicyCmd::Ls,
        } => done(l::policy_ls()),
        Cmd::Policy {
            command: PolicyCmd::Pending { name },
        } => done(l::policy_pending(&name)),
        Cmd::Policy {
            command:
                PolicyCmd::Approve {
                    all_sandboxes,
                    name,
                    dests,
                },
        } => done(l::policy_approve(&name, &dests, all_sandboxes)),
        Cmd::Policy {
            command: PolicyCmd::Init { preset },
        } => done(l::policy_init(&preset)),
        Cmd::Policy {
            command: PolicyCmd::Allow { sandbox, dests },
        } => done(l::policy_add("allow", &dests, sandbox)),
        Cmd::Policy {
            command: PolicyCmd::Deny { sandbox, dests },
        } => done(l::policy_add("deny", &dests, sandbox)),
        Cmd::Policy {
            command: PolicyCmd::Rm { sandbox, dest },
        } => done(l::policy_rm(&dest, sandbox)),
        Cmd::Env {
            command:
                EnvCmd::Run {
                    file,
                    env_args,
                    detach,
                },
        } => code(l::env_run(&file, &env_args, detach)),
        _ => unreachable!("not a lifecycle command"),
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn lifecycle_cmd(_: Cmd) -> ExitCode {
    eprintln!(
        "error: sandboxes need a hypervisor backend; osbx supports Linux (KVM) and Windows (WHP) hosts"
    );
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let cmd = Cli::parse().command;
    let lifecycle = matches!(
        cmd,
        Cmd::Create { .. }
            | Cmd::Run { .. }
            | Cmd::Start { .. }
            | Cmd::Stop { .. }
            | Cmd::Rm { .. }
            | Cmd::Ls
            | Cmd::Exec { .. }
            | Cmd::Cp { .. }
            | Cmd::Ports { .. }
            | Cmd::Logs { .. }
            | Cmd::Save { .. }
            | Cmd::Templates
            | Cmd::Secret { .. }
            | Cmd::Supervise { .. }
            | Cmd::Policy {
                command: PolicyCmd::Ls
                    | PolicyCmd::Pending { .. }
                    | PolicyCmd::Approve { .. }
                    | PolicyCmd::Init { .. }
                    | PolicyCmd::Allow { .. }
                    | PolicyCmd::Deny { .. }
                    | PolicyCmd::Rm { .. }
            }
            | Cmd::Env {
                command: EnvCmd::Run { .. }
            }
    );
    if lifecycle {
        return lifecycle_cmd(cmd);
    }
    match cmd {
        Cmd::Vmm {
            command:
                VmmCmd::Boot {
                    kernel,
                    initrd,
                    append,
                    mem,
                    timeout,
                    interactive,
                },
        } => vmm_boot(kernel, initrd, &append, mem, timeout, interactive),
        Cmd::Vmm {
            command:
                VmmCmd::Probe {
                    run_guest,
                    require_nested,
                },
        } => vmm_probe(run_guest, require_nested),
        Cmd::Kit {
            command: KitCmd::Validate { files },
        } => kit_validate(&files),
        Cmd::Env {
            command:
                EnvCmd::Check {
                    file,
                    env_args,
                    no_user_base,
                },
        } => env_check(&file, &env_args, no_user_base),
        Cmd::Policy {
            command: PolicyCmd::Baseline,
        } => {
            for h in balanced_baseline() {
                println!("{h}");
            }
            ExitCode::SUCCESS
        }
        Cmd::Policy {
            command:
                PolicyCmd::Check {
                    preset,
                    allow,
                    deny,
                    sandbox,
                    target,
                },
        } => match check(&preset, &allow, &deny, &sandbox, &target) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(64)
            }
        },
        _ => unreachable!("handled above"),
    }
}

fn check(
    preset: &str,
    allow: &[String],
    deny: &[String],
    sandbox: &str,
    target: &str,
) -> Result<u8, String> {
    let mut set = PolicySet::new(preset.parse::<Preset>()?);
    for (action, list) in [(Action::Allow, allow), (Action::Deny, deny)] {
        for d in list {
            set.rules
                .push(Rule::new(action, d, Origin::Local).map_err(|e| format!("{d}: {e}"))?);
        }
    }
    // Reuse the destination parser so `host`, `host:port` and `[v6]:port` all work.
    let dest: Destination = target.parse().map_err(|e| format!("{target}: {e}"))?;
    let port = dest.port.unwrap_or(443);
    let host = dest.to_string();
    let host = host
        .rsplit_once(':')
        .filter(|_| dest.port.is_some())
        .map_or(host.as_str(), |(h, _)| h);
    let req = Request {
        host,
        ip: host.trim_matches(['[', ']']).parse().ok(),
        port,
        http: None,
    };
    let decision = set.evaluate(sandbox, &req);
    println!("{decision:?}");
    Ok(match decision {
        Decision::Allow(_) => 0,
        Decision::Deny(_) => 1,
        Decision::NeedsApproval => 2,
    })
}

fn kit_validate(files: &[std::path::PathBuf]) -> ExitCode {
    let mut failed = false;
    for f in files {
        let result = std::fs::read_to_string(f)
            .map_err(|e| vec![e.to_string()])
            .and_then(|t| osbx_kit::Descriptor::from_yaml(&t).map_err(|e| vec![e]))
            .and_then(|d| {
                let issues = osbx_kit::validate(&d);
                if issues.is_empty() {
                    Ok(d)
                } else {
                    Err(issues.iter().map(ToString::to_string).collect())
                }
            });
        match result {
            Ok(d) => println!(
                "{}: ok ({:?}, {} capability item(s))",
                f.display(),
                d.kind,
                d.capabilities.len()
            ),
            Err(problems) => {
                failed = true;
                for p in problems {
                    eprintln!("{}: {p}", f.display());
                }
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn env_check(file: &std::path::Path, env_args: &[String], no_user_base: bool) -> ExitCode {
    let run = || -> Result<String, String> {
        let mut docs = Vec::new();
        if !no_user_base
            && let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
            && let Ok(t) = std::fs::read_to_string(std::path::Path::new(&home).join(".sbxenv.yaml"))
        {
            docs.push(t);
        }
        docs.push(std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?);
        let dir = file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let dir = state::plain_path(&std::fs::canonicalize(dir).map_err(|e| e.to_string())?)
            .to_string_lossy()
            .into_owned();
        let mut args = std::collections::BTreeMap::new();
        for a in env_args {
            let (k, v) = a
                .split_once('=')
                .ok_or(format!("--env-arg {a:?}: expected name=value"))?;
            args.insert(k.to_owned(), v.to_owned());
        }
        let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
        let e = osbx_env::load(
            &refs,
            &osbx_env::Context {
                project_dir: dir.clone(),
                file_dir: dir,
                args,
            },
        )
        .map_err(|e| e.to_string())?;
        let mut out = format!(
            "agent: {}\nname: {}\n",
            e.agent,
            e.name.as_deref().unwrap_or("(default)")
        );
        for k in &e.kits {
            out += &format!(
                "kit: {} -> handle {:?} ({:?})\n",
                k.source(),
                k.handle(),
                k.kind()
            );
        }
        for (sandbox, host) in &e.mounts {
            out += &format!("mount: {sandbox} <- {host}\n");
        }
        for (n, s) in &e.secrets {
            if s.is_literal() {
                out += &format!(
                    "WARNING: secret {n:?} embeds a literal value; use ref: or command:\n"
                );
            }
        }
        if !e.lifecycle.initialize.is_empty()
            || !e.lifecycle.post_create.is_empty()
            || !e.lifecycle.pre_remove.is_empty()
        {
            out += "NOTE: lifecycle hooks run on the host with your privileges\n";
        }
        Ok(out)
    };
    match run() {
        Ok(s) => {
            print!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn vmm_probe(run_guest: bool, require_nested: bool) -> ExitCode {
    if osbx_vmm::report_probe(run_guest, require_nested) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(any(target_os = "linux", windows))]
fn vmm_boot(
    kernel: std::path::PathBuf,
    initrd: Option<std::path::PathBuf>,
    append: &str,
    mem: usize,
    timeout: u64,
    interactive: bool,
) -> ExitCode {
    // ASSUMPTION: no ACPI/MP tables are provided yet, so the guest runs on the legacy PIC and
    // is told not to probe PCI/ACPI; reboot=k makes `reboot -f` use the keyboard-controller reset.
    let mut cmdline = String::from(
        "console=ttyS0 earlyprintk=serial,ttyS0 reboot=k panic=1 acpi=off pci=off nokaslr tsc=reliable i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd",
    );
    if interactive {
        cmdline += " osbx.mode=shell";
    }
    if !append.is_empty() {
        cmdline.push(' ');
        cmdline.push_str(append);
    }
    let cfg = osbx_vmm::BootConfig {
        kernel,
        initrd,
        cmdline,
        mem_mib: mem,
        cpus: 1,
        timeout: (timeout > 0).then(|| std::time::Duration::from_secs(timeout)),
        echo: true,
        stdin: interactive,
        disks: vec![],
        vsock_cid: None,
        shares: vec![],
    };
    match osbx_vmm::boot_linux(&cfg) {
        Ok(out) => {
            eprintln!("\n[osbx] guest ended: {:?}", out.exit);
            if out.exit == osbx_vmm::ExitReason::GuestReset {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn vmm_boot(
    _: std::path::PathBuf,
    _: Option<std::path::PathBuf>,
    _: &str,
    _: usize,
    _: u64,
    _: bool,
) -> ExitCode {
    eprintln!("error: booting guests needs a Linux (KVM) or Windows (WHP) host");
    ExitCode::from(1)
}
