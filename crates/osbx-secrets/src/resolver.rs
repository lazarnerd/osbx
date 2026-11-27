//! Resolving a stored entry to the real value, with scope precedence and caching.

use crate::store::{Refresh, Scope, SecretStore, Source, StoreError};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Time source (injectable for tests).
pub trait Clock: Send + Sync {
    /// Monotonic now.
    fn now(&self) -> Instant;
}
/// Real clock.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Runs host commands (injectable for tests).
pub trait CommandRunner: Send + Sync {
    /// Run `argv`, returning trimmed stdout.
    fn run(&self, argv: &[String]) -> Result<String, String>;
}

/// Runs commands for real. Shell commands go through `sh -c` (`cmd /C` on Windows).
pub struct ShellRunner;
impl CommandRunner for ShellRunner {
    fn run(&self, argv: &[String]) -> Result<String, String> {
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {}: {e}", argv[0]))?;
        if !out.status.success() {
            // stderr only: stdout may contain a partial secret
            return Err(format!(
                "{} failed: {}",
                argv[0],
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .trim_end_matches(['\r', '\n'])
            .to_owned())
    }
}

/// Resolution failure. Never contains a secret value.
#[derive(Debug)]
pub enum ResolveError {
    /// The store failed.
    Store(StoreError),
    /// The command or vault lookup failed.
    Source(String),
    /// The source produced an empty value.
    Empty,
}
impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Source(e) => write!(f, "source: {e}"),
            Self::Empty => f.write_str("source produced an empty value"),
        }
    }
}
impl std::error::Error for ResolveError {}

/// Resolves `(sandbox, service)` to the real credential.
pub struct Resolver<S, R = ShellRunner, C = SystemClock> {
    store: S,
    runner: R,
    clock: C,
    cache: Mutex<HashMap<(Scope, String), (Instant, String)>>,
}

impl<S: SecretStore> Resolver<S> {
    /// Resolver with the real shell runner and clock.
    pub fn new(store: S) -> Self {
        Self::with(store, ShellRunner, SystemClock)
    }
}

impl<S: SecretStore, R: CommandRunner, C: Clock> Resolver<S, R, C> {
    /// Resolver with explicit runner and clock.
    pub fn with(store: S, runner: R, clock: C) -> Self {
        Self {
            store,
            runner,
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve for `sandbox`: its own scoped secret first, then the global one.
    pub fn resolve(&self, sandbox: &str, service: &str) -> Result<Option<String>, ResolveError> {
        for scope in [Scope::Sandbox(sandbox.to_owned()), Scope::Global] {
            if let Some(v) = self.resolve_scope(&scope, service)? {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    fn resolve_scope(&self, scope: &Scope, service: &str) -> Result<Option<String>, ResolveError> {
        let Some(entry) = self
            .store
            .get(scope, service)
            .map_err(ResolveError::Store)?
        else {
            return Ok(None);
        };
        let argv = match &entry.source {
            Source::Value(v) => return Ok(Some(v.clone())),
            Source::Command(c) => shell_argv(c),
            Source::Ref(r) => ref_argv(r),
        };
        let ttl = match entry.refresh {
            Refresh::Default => Some(crate::DEFAULT_TTL),
            Refresh::Seconds(s) => Some(Duration::from_secs(s)),
            Refresh::OnDemand => None,
        };
        let ck = (scope.clone(), service.to_owned());
        let now = self.clock.now();
        if let Some(ttl) = ttl
            && let Some((at, v)) = self.cache.lock().unwrap().get(&ck)
            && now.duration_since(*at) < ttl
        {
            return Ok(Some(v.clone()));
        }
        let v = self.runner.run(&argv).map_err(ResolveError::Source)?;
        if v.is_empty() {
            return Err(ResolveError::Empty);
        }
        if ttl.is_some() {
            self.cache.lock().unwrap().insert(ck, (now, v.clone()));
        }
        Ok(Some(v))
    }

    /// Drop cached values (after `secret set/rm`).
    pub fn invalidate(&self) {
        self.cache.lock().unwrap().clear();
    }
}

fn shell_argv(cmd: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), cmd.into()]
    } else {
        vec!["sh".into(), "-c".into(), cmd.into()]
    }
}

/// 1Password references go through `op read`, AWS Secrets Manager ARNs through the AWS CLI.
fn ref_argv(r: &str) -> Vec<String> {
    if r.starts_with("arn:aws") {
        [
            "aws",
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            r,
            "--query",
            "SecretString",
            "--output",
            "text",
        ]
        .map(String::from)
        .to_vec()
    } else {
        vec!["op".into(), "read".into(), r.into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, Stored};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeClock(Mutex<Instant>);
    impl FakeClock {
        fn advance(&self, d: Duration) {
            *self.0.lock().unwrap() += d;
        }
    }
    impl Clock for Arc<FakeClock> {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }
    struct Counting(Arc<AtomicUsize>);
    impl CommandRunner for Counting {
        fn run(&self, argv: &[String]) -> Result<String, String> {
            let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(format!("{}-{n}", argv.last().unwrap()))
        }
    }

    fn entry(source: Source, refresh: Refresh) -> Stored {
        Stored { source, refresh }
    }

    #[test]
    fn sandbox_scope_overrides_global_and_removal_restores_it() {
        let store = MemoryStore::default();
        store
            .set(
                &Scope::Global,
                "github",
                entry(Source::Value("global".into()), Refresh::Default),
            )
            .unwrap();
        store
            .set(
                &Scope::Sandbox("a".into()),
                "github",
                entry(Source::Value("scoped".into()), Refresh::Default),
            )
            .unwrap();
        let r = Resolver::new(store);
        assert_eq!(r.resolve("a", "github").unwrap().as_deref(), Some("scoped"));
        assert_eq!(r.resolve("b", "github").unwrap().as_deref(), Some("global"));
        assert_eq!(r.resolve("a", "nope").unwrap(), None);
    }

    #[test]
    fn command_results_are_cached_for_the_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(FakeClock(Mutex::new(Instant::now())));
        let store = MemoryStore::default();
        store
            .set(
                &Scope::Global,
                "s",
                entry(Source::Command("tok".into()), Refresh::Default),
            )
            .unwrap();
        let r = Resolver::with(store, Counting(calls.clone()), clock.clone());
        assert_eq!(r.resolve("x", "s").unwrap().as_deref(), Some("tok-1"));
        clock.advance(Duration::from_secs(54 * 60));
        assert_eq!(r.resolve("x", "s").unwrap().as_deref(), Some("tok-1")); // still cached
        clock.advance(Duration::from_secs(2 * 60));
        assert_eq!(r.resolve("x", "s").unwrap().as_deref(), Some("tok-2")); // 56 min: re-resolved
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn on_demand_resolves_every_time_and_custom_ttl_is_honoured() {
        let calls = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(FakeClock(Mutex::new(Instant::now())));
        let store = MemoryStore::default();
        store
            .set(
                &Scope::Global,
                "od",
                entry(Source::Command("a".into()), Refresh::OnDemand),
            )
            .unwrap();
        store
            .set(
                &Scope::Global,
                "ttl",
                entry(Source::Command("b".into()), Refresh::Seconds(10)),
            )
            .unwrap();
        let r = Resolver::with(store, Counting(calls.clone()), clock.clone());
        r.resolve("x", "od").unwrap();
        r.resolve("x", "od").unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        r.resolve("x", "ttl").unwrap();
        clock.advance(Duration::from_secs(11));
        r.resolve("x", "ttl").unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn refs_pick_the_right_tool_and_errors_leak_nothing() {
        assert_eq!(ref_argv("op://V/i/f")[0], "op");
        assert_eq!(
            ref_argv("arn:aws:secretsmanager:us-east-1:1:secret:x")[0],
            "aws"
        );
        let store = MemoryStore::default();
        store
            .set(
                &Scope::Global,
                "bad",
                entry(
                    Source::Command("echo SECRETVALUE >&2; exit 3".into()),
                    Refresh::Default,
                ),
            )
            .unwrap();
        store
            .set(
                &Scope::Global,
                "empty",
                entry(Source::Command("true".into()), Refresh::Default),
            )
            .unwrap();
        let r = Resolver::new(store);
        if cfg!(unix) {
            assert!(matches!(
                r.resolve("x", "bad"),
                Err(ResolveError::Source(_))
            ));
            assert!(matches!(r.resolve("x", "empty"), Err(ResolveError::Empty)));
        }
    }

    #[test]
    fn real_shell_runner_trims_the_trailing_newline() {
        if cfg!(unix) {
            let store = MemoryStore::default();
            store
                .set(
                    &Scope::Global,
                    "s",
                    entry(Source::Command("printf 'abc\\n'".into()), Refresh::Default),
                )
                .unwrap();
            assert_eq!(
                Resolver::new(store).resolve("x", "s").unwrap().as_deref(),
                Some("abc")
            );
        }
    }
}
