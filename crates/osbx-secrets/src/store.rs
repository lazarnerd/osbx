//! Secret storage: scopes, sources and the store trait with two backends.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Where a stored secret applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// All sandboxes (default).
    Global,
    /// One sandbox; overrides the global value.
    Sandbox(String),
}

/// How the real value is obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Source {
    /// Literal value stored as-is.
    Value(String),
    /// Host command whose stdout is the secret.
    Command(String),
    /// Vault reference (`op://…` 1Password, or an AWS Secrets Manager ARN).
    Ref(String),
}

/// Re-resolution policy for command/ref sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Refresh {
    /// Cache for [`crate::DEFAULT_TTL`].
    #[default]
    Default,
    /// Cache for this many seconds.
    Seconds(u64),
    /// Resolve on every use.
    OnDemand,
}

/// A stored entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    /// Value source.
    pub source: Source,
    /// Refresh policy.
    #[serde(default)]
    pub refresh: Refresh,
}

/// Storage failure.
#[derive(Debug)]
pub struct StoreError(pub String);
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

/// A secret store.
pub trait SecretStore: Send + Sync {
    /// Fetch one entry.
    fn get(&self, scope: &Scope, service: &str) -> Result<Option<Stored>, StoreError>;
    /// Create or replace an entry.
    fn set(&self, scope: &Scope, service: &str, entry: Stored) -> Result<(), StoreError>;
    /// Remove an entry; returns whether it existed.
    fn remove(&self, scope: &Scope, service: &str) -> Result<bool, StoreError>;
    /// List `(scope, service)` pairs (never values).
    fn list(&self) -> Result<Vec<(Scope, String)>, StoreError>;
    /// Delete everything (`sbx reset`).
    fn clear(&self) -> Result<(), StoreError>;
}

type Map = BTreeMap<String, Stored>;
fn key(scope: &Scope, service: &str) -> String {
    match scope {
        Scope::Global => format!("global\u{1f}{service}"),
        Scope::Sandbox(s) => format!("sandbox:{s}\u{1f}{service}"),
    }
}
fn unkey(k: &str) -> Option<(Scope, String)> {
    let (scope, service) = k.split_once('\u{1f}')?;
    let scope = match scope.strip_prefix("sandbox:") {
        Some(s) => Scope::Sandbox(s.to_owned()),
        None if scope == "global" => Scope::Global,
        None => return None,
    };
    Some((scope, service.to_owned()))
}

/// In-memory store (tests, ephemeral daemons).
#[derive(Default)]
pub struct MemoryStore(Mutex<Map>);

impl SecretStore for MemoryStore {
    fn get(&self, scope: &Scope, service: &str) -> Result<Option<Stored>, StoreError> {
        Ok(self.0.lock().unwrap().get(&key(scope, service)).cloned())
    }
    fn set(&self, scope: &Scope, service: &str, entry: Stored) -> Result<(), StoreError> {
        self.0.lock().unwrap().insert(key(scope, service), entry);
        Ok(())
    }
    fn remove(&self, scope: &Scope, service: &str) -> Result<bool, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .remove(&key(scope, service))
            .is_some())
    }
    fn list(&self) -> Result<Vec<(Scope, String)>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .keys()
            .filter_map(|k| unkey(k))
            .collect())
    }
    fn clear(&self) -> Result<(), StoreError> {
        self.0.lock().unwrap().clear();
        Ok(())
    }
}

/// File-backed store: `<dir>/secrets.json`, directory mode 0700, file mode 0600.
/// Anyone who can read the file can read the credentials; this is the fallback for
/// hosts without a keychain.
pub struct FileStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl FileStore {
    /// Open (creating the directory with restrictive permissions).
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.join("secrets.json")
    }
    fn load(&self) -> Result<Map, StoreError> {
        match std::fs::read(self.path()) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| StoreError(format!("corrupt secrets file: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
            Err(e) => Err(e.into()),
        }
    }
    fn save(&self, m: &Map) -> Result<(), StoreError> {
        let tmp = self.dir.join("secrets.json.tmp");
        let data = serde_json::to_vec_pretty(m).map_err(|e| StoreError(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, self.path())?;
        Ok(())
    }
}

impl SecretStore for FileStore {
    fn get(&self, scope: &Scope, service: &str) -> Result<Option<Stored>, StoreError> {
        let _g = self.lock.lock().unwrap();
        Ok(self.load()?.get(&key(scope, service)).cloned())
    }
    fn set(&self, scope: &Scope, service: &str, entry: Stored) -> Result<(), StoreError> {
        let _g = self.lock.lock().unwrap();
        let mut m = self.load()?;
        m.insert(key(scope, service), entry);
        self.save(&m)
    }
    fn remove(&self, scope: &Scope, service: &str) -> Result<bool, StoreError> {
        let _g = self.lock.lock().unwrap();
        let mut m = self.load()?;
        let had = m.remove(&key(scope, service)).is_some();
        self.save(&m)?;
        Ok(had)
    }
    fn list(&self) -> Result<Vec<(Scope, String)>, StoreError> {
        let _g = self.lock.lock().unwrap();
        Ok(self.load()?.keys().filter_map(|k| unkey(k)).collect())
    }
    fn clear(&self) -> Result<(), StoreError> {
        let _g = self.lock.lock().unwrap();
        self.save(&Map::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(v: &str) -> Stored {
        Stored {
            source: Source::Value(v.into()),
            refresh: Refresh::Default,
        }
    }

    fn exercise(s: &dyn SecretStore) {
        assert!(s.get(&Scope::Global, "github").unwrap().is_none());
        s.set(&Scope::Global, "github", lit("g")).unwrap();
        s.set(&Scope::Sandbox("a".into()), "github", lit("a"))
            .unwrap();
        assert_eq!(s.get(&Scope::Global, "github").unwrap(), Some(lit("g")));
        assert_eq!(
            s.get(&Scope::Sandbox("a".into()), "github").unwrap(),
            Some(lit("a"))
        );
        assert!(
            s.get(&Scope::Sandbox("b".into()), "github")
                .unwrap()
                .is_none()
        );
        assert_eq!(s.list().unwrap().len(), 2);
        assert!(s.remove(&Scope::Sandbox("a".into()), "github").unwrap());
        assert!(!s.remove(&Scope::Sandbox("a".into()), "github").unwrap());
        s.clear().unwrap();
        assert!(s.list().unwrap().is_empty());
    }

    #[test]
    fn memory_store() {
        exercise(&MemoryStore::default());
    }

    #[test]
    fn file_store_roundtrip_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandboxes");
        let s = FileStore::open(&path).unwrap();
        exercise(&s);
        s.set(&Scope::Global, "openai", lit("sk")).unwrap();
        // survives reopen
        let again = FileStore::open(&path).unwrap();
        assert_eq!(
            again.get(&Scope::Global, "openai").unwrap(),
            Some(lit("sk"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o700);
            assert_eq!(mode(&path.join("secrets.json")), 0o600);
        }
    }

    #[test]
    fn corrupt_file_is_an_error_not_silent_loss() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStore::open(dir.path()).unwrap();
        std::fs::write(dir.path().join("secrets.json"), b"{not json").unwrap();
        assert!(s.get(&Scope::Global, "x").is_err());
        assert!(s.set(&Scope::Global, "x", lit("v")).is_err()); // must not overwrite what it cannot read
    }
}
