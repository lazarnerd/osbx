//! Credential bindings: which mechanisms and domains the user approved per service.
//!
//! A binding records an *approval*, never a value. A required credential without a
//! binding fails sandbox creation; an optional one is withheld.

use osbx_policy::Destination;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Credential mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mechanism {
    /// Static API key injected by the proxy.
    ApiKey,
    /// OAuth handled on the host.
    Oauth,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    domains: Vec<String>,
}

/// The approvals file (`credentials.yaml`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bindings(BTreeMap<String, BTreeMap<Mechanism, Entry>>);

impl Bindings {
    /// Parse the YAML form:
    /// ```yaml
    /// github:
    ///   apiKey: {domains: [api.github.com]}
    /// ```
    pub fn from_yaml(s: &str) -> Result<Self, String> {
        serde_yaml_ng::from_str(s).map_err(|e| e.to_string())
    }
    /// Serialize to YAML.
    pub fn to_yaml(&self) -> String {
        serde_yaml_ng::to_string(self).unwrap_or_default()
    }
    /// Approve `mechanism` for `service` on `domains` (merging with existing domains).
    pub fn approve(&mut self, service: &str, mechanism: Mechanism, domains: &[&str]) {
        let e = self
            .0
            .entry(service.to_owned())
            .or_default()
            .entry(mechanism)
            .or_default();
        for d in domains {
            if !e.domains.iter().any(|x| x == d) {
                e.domains.push((*d).to_owned());
            }
        }
    }
    /// Is any binding present for `service`/`mechanism`?
    pub fn has(&self, service: &str, mechanism: Mechanism) -> bool {
        self.0
            .get(service)
            .is_some_and(|m| m.contains_key(&mechanism))
    }
    /// May the credential for `service` be presented to `domain` under `mechanism`?
    pub fn allows(&self, service: &str, mechanism: Mechanism, domain: &str) -> bool {
        self.0
            .get(service)
            .and_then(|m| m.get(&mechanism))
            .is_some_and(|e| {
                e.domains.iter().any(|p| {
                    p.parse::<Destination>()
                        .is_ok_and(|d| d.matches(domain, None, 443))
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_roundtrip_and_checks() {
        let b = Bindings::from_yaml("github:\n  apiKey:\n    domains: [api.github.com, \"*.githubusercontent.com\"]\nopenai:\n  oauth:\n    domains: [auth.openai.com]\n").unwrap();
        assert!(b.allows("github", Mechanism::ApiKey, "api.github.com"));
        assert!(b.allows("github", Mechanism::ApiKey, "raw.githubusercontent.com"));
        assert!(!b.allows("github", Mechanism::ApiKey, "evil.example"));
        assert!(!b.allows("github", Mechanism::Oauth, "api.github.com")); // mechanism must match
        assert!(!b.allows("anthropic", Mechanism::ApiKey, "api.anthropic.com")); // no binding
        assert!(b.has("openai", Mechanism::Oauth));
        assert_eq!(Bindings::from_yaml(&b.to_yaml()).unwrap(), b);
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(
            Bindings::from_yaml("github:\n  apiKey:\n    domains: []\n    secret: x\n").is_err()
        );
    }

    #[test]
    fn approve_merges_without_duplicates() {
        let mut b = Bindings::default();
        b.approve("github", Mechanism::ApiKey, &["a.com"]);
        b.approve("github", Mechanism::ApiKey, &["a.com", "b.com"]);
        assert!(b.allows("github", Mechanism::ApiKey, "b.com"));
        assert_eq!(b.to_yaml().matches("a.com").count(), 1);
    }
}
