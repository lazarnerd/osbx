//! Built-in services and how their credentials are presented.
//!
//! ASSUMPTION: Docker documents only the service names (anthropic, cursor, droid, github,
//! google, groq, mistral, nebius, openai, openrouter, xai). The env variables, API hosts
//! and header formats below come from each provider's public API conventions and must be
//! compared with a real `sbx secret import --dry-run` / `sbx policy ls`.

use crate::InjectRule;

/// A built-in credential service.
#[derive(Debug, Clone, Copy)]
pub struct Service {
    /// Service name as used by `secret set <service>`.
    pub name: &'static str,
    /// Environment variables `secret import` reads (first non-empty wins).
    pub env_vars: &'static [&'static str],
    /// `(host pattern, header, format)` presentation rules.
    pub rules: &'static [(&'static str, &'static str, &'static str)],
}

const BEARER: &str = "Bearer %s";

static SERVICES: &[Service] = &[
    Service {
        name: "anthropic",
        env_vars: &["ANTHROPIC_API_KEY"],
        rules: &[("api.anthropic.com", "x-api-key", "%s")],
    },
    Service {
        name: "openai",
        env_vars: &["OPENAI_API_KEY"],
        rules: &[("api.openai.com", "Authorization", BEARER)],
    },
    Service {
        name: "github",
        env_vars: &["GH_TOKEN", "GITHUB_TOKEN"],
        rules: &[
            ("api.github.com", "Authorization", BEARER),
            ("github.com", "Authorization", BEARER),
        ],
    },
    Service {
        name: "google",
        env_vars: &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        rules: &[("generativelanguage.googleapis.com", "x-goog-api-key", "%s")],
    },
    Service {
        name: "groq",
        env_vars: &["GROQ_API_KEY"],
        rules: &[("api.groq.com", "Authorization", BEARER)],
    },
    Service {
        name: "mistral",
        env_vars: &["MISTRAL_API_KEY"],
        rules: &[("api.mistral.ai", "Authorization", BEARER)],
    },
    Service {
        name: "nebius",
        env_vars: &["NEBIUS_API_KEY"],
        rules: &[("api.studio.nebius.com", "Authorization", BEARER)],
    },
    Service {
        name: "openrouter",
        env_vars: &["OPENROUTER_API_KEY"],
        rules: &[("openrouter.ai", "Authorization", BEARER)],
    },
    Service {
        name: "xai",
        env_vars: &["XAI_API_KEY"],
        rules: &[("api.x.ai", "Authorization", BEARER)],
    },
    Service {
        name: "cursor",
        env_vars: &["CURSOR_API_KEY"],
        rules: &[("api.cursor.com", "Authorization", BEARER)],
    },
    Service {
        name: "droid",
        env_vars: &["FACTORY_API_KEY"],
        rules: &[("api.factory.ai", "Authorization", BEARER)],
    },
];

/// All built-in services.
pub fn builtin_services() -> &'static [Service] {
    SERVICES
}

/// Look up a built-in service by name.
pub fn find_service(name: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.name == name)
}

impl Service {
    /// The injection rules for this service.
    pub fn inject_rules(&self) -> Vec<InjectRule> {
        self.rules
            .iter()
            .map(|(d, h, f)| InjectRule {
                domain: (*d).to_owned(),
                header: (*h).to_owned(),
                format: (*f).to_owned(),
                basic_user: None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_service_exists_and_rules_parse() {
        for n in [
            "anthropic",
            "cursor",
            "droid",
            "github",
            "google",
            "groq",
            "mistral",
            "nebius",
            "openai",
            "openrouter",
            "xai",
        ] {
            let s = find_service(n).unwrap_or_else(|| panic!("{n}"));
            assert!(!s.env_vars.is_empty() && !s.rules.is_empty());
            for r in s.inject_rules() {
                r.domain.parse::<osbx_policy::Destination>().unwrap();
            }
        }
        assert_eq!(builtin_services().len(), 11);
    }
}
