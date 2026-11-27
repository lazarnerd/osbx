//! Policy evaluation.

use crate::baseline::balanced_baseline;
use crate::rule::{Action, Origin, Request, Rule};
use std::str::FromStr;

/// The three documented presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// `allow-all`: all outbound TCP allowed.
    AllowAll,
    /// `balanced`: default deny plus a baseline allow-list.
    Balanced,
    /// `deny-all`: no baseline rules.
    DenyAll,
}

impl FromStr for Preset {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "allow-all" => Ok(Self::AllowAll),
            "balanced" => Ok(Self::Balanced),
            "deny-all" => Ok(Self::DenyAll),
            _ => Err(format!(
                "unknown preset {s:?} (allow-all | balanced | deny-all)"
            )),
        }
    }
}

/// Organization governance state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Governance {
    /// Organization name (shown as "Managed by <org>").
    pub org: String,
    /// Optional admin-configured support message appended to block messages.
    pub support_message: Option<String>,
}

/// Why a decision was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Allowed by `rules[i]`.
    AllowRule(usize),
    /// Allowed by the preset's baseline list.
    Baseline,
    /// Preset is `allow-all` and nothing denied it.
    PresetAllowAll,
    /// Denied by `rules[i]`.
    DenyRule(usize),
    /// Organization policy active and no org allow rule matched.
    OrgPolicy,
    /// No rule matched under a default-deny preset.
    NoMatch,
}

/// Outcome for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let it through.
    Allow(Reason),
    /// Block.
    Deny(Reason),
    /// Block for now and ask the user. Never produced under governance.
    NeedsApproval,
}

impl Decision {
    /// True for [`Decision::Allow`].
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}

/// All policy inputs for one host.
#[derive(Debug, Clone)]
pub struct PolicySet {
    /// Active preset.
    pub preset: Preset,
    /// Explicit rules from every source.
    pub rules: Vec<Rule>,
    /// Set when organization governance is enforced.
    pub governance: Option<Governance>,
}

impl PolicySet {
    /// New set with a preset and no rules.
    pub fn new(preset: Preset) -> Self {
        Self {
            preset,
            rules: Vec::new(),
            governance: None,
        }
    }

    /// Message for a blocked request (`Blocked by org policy` + support message under governance).
    pub fn block_message(&self, d: &Decision) -> Option<String> {
        match (d, &self.governance) {
            (Decision::Deny(Reason::OrgPolicy), Some(g)) => Some(match &g.support_message {
                Some(m) => format!("Blocked by org policy. {m}"),
                None => "Blocked by org policy".to_owned(),
            }),
            (Decision::Deny(_), _) => Some("Blocked by network policy".to_owned()),
            (Decision::NeedsApproval, _) => Some("Approval required".to_owned()),
            _ => None,
        }
    }

    /// True if any rule for `sandbox` that covers `host:port` carries HTTP constraints.
    /// A proxy must then terminate TLS for that host to see method/path/query.
    pub fn needs_http_inspection(&self, sandbox: &str, host: &str, port: u16) -> bool {
        let probe = Request {
            host,
            ip: None,
            port,
            http: None,
        };
        self.rules.iter().any(|r| {
            r.http.is_some()
                && !matches!(&r.origin, Origin::Sandbox(s) if s != sandbox)
                && r.dest.matches(probe.host, probe.ip, probe.port)
        })
    }

    /// Evaluate `req` for sandbox `sandbox`.
    ///
    /// Order: (1) any matching deny wins; (2) under governance only org allows grant
    /// access; (3) otherwise any matching allow or baseline entry grants access;
    /// (4) unmatched: `allow-all` allows, the others ask for approval.
    pub fn evaluate(&self, sandbox: &str, req: &Request<'_>) -> Decision {
        let matching = || {
            self.rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.matches(sandbox, req))
        };

        if let Some((i, _)) = matching().find(|(_, r)| r.action == Action::Deny) {
            return Decision::Deny(Reason::DenyRule(i));
        }
        if self.governance.is_some() {
            return match matching()
                .find(|(_, r)| r.action == Action::Allow && r.origin == Origin::Org)
            {
                Some((i, _)) => Decision::Allow(Reason::AllowRule(i)),
                None => Decision::Deny(Reason::OrgPolicy),
            };
        }
        if let Some((i, _)) = matching().find(|(_, r)| r.action == Action::Allow) {
            return Decision::Allow(Reason::AllowRule(i));
        }
        match self.preset {
            Preset::AllowAll => Decision::Allow(Reason::PresetAllowAll),
            Preset::Balanced if self.baseline_allows(req) => Decision::Allow(Reason::Baseline),
            Preset::Balanced | Preset::DenyAll => Decision::NeedsApproval,
        }
    }

    fn baseline_allows(&self, req: &Request<'_>) -> bool {
        balanced_baseline().iter().any(|p| {
            p.parse::<crate::Destination>()
                .is_ok_and(|d| d.matches(req.host, req.ip, req.port))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(host: &str, port: u16) -> Request<'_> {
        Request {
            host,
            ip: None,
            port,
            http: None,
        }
    }
    fn rule(a: Action, d: &str, o: Origin) -> Rule {
        Rule::new(a, d, o).unwrap()
    }

    #[test]
    fn baseline_compiles() {
        for p in balanced_baseline() {
            p.parse::<crate::Destination>()
                .unwrap_or_else(|e| panic!("{p}: {e}"));
        }
    }

    #[test]
    fn presets_without_rules() {
        assert!(
            PolicySet::new(Preset::AllowAll)
                .evaluate("s", &r("evil.example", 4444))
                .is_allow()
        );
        let b = PolicySet::new(Preset::Balanced);
        assert!(b.evaluate("s", &r("api.anthropic.com", 443)).is_allow());
        assert_eq!(
            b.evaluate("s", &r("evil.example", 443)),
            Decision::NeedsApproval
        );
        // baseline does not open non-web ports
        assert_eq!(
            b.evaluate("s", &r("github.com", 22)),
            Decision::NeedsApproval
        );
        // deny-all has no baseline
        let d = PolicySet::new(Preset::DenyAll);
        assert_eq!(
            d.evaluate("s", &r("api.anthropic.com", 443)),
            Decision::NeedsApproval
        );
    }

    #[test]
    fn deny_beats_allow_from_any_source() {
        let mut p = PolicySet::new(Preset::AllowAll);
        p.rules
            .push(rule(Action::Allow, "x.com", Origin::Kit("k".into())));
        p.rules.push(rule(Action::Deny, "x.com", Origin::Local));
        assert_eq!(
            p.evaluate("s", &r("x.com", 443)),
            Decision::Deny(Reason::DenyRule(1))
        );
        // even under allow-all, a deny still applies
        assert!(p.evaluate("s", &r("y.com", 443)).is_allow());
    }

    #[test]
    fn kit_rules_apply_under_deny_all() {
        let mut p = PolicySet::new(Preset::DenyAll);
        p.rules.push(rule(
            Action::Allow,
            "api.example.com",
            Origin::Kit("k".into()),
        ));
        assert_eq!(
            p.evaluate("s", &r("api.example.com", 443)),
            Decision::Allow(Reason::AllowRule(0))
        );
    }

    #[test]
    fn sandbox_scoped_deny_only_hits_that_sandbox() {
        let mut p = PolicySet::new(Preset::Balanced);
        p.rules.push(rule(
            Action::Deny,
            "github.com",
            Origin::Sandbox("a".into()),
        ));
        assert!(!p.evaluate("a", &r("github.com", 443)).is_allow());
        assert!(p.evaluate("b", &r("github.com", 443)).is_allow());
    }

    #[test]
    fn governance_ignores_local_kit_and_baseline_allows() {
        let mut p = PolicySet::new(Preset::Balanced);
        p.governance = Some(Governance {
            org: "acme".into(),
            support_message: Some("ask #it".into()),
        });
        p.rules.push(rule(Action::Allow, "x.com", Origin::Local));
        p.rules
            .push(rule(Action::Allow, "x.com", Origin::Kit("k".into())));
        p.rules.push(rule(Action::Allow, "ok.com", Origin::Org));
        let d = p.evaluate("s", &r("x.com", 443));
        assert_eq!(d, Decision::Deny(Reason::OrgPolicy));
        assert_eq!(
            p.block_message(&d).unwrap(),
            "Blocked by org policy. ask #it"
        );
        // baseline host is blocked too, and never "needs approval" under governance
        assert_eq!(
            p.evaluate("s", &r("api.anthropic.com", 443)),
            Decision::Deny(Reason::OrgPolicy)
        );
        assert!(p.evaluate("s", &r("ok.com", 443)).is_allow());
    }

    #[test]
    fn governance_still_honours_local_deny() {
        let mut p = PolicySet::new(Preset::Balanced);
        p.governance = Some(Governance {
            org: "acme".into(),
            support_message: None,
        });
        p.rules.push(rule(Action::Allow, "ok.com", Origin::Org));
        p.rules.push(rule(Action::Deny, "ok.com", Origin::Local));
        assert_eq!(
            p.evaluate("s", &r("ok.com", 443)),
            Decision::Deny(Reason::DenyRule(1))
        );
    }

    #[test]
    fn http_constrained_rules_require_inspection() {
        use crate::rule::HttpMatch;
        let mut p = PolicySet::new(Preset::DenyAll);
        let mut r = rule(Action::Allow, "api.example.com", Origin::Local);
        r.http = Some(HttpMatch {
            methods: vec!["GET".into()],
            ..Default::default()
        });
        p.rules.push(r);
        p.rules
            .push(rule(Action::Allow, "plain.example.com", Origin::Local));
        assert!(p.needs_http_inspection("s", "api.example.com", 443));
        assert!(!p.needs_http_inspection("s", "plain.example.com", 443));
        assert!(!p.needs_http_inspection("s", "other.com", 443));
    }

    #[test]
    fn allow_all_wildcard_rule_opens_every_port() {
        let mut p = PolicySet::new(Preset::DenyAll);
        p.rules.push(rule(Action::Allow, "**", Origin::Local));
        assert!(p.evaluate("s", &r("anything", 5432)).is_allow());
    }
}
