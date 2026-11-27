//! Kit-set resolution (spec §5.3) and capability selection (spec §7.1.1, §7.1.2).

use crate::descriptor::{CapabilityItem, Descriptor, Kind};
use crate::version::{Provide, Requirement, normalize_name};
use std::collections::{BTreeMap, BTreeSet};

/// A kit as handed to the resolver.
#[derive(Debug, Clone)]
pub struct KitInput {
    /// The reference the kit is consumed by (identity; used for ordering and diagnostics).
    pub reference: String,
    /// Version carried by that reference (OCI tag, git ref), if any.
    pub ref_version: Option<String>,
    /// Published (or effective) descriptor.
    pub descriptor: Descriptor,
}

/// Why resolution failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No `workload` in the set.
    NoWorkload,
    /// More than one `workload`.
    MultipleWorkloads(Vec<String>),
    /// `kind: set` reached the resolver (authoring-only).
    SetKind(String),
    /// A descriptor entry failed to parse.
    Malformed {
        /// Offending kit reference.
        kit: String,
        /// Detail.
        message: String,
    },
    /// Two kits provide one normalized name.
    DuplicateProvider {
        /// Capability name.
        name: String,
        /// The two kit references.
        kits: (String, String),
    },
    /// A `requires` is not met by any other kit in the set.
    UnmetRequire {
        /// Requiring kit.
        kit: String,
        /// The requirement text.
        requirement: String,
    },
    /// A `conflicts` name is provided by the set.
    Conflict {
        /// Declaring kit.
        kit: String,
        /// Provided name.
        name: String,
    },
    /// A present provider violates an `integrates` constraint.
    IntegrateViolation {
        /// Declaring kit.
        kit: String,
        /// The constraint text.
        requirement: String,
    },
    /// Dependency cycle among these kits.
    Cycle(Vec<String>),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ResolveError {}

/// Effective provides of a kit. ASSUMPTION: an unversioned provide takes the consumption
/// reference's version, else the descriptor's fallback `version` (spec §4).
fn provides_of(k: &KitInput) -> Result<Vec<Provide>, ResolveError> {
    let fallback = k.ref_version.as_deref().or(k.descriptor.version.as_deref());
    k.descriptor
        .provides
        .iter()
        .map(|p| {
            let mut pv = Provide::parse(p).map_err(|message| ResolveError::Malformed {
                kit: k.reference.clone(),
                message,
            })?;
            if pv.version.is_none()
                && let Some(v) = fallback
            {
                pv.version = crate::Version::parse(v).ok();
            }
            Ok(pv)
        })
        .collect()
}

/// Resolve a closed set: validates the composition and returns kit indices in dependency
/// order (providers before requirers). Ties break on the reference string, so the result
/// never depends on the order the kits were passed in.
pub fn resolve(kits: &[KitInput]) -> Result<Vec<usize>, Vec<ResolveError>> {
    let mut errs = Vec::new();
    let workloads: Vec<&str> = kits
        .iter()
        .filter(|k| matches!(k.descriptor.kind, Kind::Workload | Kind::Sandbox))
        .map(|k| k.reference.as_str())
        .collect();
    match workloads.len() {
        0 => errs.push(ResolveError::NoWorkload),
        1 => {}
        _ => errs.push(ResolveError::MultipleWorkloads(
            workloads.iter().map(|s| (*s).to_owned()).collect(),
        )),
    }
    for k in kits {
        if k.descriptor.kind == Kind::Set {
            errs.push(ResolveError::SetKind(k.reference.clone()));
        }
    }

    // provider table
    let mut provided: Vec<Vec<Provide>> = Vec::new();
    let mut owner: BTreeMap<String, usize> = BTreeMap::new();
    for (i, k) in kits.iter().enumerate() {
        match provides_of(k) {
            Ok(ps) => {
                for p in &ps {
                    if let Some(&j) = owner.get(&p.name) {
                        errs.push(ResolveError::DuplicateProvider {
                            name: p.name.clone(),
                            kits: (kits[j].reference.clone(), k.reference.clone()),
                        });
                    } else {
                        owner.insert(p.name.clone(), i);
                    }
                }
                provided.push(ps);
            }
            Err(e) => {
                errs.push(e);
                provided.push(Vec::new());
            }
        }
    }

    // edges: provider -> requirer
    let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (i, k) in kits.iter().enumerate() {
        let d = &k.descriptor;
        for r in &d.requires {
            match Requirement::parse(r) {
                Err(message) => errs.push(ResolveError::Malformed {
                    kit: k.reference.clone(),
                    message,
                }),
                Ok(req) => {
                    let hit = (0..kits.len())
                        .find(|&j| j != i && provided[j].iter().any(|p| req.satisfied_by(p)));
                    match hit {
                        Some(j) => {
                            edges.insert((j, i));
                        }
                        None => errs.push(ResolveError::UnmetRequire {
                            kit: k.reference.clone(),
                            requirement: r.clone(),
                        }),
                    }
                }
            }
        }
        for r in &d.integrates {
            match Requirement::parse(r) {
                Err(message) => errs.push(ResolveError::Malformed {
                    kit: k.reference.clone(),
                    message,
                }),
                Ok(req) => {
                    if let Some(&j) = owner.get(&req.name)
                        && j != i
                    {
                        if provided[j].iter().any(|p| req.satisfied_by(p)) {
                            edges.insert((j, i));
                        } else {
                            errs.push(ResolveError::IntegrateViolation {
                                kit: k.reference.clone(),
                                requirement: r.clone(),
                            });
                        }
                    }
                }
            }
        }
        for n in &d.conflicts {
            let name = normalize_name(n);
            if owner.get(&name).is_some_and(|&j| j != i) {
                errs.push(ResolveError::Conflict {
                    kit: k.reference.clone(),
                    name,
                });
            }
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }

    // Kahn's algorithm with a deterministic tie-break on reference
    let mut indeg = vec![0usize; kits.len()];
    for &(_, to) in &edges {
        indeg[to] += 1;
    }
    let mut ready: BTreeSet<(&str, usize)> = (0..kits.len())
        .filter(|&i| indeg[i] == 0)
        .map(|i| (kits[i].reference.as_str(), i))
        .collect();
    let mut order = Vec::with_capacity(kits.len());
    while let Some(&(r, i)) = ready.iter().next() {
        ready.remove(&(r, i));
        order.push(i);
        for &(from, to) in edges.range((i, 0)..(i + 1, 0)) {
            debug_assert_eq!(from, i);
            indeg[to] -= 1;
            if indeg[to] == 0 {
                ready.insert((kits[to].reference.as_str(), to));
            }
        }
    }
    if order.len() != kits.len() {
        let stuck = (0..kits.len())
            .filter(|i| !order.contains(i))
            .map(|i| kits[i].reference.clone())
            .collect();
        return Err(vec![ResolveError::Cycle(stuck)]);
    }
    Ok(order)
}

/// Outcome of selecting one kit's capability requests against a host's support list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selection {
    /// Granted exact types, in declaration order (groups flattened at their position).
    pub granted: Vec<String>,
    /// Skipped optional requests/groups with the reason.
    pub skipped: Vec<(String, String)>,
}

/// Selection refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectError {
    /// The rejected exact type (the first one).
    pub ty: String,
    /// Why.
    pub message: String,
}

/// Select capability requests against `supported` exact types (spec §7.1.2: exact match,
/// no version ranking). An unsupported *required* ordinary request refuses; an unsupported
/// optional one is skipped and recorded. A group is granted only if every member is
/// supported; otherwise an optional group is skipped whole and a required one refuses.
pub fn select(d: &Descriptor, supported: &BTreeSet<String>) -> Result<Selection, SelectError> {
    let mut sel = Selection::default();
    for item in &d.capabilities {
        match item {
            CapabilityItem::Request(c) => {
                if supported.contains(&c.ty) {
                    sel.granted.push(c.ty.clone());
                } else if c.is_optional() {
                    sel.skipped
                        .push((c.ty.clone(), "unsupported by host".into()));
                } else {
                    return Err(SelectError {
                        ty: c.ty.clone(),
                        message: "required capability not supported by host".into(),
                    });
                }
            }
            CapabilityItem::Group(g) => {
                let missing: Vec<&str> = g
                    .capabilities
                    .iter()
                    .filter(|m| !supported.contains(&m.ty))
                    .map(|m| m.ty.as_str())
                    .collect();
                if missing.is_empty() {
                    sel.granted
                        .extend(g.capabilities.iter().map(|m| m.ty.clone()));
                } else if g.optional {
                    for m in &g.capabilities {
                        sel.skipped.push((
                            m.ty.clone(),
                            format!("group skipped: {} unsupported", missing.join(", ")),
                        ));
                    }
                } else {
                    return Err(SelectError {
                        ty: missing[0].to_owned(),
                        message: format!(
                            "required group has unsupported member(s): {}",
                            missing.join(", ")
                        ),
                    });
                }
            }
        }
    }
    Ok(sel)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kit(reference: &str, yaml: &str) -> KitInput {
        KitInput {
            reference: reference.into(),
            ref_version: None,
            descriptor: Descriptor::from_yaml(&format!("schemaVersion: \"3\"\n{yaml}")).unwrap(),
        }
    }
    fn sup(types: &[&str]) -> BTreeSet<String> {
        types
            .iter()
            .map(|t| format!("com.docker.sandbox/{t}"))
            .collect()
    }

    fn base() -> Vec<KitInput> {
        vec![
            kit(
                "reg/claude-mixin:1",
                "kind: mixin\nrequires: [\"claude >= 2.0\"]\n",
            ),
            kit(
                "reg/claude:2.1",
                "kind: workload\nprovides: [claude@2.1.0]\n",
            ),
            kit("reg/gh:1", "kind: mixin\nprovides: [gh@2.72.0]\n"),
        ]
    }

    #[test]
    fn orders_providers_before_requirers_independent_of_input_order() {
        let a = base();
        let mut b = base();
        b.reverse();
        let names = |ks: &[KitInput], o: Vec<usize>| {
            o.into_iter()
                .map(|i| ks[i].reference.clone())
                .collect::<Vec<_>>()
        };
        let oa = names(&a, resolve(&a).unwrap());
        let ob = names(&b, resolve(&b).unwrap());
        assert_eq!(oa, ob);
        let pos = |n: &str| oa.iter().position(|x| x == n).unwrap();
        assert!(pos("reg/claude:2.1") < pos("reg/claude-mixin:1"));
    }

    #[test]
    fn exactly_one_workload() {
        let none = vec![kit("a", "kind: mixin\n")];
        assert!(
            resolve(&none)
                .unwrap_err()
                .contains(&ResolveError::NoWorkload)
        );
        let two = vec![kit("a", "kind: workload\n"), kit("b", "kind: workload\n")];
        assert!(matches!(
            resolve(&two).unwrap_err()[0],
            ResolveError::MultipleWorkloads(_)
        ));
    }

    #[test]
    fn duplicate_provider_is_refused_at_any_version() {
        // composing claude with claude-mixin: both provide `claude`
        let ks = vec![
            kit("w", "kind: workload\nprovides: [claude@2.1.0]\n"),
            kit("m", "kind: mixin\nprovides: [claude@2.0.0]\n"),
        ];
        assert!(matches!(
            resolve(&ks).unwrap_err()[0],
            ResolveError::DuplicateProvider { .. }
        ));
    }

    #[test]
    fn closed_set_requires_and_versions() {
        let mut ks = base();
        ks.remove(1); // no provider of `claude`
        ks.push(kit("w", "kind: workload\n"));
        assert!(matches!(
            resolve(&ks).unwrap_err()[0],
            ResolveError::UnmetRequire { .. }
        ));
        // provider too old
        let old = vec![
            kit("w", "kind: workload\nprovides: [claude@1.9.0]\n"),
            kit("m", "kind: mixin\nrequires: [\"claude >= 2.0\"]\n"),
        ];
        assert!(matches!(
            resolve(&old).unwrap_err()[0],
            ResolveError::UnmetRequire { .. }
        ));
    }

    #[test]
    fn unversioned_provide_takes_reference_version() {
        let mut w = kit("w", "kind: workload\nprovides: [claude]\n");
        let m = kit("m", "kind: mixin\nrequires: [\"claude >= 2.0\"]\n");
        assert!(resolve(&[w.clone(), m.clone()]).is_err()); // unversioned never meets a constraint
        w.ref_version = Some("2.1.0".into());
        assert!(resolve(&[w, m]).is_ok());
    }

    #[test]
    fn conflicts_and_integrates() {
        let ks = vec![
            kit("w", "kind: workload\nprovides: [podman@5.0]\n"),
            kit("m", "kind: mixin\nconflicts: [podman]\n"),
        ];
        assert!(matches!(
            resolve(&ks).unwrap_err()[0],
            ResolveError::Conflict { .. }
        ));
        // integrates: absent provider is fine, violating present provider fails
        let absent = vec![
            kit("w", "kind: workload\n"),
            kit(
                "m",
                "kind: mixin\nintegrates: [\"docker-engine >= 25.0\"]\n",
            ),
        ];
        assert!(resolve(&absent).is_ok());
        let bad = vec![
            kit("w", "kind: workload\nprovides: [docker-engine@24.0]\n"),
            kit(
                "m",
                "kind: mixin\nintegrates: [\"docker-engine >= 25.0\"]\n",
            ),
        ];
        assert!(matches!(
            resolve(&bad).unwrap_err()[0],
            ResolveError::IntegrateViolation { .. }
        ));
        let good = vec![
            kit("w", "kind: workload\nprovides: [docker-engine@26.0]\n"),
            kit(
                "m",
                "kind: mixin\nintegrates: [\"docker-engine >= 25.0\"]\n",
            ),
        ];
        assert_eq!(resolve(&good).unwrap(), vec![0, 1]); // met integrates order like requires
    }

    #[test]
    fn cycles_are_detected() {
        let ks = vec![
            kit("w", "kind: workload\nprovides: [a@1]\nrequires: [b]\n"),
            kit("m", "kind: mixin\nprovides: [b@1]\nrequires: [a]\n"),
        ];
        assert!(matches!(
            resolve(&ks).unwrap_err()[0],
            ResolveError::Cycle(_)
        ));
    }

    #[test]
    fn selection_exact_types_and_optionality() {
        let d = Descriptor::from_yaml(
            "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - type: com.docker.sandbox/network-policy@2\n    optional: true\n  - type: com.docker.sandbox/lifecycle@1\n",
        )
        .unwrap();
        // host supports only @1 of network-policy: optional @2 is skipped, never rewritten
        let s = select(&d, &sup(&["network-policy@1", "lifecycle@1"])).unwrap();
        assert_eq!(s.granted, vec!["com.docker.sandbox/lifecycle@1"]);
        assert_eq!(s.skipped.len(), 1);
        // unsupported required type refuses by name
        let e = select(&d, &sup(&["network-policy@2"])).unwrap_err();
        assert_eq!(e.ty, "com.docker.sandbox/lifecycle@1");
    }

    #[test]
    fn groups_are_atomic() {
        let d = Descriptor::from_yaml(
            "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - group:\n      optional: true\n      capabilities:\n        - type: com.docker.sandbox/agent-skills@1\n          config: {path: /s, mode: readonly}\n        - type: com.docker.sandbox/lifecycle@1\n",
        )
        .unwrap();
        // one member unsupported: the whole optional group is skipped, nothing partially granted
        let s = select(&d, &sup(&["lifecycle@1"])).unwrap();
        assert!(s.granted.is_empty());
        assert_eq!(s.skipped.len(), 2);
        let all = select(&d, &sup(&["lifecycle@1", "agent-skills@1"])).unwrap();
        assert_eq!(all.granted.len(), 2);
        // required group with an unsupported member refuses
        let req = Descriptor::from_yaml(
            "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - group:\n      capabilities:\n        - type: com.docker.sandbox/lifecycle@1\n        - type: com.docker.sandbox/kvm@1\n",
        )
        .unwrap();
        assert!(select(&req, &sup(&["lifecycle@1"])).is_err());
    }
}
