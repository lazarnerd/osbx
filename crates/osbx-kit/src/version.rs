//! Capability names, versions and `requires`-style constraints (spec §5).

use std::cmp::Ordering;
use std::fmt;

/// Namespace bare names normalize into (spec §5.1).
pub const DEFAULT_NAMESPACE: &str = "com.docker.kit";
/// Namespaces only publishing may write (spec §5.1).
pub const RESERVED_NAMESPACES: [&str; 2] = ["deb", "apk"];

/// Normalize a capability name: bare `gh` becomes `com.docker.kit/gh`.
pub fn normalize_name(name: &str) -> String {
    if name.contains('/') {
        name.to_owned()
    } else {
        format!("{DEFAULT_NAMESPACE}/{name}")
    }
}

/// Validate a capability name per spec §5.1.
pub fn validate_name(name: &str) -> Result<(), String> {
    let (ns, base) = match name.split_once('/') {
        Some((ns, base)) => (Some(ns), base),
        None => (None, name),
    };
    if let Some(ns) = ns
        && !RESERVED_NAMESPACES.contains(&ns)
        && !is_reverse_dns(ns)
    {
        return Err(format!(
            "namespace {ns:?} must be reverse-DNS (two or more domain labels)"
        ));
    }
    let ok = !base.is_empty()
        && base.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !base.ends_with(['-', '.'])
        && base
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-.+".contains(c));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid capability name {base:?}"))
    }
}

fn is_reverse_dns(ns: &str) -> bool {
    ns.len() <= 253
        && ns.split('.').count() >= 2
        && ns.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.starts_with(|c: char| c.is_ascii_alphanumeric())
                && l.ends_with(|c: char| c.is_ascii_alphanumeric())
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// A dotted version, `[0-9]+(\.[0-9A-Za-z-]+)*`, no `v` prefix.
#[derive(Debug, Clone)]
pub struct Version(Vec<String>);

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Version {}

impl Version {
    /// Parse; rejects `v1.2`, empty segments, etc.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut parts = s.split('.');
        let first = parts.next().unwrap_or("");
        if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("invalid version {s:?}"));
        }
        let mut segs = vec![first.to_owned()];
        for p in parts {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(format!("invalid version {s:?}"));
            }
            segs.push(p.to_owned());
        }
        Ok(Self(segs))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

impl Ord for Version {
    /// ASSUMPTION: a missing trailing segment compares as `0` (`1.2 == 1.2.0`), and a
    /// numeric segment sorts before a non-numeric one. The spec only says numeric
    /// segments compare numerically and the rest lexically.
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let a = self.0.get(i).map_or("0", String::as_str);
            let b = other.0.get(i).map_or("0", String::as_str);
            let ord = match (a.parse::<u128>(), b.parse::<u128>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b),
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Comparison operator in a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `>=`
    Ge,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `<`
    Lt,
    /// `=`
    Eq,
}

impl Op {
    fn holds(self, have: &Version, want: &Version) -> bool {
        let o = have.cmp(want);
        match self {
            Self::Ge => o != Ordering::Less,
            Self::Gt => o == Ordering::Greater,
            Self::Le => o != Ordering::Greater,
            Self::Lt => o == Ordering::Less,
            Self::Eq => o == Ordering::Equal,
        }
    }
}

/// An offered capability: `name` or `name@version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provide {
    /// Normalized name.
    pub name: String,
    /// Version, if stated.
    pub version: Option<Version>,
}

impl Provide {
    /// Parse a `provides` entry (arg references must already be expanded).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (name, ver) = match s.split_once('@') {
            Some((n, v)) => (n, Some(Version::parse(v)?)),
            None => (s, None),
        };
        validate_name(name)?;
        Ok(Self {
            name: normalize_name(name),
            version: ver,
        })
    }
}

/// A `requires`/`integrates` entry: a name plus ANDed constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// Normalized name.
    pub name: String,
    /// Constraints, all must hold.
    pub constraints: Vec<(Op, Version)>,
}

impl Requirement {
    /// Parse `name`, `name >= 1.0` or `name >= 1.0, < 2.0`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut pieces = s.split(',').map(str::trim);
        let first = pieces
            .next()
            .filter(|p| !p.is_empty())
            .ok_or("empty requirement")?;
        let (name, first_c) = match first.split_once(char::is_whitespace) {
            Some((n, rest)) => (n, Some(rest.trim())),
            None => (first, None),
        };
        validate_name(name)?;
        let mut constraints = Vec::new();
        for c in first_c.into_iter().chain(pieces) {
            constraints.push(parse_constraint(c)?);
        }
        check_satisfiable(&constraints)?;
        Ok(Self {
            name: normalize_name(name),
            constraints,
        })
    }

    /// Does `p` satisfy this requirement? An unversioned provide satisfies only an
    /// unconstrained requirement (spec §5.2).
    pub fn satisfied_by(&self, p: &Provide) -> bool {
        if p.name != self.name {
            return false;
        }
        match &p.version {
            None => self.constraints.is_empty(),
            Some(v) => self.constraints.iter().all(|(op, want)| op.holds(v, want)),
        }
    }
}

fn parse_constraint(c: &str) -> Result<(Op, Version), String> {
    for (tok, op) in [
        (">=", Op::Ge),
        ("<=", Op::Le),
        (">", Op::Gt),
        ("<", Op::Lt),
        ("=", Op::Eq),
    ] {
        if let Some(v) = c.strip_prefix(tok) {
            return Ok((op, Version::parse(v.trim())?));
        }
    }
    Err(format!(
        "bad constraint {c:?}: expected >=, >, <=, < or = followed by a version"
    ))
}

/// Reject constraint sets no version can satisfy (conflicting pins, inverted or
/// exclusively-touching bounds).
fn check_satisfiable(cs: &[(Op, Version)]) -> Result<(), String> {
    let mut lo: Option<(&Version, bool)> = None; // (bound, inclusive)
    let mut hi: Option<(&Version, bool)> = None;
    let mut pin: Option<&Version> = None;
    for (op, v) in cs {
        match op {
            Op::Eq => {
                if pin.is_some_and(|p| p != v) {
                    return Err("conflicting version pins".into());
                }
                pin = Some(v);
            }
            Op::Ge | Op::Gt => {
                let incl = *op == Op::Ge;
                if lo.is_none_or(|(b, bi)| v > b || (v == b && bi && !incl)) {
                    lo = Some((v, incl));
                }
            }
            Op::Le | Op::Lt => {
                let incl = *op == Op::Le;
                if hi.is_none_or(|(b, bi)| v < b || (v == b && bi && !incl)) {
                    hi = Some((v, incl));
                }
            }
        }
    }
    if let (Some((l, li)), Some((h, hi_incl))) = (lo, hi)
        && (l > h || (l == h && !(li && hi_incl)))
    {
        return Err("unsatisfiable version range".into());
    }
    if let Some(p) = pin {
        let ok_lo = lo.is_none_or(|(l, i)| if i { p >= l } else { p > l });
        let ok_hi = hi.is_none_or(|(h, i)| if i { p <= h } else { p < h });
        if !(ok_lo && ok_hi) {
            return Err("version pin outside the stated range".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(normalize_name("gh"), "com.docker.kit/gh");
        assert_eq!(normalize_name("com.example/gh"), "com.example/gh");
        assert!(validate_name("com.example/gh").is_ok());
        assert!(validate_name("deb/libstdc++6").is_ok());
        assert!(validate_name("example/gh").is_err()); // single label is reserved space
        assert!(validate_name("com..example/gh").is_err());
        assert!(validate_name("Gh").is_err());
        assert!(validate_name("gh-").is_err());
    }

    #[test]
    fn version_order() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("1.10.0") > v("1.9.9"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert!(v("1.2.0") < v("1.2.0.rc1"));
        assert!(Version::parse("v1.2").is_err());
        assert!(Version::parse("1..2").is_err());
    }

    #[test]
    fn requirement_satisfaction() {
        let r = Requirement::parse("node >= 20.0.0, < 21.0.0").unwrap();
        assert!(r.satisfied_by(&Provide::parse("node@20.5.1").unwrap()));
        assert!(!r.satisfied_by(&Provide::parse("node@21.0.0").unwrap()));
        assert!(!r.satisfied_by(&Provide::parse("node").unwrap())); // unversioned never meets a constraint
        assert!(
            Requirement::parse("node")
                .unwrap()
                .satisfied_by(&Provide::parse("node").unwrap())
        );
        assert!(!r.satisfied_by(&Provide::parse("nodejs@20.0.0").unwrap()));
    }

    #[test]
    fn unsatisfiable_sets_rejected() {
        for s in [
            "a = 1.0, = 2.0",
            "a >= 2.0, < 1.0",
            "a > 1.0, < 1.0",
            "a >= 1.0, < 1.0",
            "a = 3.0, < 2.0",
        ] {
            assert!(Requirement::parse(s).is_err(), "{s}");
        }
        assert!(Requirement::parse("a >= 1.0, <= 1.0").is_ok());
        assert!(Requirement::parse("a = 1.0, >= 1.0").is_ok());
    }
}
