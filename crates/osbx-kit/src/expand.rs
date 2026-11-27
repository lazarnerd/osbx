//! Create-phase expansion of `${{ kit.args.* }}` and `${{ kit.env.* }}` (spec §6, §6.1).
//!
//! Expansion is *structural*: it substitutes into the decoded document (every string
//! value and, for args, every map key) and never into serialized bytes, so a value is
//! carried verbatim whatever it contains.

use crate::descriptor::Arg;
use regex::Regex;
use serde_yaml_ng::{Mapping, Number, Value};
use std::collections::BTreeMap;
use std::sync::LazyLock;

static REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{\{\s*kit\.(args|env)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").unwrap()
});

/// Expansion failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandError(pub String);
impl std::fmt::Display for ExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ExpandError {}

fn bad<T>(m: impl Into<String>) -> Result<T, ExpandError> {
    Err(ExpandError(m.into()))
}

/// Resolve every declared arg to a value: supplied, else default, else error if required.
/// Rejects undeclared supplied names and values failing `enum`/`pattern`.
pub fn resolve_args(
    declared: &BTreeMap<String, Arg>,
    supplied: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ExpandError> {
    for name in supplied.keys() {
        if !declared.contains_key(name) {
            return bad(format!("supplied arg {name:?} is not declared by the kit"));
        }
    }
    let mut out = BTreeMap::new();
    for (name, a) in declared {
        let value = match (supplied.get(name), &a.default) {
            (Some(v), _) => v.clone(),
            (None, Some(d)) => d.clone(),
            (None, None) if a.required == Some(true) => {
                return bad(format!("required arg {name:?} not supplied"));
            }
            (None, None) => continue,
        };
        if value.contains("${{") {
            return bad(format!(
                "arg {name:?}: values containing kit placeholders are refused"
            ));
        }
        if let Some(en) = &a.enum_values
            && !en.contains(&value)
        {
            return bad(format!("arg {name:?}: {value:?} not in {en:?}"));
        }
        if let Some(p) = &a.pattern {
            let re = Regex::new(&format!("^(?:{p})$"))
                .map_err(|e| ExpandError(format!("arg {name:?}: bad pattern: {e}")))?;
            if !re.is_match(&value) {
                return bad(format!("arg {name:?}: {value:?} does not match {p:?}"));
            }
        }
        out.insert(name.clone(), value);
    }
    Ok(out)
}

/// Expand a decoded descriptor document. `env` is the final container environment for
/// `kit.env` references (values only, never keys). The top-level `args` block is left
/// untouched.
pub fn expand(
    doc: &Value,
    args: &BTreeMap<String, String>,
    env: &BTreeMap<String, String>,
) -> Result<Value, ExpandError> {
    let Value::Mapping(top) = doc else {
        return bad("descriptor must be a mapping");
    };
    let mut out = Mapping::new();
    for (k, v) in top {
        if k.as_str() == Some("args") {
            out.insert(k.clone(), v.clone());
        } else {
            out.insert(k.clone(), walk(v, None, args, env)?);
        }
    }
    Ok(Value::Mapping(out))
}

fn walk(
    v: &Value,
    parent_key: Option<&str>,
    args: &BTreeMap<String, String>,
    env: &BTreeMap<String, String>,
) -> Result<Value, ExpandError> {
    match v {
        Value::String(s) => subst_value(s, parent_key, args, env),
        Value::Sequence(items) => items
            .iter()
            .map(|x| walk(x, parent_key, args, env))
            .collect::<Result<_, _>>()
            .map(Value::Sequence),
        Value::Mapping(m) => {
            let mut out = Mapping::new();
            for (k, x) in m {
                let key = match k {
                    // keys expand args only (never env) and always as text
                    Value::String(ks) => Value::String(subst_text(ks, args, None)?),
                    other => other.clone(),
                };
                let kname = key.as_str().map(str::to_owned);
                if out
                    .insert(key.clone(), walk(x, kname.as_deref(), args, env)?)
                    .is_some()
                {
                    return bad(format!("two keys expand onto {key:?}"));
                }
            }
            Ok(Value::Mapping(out))
        }
        other => Ok(other.clone()),
    }
}

fn lookup<'a>(
    kind: &str,
    name: &str,
    args: &'a BTreeMap<String, String>,
    env: Option<&'a BTreeMap<String, String>>,
) -> Result<&'a str, ExpandError> {
    let map = match (kind, env) {
        ("args", _) => Some(args),
        ("env", Some(e)) => Some(e),
        _ => None,
    };
    match map.and_then(|m| m.get(name)) {
        Some(v) => Ok(v),
        None => bad(format!(
            "kit.{kind}.{name} has no value (or is not allowed here)"
        )),
    }
}

fn subst_text(
    s: &str,
    args: &BTreeMap<String, String>,
    env: Option<&BTreeMap<String, String>>,
) -> Result<String, ExpandError> {
    let mut out = String::new();
    let mut last = 0;
    for m in REF.captures_iter(s) {
        let whole = m.get(0).unwrap();
        out.push_str(&s[last..whole.start()]);
        let v = lookup(&m[1], &m[2], args, env)?;
        if v.contains("${{") {
            return bad("inserted values are not templates: placeholders in a value are refused");
        }
        out.push_str(v);
        last = whole.end();
    }
    out.push_str(&s[last..]);
    Ok(out)
}

/// ASSUMPTION: a string that is exactly one *arg* reference adopts the type its spelling
/// names (integer, float, bool) only when the spelling round-trips; `size` and `mode`
/// keys stay text (spec §6). `kit.env` whole-value references always stay strings.
fn subst_value(
    s: &str,
    parent_key: Option<&str>,
    args: &BTreeMap<String, String>,
    env: &BTreeMap<String, String>,
) -> Result<Value, ExpandError> {
    if let Some(m) = REF.captures(s)
        && m.get(0).unwrap().as_str() == s
        && &m[1] == "args"
        && !matches!(parent_key, Some("size" | "mode"))
    {
        let v = lookup("args", &m[2], args, None)?;
        if v.contains("${{") {
            return bad("inserted values are not templates: placeholders in a value are refused");
        }
        return Ok(typed(v));
    }
    Ok(Value::String(subst_text(s, args, Some(env))?))
}

fn typed(v: &str) -> Value {
    if let Ok(i) = v.parse::<i64>()
        && i.to_string() == v
    {
        return Value::Number(Number::from(i));
    }
    if let Ok(f) = v.parse::<f64>()
        && f.is_finite()
        && f.to_string() == v
    {
        return Value::Number(Number::from(f));
    }
    match v {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::String(v.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn y(s: &str) -> Value {
        serde_yaml_ng::from_str(s).unwrap()
    }
    fn m(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn whole_value_adopts_round_trippable_type() {
        let doc = y(
            "a: ${{ kit.args.n }}\nb: ${{ kit.args.v }}\nc: ${{ kit.args.z }}\nd: ${{ kit.args.t }}\ne: \"x${{ kit.args.n }}\"\nf: {size: \"${{ kit.args.n }}\"}",
        );
        let a = m(&[("n", "8080"), ("v", "1.0"), ("z", "007"), ("t", "true")]);
        let out = expand(&doc, &a, &BTreeMap::new()).unwrap();
        assert_eq!(out["a"], Value::from(8080));
        assert_eq!(out["b"], Value::from("1.0")); // does not round-trip: stays text
        assert_eq!(out["c"], Value::from("007"));
        assert_eq!(out["d"], Value::from(true));
        assert_eq!(out["e"], Value::from("x8080")); // embedded: always text
        assert_eq!(out["f"]["size"], Value::from("8080")); // size/mode stay text
    }

    #[test]
    fn values_are_carried_verbatim() {
        let doc = y("a: \"${{ kit.args.v }}\"");
        let nasty = "q\"uote\\ back: [x] # not-a-comment\nnewline";
        let out = expand(&doc, &m(&[("v", nasty)]), &BTreeMap::new()).unwrap();
        assert_eq!(out["a"].as_str(), Some(nasty));
    }

    #[test]
    fn keys_expand_and_collisions_fail() {
        let doc = y("m: {\"${{ kit.args.a }}\": 1, \"${{ kit.args.b }}\": 2}");
        assert!(expand(&doc, &m(&[("a", "k"), ("b", "k")]), &BTreeMap::new()).is_err());
        let ok = expand(&doc, &m(&[("a", "k1"), ("b", "k2")]), &BTreeMap::new()).unwrap();
        assert_eq!(ok["m"]["k1"], Value::from(1));
    }

    #[test]
    fn args_block_is_not_expanded() {
        let doc = y("args: {a: {default: \"${{ kit.args.a }}\"}}\nx: ${{ kit.args.a }}");
        let out = expand(&doc, &m(&[("a", "1")]), &BTreeMap::new()).unwrap();
        assert_eq!(
            out["args"]["a"]["default"].as_str(),
            Some("${{ kit.args.a }}")
        );
    }

    #[test]
    fn env_refs_values_only_and_text() {
        let doc = y("a: ${{ kit.env.HOME }}\nb: {\"${{ kit.env.HOME }}\": 1}");
        let env = m(&[("HOME", "/home/agent")]);
        // env in a key is refused
        assert!(expand(&doc, &BTreeMap::new(), &env).is_err());
        let doc = y("a: ${{ kit.env.HOME }}\nn: ${{ kit.env.N }}");
        let out = expand(
            &doc,
            &BTreeMap::new(),
            &m(&[("HOME", "/home/agent"), ("N", "5")]),
        )
        .unwrap();
        assert_eq!(out["a"].as_str(), Some("/home/agent"));
        assert_eq!(out["n"].as_str(), Some("5")); // env stays a string
        assert!(expand(&doc, &BTreeMap::new(), &BTreeMap::new()).is_err()); // missing name
    }

    #[test]
    fn placeholders_in_values_are_refused() {
        let doc = y("a: ${{ kit.args.v }}");
        assert!(expand(&doc, &m(&[("v", "${{ kit.env.X }}")]), &m(&[("X", "1")])).is_err());
    }

    #[test]
    fn arg_resolution_rules() {
        let declared: BTreeMap<String, Arg> = serde_yaml_ng::from_str(
            "team: {required: true, enum: [alpha, beta]}\nport: {default: '80', pattern: '[0-9]+'}",
        )
        .unwrap();
        assert!(resolve_args(&declared, &m(&[])).is_err()); // required missing
        assert!(resolve_args(&declared, &m(&[("team", "gamma")])).is_err()); // enum
        assert!(resolve_args(&declared, &m(&[("team", "alpha"), ("port", "x")])).is_err()); // pattern
        assert!(resolve_args(&declared, &m(&[("team", "alpha"), ("nope", "1")])).is_err()); // undeclared
        let ok = resolve_args(&declared, &m(&[("team", "alpha")])).unwrap();
        assert_eq!(ok["port"], "80");
    }
}
