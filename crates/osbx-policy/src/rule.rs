//! Rules and the requests they are matched against.

use crate::dest::Destination;
use std::net::IpAddr;

/// Allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Grant access.
    Allow,
    /// Refuse access; overrides every allow.
    Deny,
}

/// Where a rule came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Added with the CLI (`sbx policy allow/deny`-style), global.
    Local,
    /// Added with the CLI, scoped to one sandbox.
    Sandbox(String),
    /// Declared by a kit (network-policy capability).
    Kit(String),
    /// Organization governance.
    Org,
}

/// Extra matching for HTTP(S) requests (visible to the MITM proxy).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpMatch {
    /// Allowed methods (empty = any), compared case-insensitively.
    pub methods: Vec<String>,
    /// Path glob (`*` = any characters incl. `/`), ASCII case-insensitive. `None` = any.
    pub path: Option<String>,
    /// Required query parameters, all must be present with equal value (ASCII case-insensitive).
    pub query: Vec<(String, String)>,
}

/// The HTTP part of a request, when the proxy can see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    /// Method, e.g. `GET`.
    pub method: &'a str,
    /// Path without query string.
    pub path: &'a str,
    /// Decoded query pairs.
    pub query: Vec<(&'a str, &'a str)>,
}

/// An outbound connection attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// Name the sandbox asked for (SNI / Host / CONNECT target).
    pub host: &'a str,
    /// Resolved or literal IP, if known.
    pub ip: Option<IpAddr>,
    /// Destination TCP port.
    pub port: u16,
    /// HTTP details if available.
    pub http: Option<HttpRequest<'a>>,
}

/// A single policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Allow or deny.
    pub action: Action,
    /// Where it applies.
    pub dest: Destination,
    /// Optional HTTP constraints. ASSUMPTION: a rule with HTTP constraints never matches
    /// a request whose HTTP layer is not visible (plain TCP).
    pub http: Option<HttpMatch>,
    /// Provenance.
    pub origin: Origin,
}

impl Rule {
    /// Convenience constructor without HTTP constraints.
    pub fn new(action: Action, dest: &str, origin: Origin) -> Result<Self, crate::ParseError> {
        Ok(Self {
            action,
            dest: dest.parse()?,
            http: None,
            origin,
        })
    }

    /// Does the rule apply to `req` for the sandbox called `sandbox`?
    pub fn matches(&self, sandbox: &str, req: &Request<'_>) -> bool {
        if let Origin::Sandbox(s) = &self.origin
            && s != sandbox
        {
            return false;
        }
        if !self.dest.matches(req.host, req.ip, req.port) {
            return false;
        }
        match (&self.http, &req.http) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(m), Some(h)) => http_matches(m, h),
        }
    }
}

fn http_matches(m: &HttpMatch, h: &HttpRequest<'_>) -> bool {
    if !m.methods.is_empty() && !m.methods.iter().any(|x| x.eq_ignore_ascii_case(h.method)) {
        return false;
    }
    if let Some(p) = &m.path
        && !path_glob(&p.to_ascii_lowercase(), &h.path.to_ascii_lowercase())
    {
        return false;
    }
    m.query.iter().all(|(k, v)| {
        h.query
            .iter()
            .any(|(hk, hv)| hk.eq_ignore_ascii_case(k) && hv.eq_ignore_ascii_case(v))
    })
}

fn path_glob(pat: &str, s: &str) -> bool {
    match pat.split_once('*') {
        None => pat == s,
        Some((head, tail)) => {
            let Some(rest) = s.strip_prefix(head) else {
                return false;
            };
            if tail.is_empty() {
                return true;
            }
            (0..=rest.len()).any(|i| rest.is_char_boundary(i) && path_glob(tail, &rest[i..]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(host: &'a str, port: u16, http: Option<HttpRequest<'a>>) -> Request<'a> {
        Request {
            host,
            ip: None,
            port,
            http,
        }
    }

    #[test]
    fn sandbox_scope() {
        let r = Rule::new(Action::Allow, "x.com", Origin::Sandbox("a".into())).unwrap();
        assert!(r.matches("a", &req("x.com", 443, None)));
        assert!(!r.matches("b", &req("x.com", 443, None)));
    }

    #[test]
    fn http_constraints() {
        let mut r = Rule::new(Action::Allow, "api.example.com", Origin::Local).unwrap();
        r.http = Some(HttpMatch {
            methods: vec!["get".into()],
            path: Some("/v1/*".into()),
            query: vec![("Mode".into(), "Read".into())],
        });
        let ok = HttpRequest {
            method: "GET",
            path: "/V1/models",
            query: vec![("mode", "read")],
        };
        assert!(r.matches("s", &req("api.example.com", 443, Some(ok))));
        let bad_method = HttpRequest {
            method: "POST",
            path: "/v1/x",
            query: vec![("mode", "read")],
        };
        assert!(!r.matches("s", &req("api.example.com", 443, Some(bad_method))));
        let bad_path = HttpRequest {
            method: "GET",
            path: "/v2/x",
            query: vec![("mode", "read")],
        };
        assert!(!r.matches("s", &req("api.example.com", 443, Some(bad_path))));
        let bad_query = HttpRequest {
            method: "GET",
            path: "/v1/x",
            query: vec![],
        };
        assert!(!r.matches("s", &req("api.example.com", 443, Some(bad_query))));
        // no visible HTTP layer: constrained rule does not match
        assert!(!r.matches("s", &req("api.example.com", 443, None)));
    }

    #[test]
    fn path_glob_cases() {
        assert!(path_glob("/a/*/c", "/a/b/c"));
        assert!(path_glob("/a/*", "/a/"));
        assert!(!path_glob("/a/*/c", "/a/b/d"));
        assert!(path_glob("*", "/anything"));
    }
}
