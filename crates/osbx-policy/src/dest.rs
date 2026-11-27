//! Destination syntax: hostname patterns, IPs, CIDRs, optional port.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Error parsing a destination string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ParseError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError(msg.into()))
}

/// The host part of a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSpec {
    /// `**` on its own: every host (and, see [`Destination::matches`], every port).
    Any,
    /// A (possibly wildcarded) DNS name, lowercase, without trailing dot.
    Pattern(Vec<String>),
    /// A single IP address.
    Ip(IpAddr),
    /// A CIDR block.
    Cidr(IpAddr, u8),
}

/// A destination: host spec plus optional port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Host matcher.
    pub host: HostSpec,
    /// Explicit port, if any.
    pub port: Option<u16>,
}

/// ASSUMPTION: a rule without an explicit port covers only the web ports 80 and 443
/// (so `allow github.com` does not open `github.com:22`). The one exception is the
/// bare `**` rule, documented as "allow all outbound TCP", which covers every port.
pub const DEFAULT_PORTS: [u16; 2] = [80, 443];

impl Destination {
    /// Does this destination cover a connection to `host` (name) / `ip` on `port`?
    pub fn matches(&self, host: &str, ip: Option<IpAddr>, port: u16) -> bool {
        let port_ok = match (self.port, &self.host) {
            (Some(p), _) => p == port,
            (None, HostSpec::Any) => true,
            (None, _) => DEFAULT_PORTS.contains(&port),
        };
        if !port_ok {
            return false;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let ip = ip.or_else(|| host.parse().ok());
        match &self.host {
            HostSpec::Any => true,
            HostSpec::Pattern(p) => {
                let labels: Vec<&str> = host.split('.').collect();
                labels_match(p, &labels)
            }
            HostSpec::Ip(want) => ip == Some(*want),
            HostSpec::Cidr(net, bits) => ip.is_some_and(|ip| cidr_contains(*net, *bits, ip)),
        }
    }
}

/// ASSUMPTION: `*` as a whole label matches exactly one label (`*.googleapis.com`
/// matches `storage.googleapis.com` but not `a.b.googleapis.com`), `**` as a whole
/// label matches one or more labels, and `*` inside a label matches any characters
/// within that label.
fn labels_match(pat: &[String], host: &[&str]) -> bool {
    match pat.split_first() {
        None => host.is_empty(),
        Some((p, rest)) if p == "**" => {
            // one or more labels
            (1..=host.len()).any(|n| labels_match(rest, &host[n..]))
        }
        Some((p, rest)) => match host.split_first() {
            Some((h, hrest)) => glob(p, h) && labels_match(rest, hrest),
            None => false,
        },
    }
}

fn glob(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

fn cidr_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

impl FromStr for Destination {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        if s.is_empty() {
            return err("empty destination");
        }
        // [v6]:port or [v6]
        if let Some(rest) = s.strip_prefix('[') {
            let (addr, tail) = rest
                .split_once(']')
                .ok_or(ParseError("unclosed '['".into()))?;
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| ParseError(format!("bad IPv6: {addr}")))?;
            let port = match tail {
                "" => None,
                t => Some(parse_port(
                    t.strip_prefix(':')
                        .ok_or(ParseError("junk after ']'".into()))?,
                )?),
            };
            return Ok(Self {
                host: HostSpec::Ip(ip),
                port,
            });
        }
        // CIDR (no port allowed)
        if let Some((net, bits)) = s.split_once('/') {
            let net: IpAddr = net
                .parse()
                .map_err(|_| ParseError(format!("bad CIDR address: {net}")))?;
            let bits: u8 = bits
                .parse()
                .map_err(|_| ParseError(format!("bad prefix length: {bits}")))?;
            let max = if net.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return err(format!("prefix length {bits} > {max}"));
            }
            return Ok(Self {
                host: HostSpec::Cidr(net, bits),
                port: None,
            });
        }
        // bare IPv6 (several colons, no brackets)
        if s.matches(':').count() > 1 {
            let ip: IpAddr = s
                .parse()
                .map_err(|_| ParseError(format!("bad IPv6: {s}")))?;
            return Ok(Self {
                host: HostSpec::Ip(ip),
                port: None,
            });
        }
        let (host, port) = match s.split_once(':') {
            Some((h, p)) => (h, Some(parse_port(p)?)),
            None => (s, None),
        };
        if host == "**" {
            return Ok(Self {
                host: HostSpec::Any,
                port,
            });
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Self {
                host: HostSpec::Ip(ip),
                port,
            });
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return err("empty host");
        }
        let labels: Vec<String> = host.split('.').map(str::to_owned).collect();
        for l in &labels {
            if l.is_empty() {
                return err(format!("empty label in {host}"));
            }
            if l == "**" {
                continue;
            }
            if l.contains("**")
                || !l
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_*".contains(&b))
            {
                return err(format!("invalid label {l:?} in {host}"));
            }
        }
        Ok(Self {
            host: HostSpec::Pattern(labels),
            port,
        })
    }
}

fn parse_port(p: &str) -> Result<u16, ParseError> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => err(format!("bad port: {p}")),
        Ok(n) => Ok(n),
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            HostSpec::Any => f.write_str("**")?,
            HostSpec::Pattern(l) => f.write_str(&l.join("."))?,
            HostSpec::Ip(ip @ IpAddr::V6(_)) if self.port.is_some() => write!(f, "[{ip}]")?,
            HostSpec::Ip(ip) => write!(f, "{ip}")?,
            HostSpec::Cidr(n, b) => write!(f, "{n}/{b}")?,
        }
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Destination {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_roundtrips() {
        for s in [
            "api.github.com",
            "myhost:22",
            "*.googleapis.com",
            "**",
            "10.0.0.0/8",
            "[::1]:22",
            "1.2.3.4:8080",
            "**.example.com",
        ] {
            assert_eq!(d(s).to_string(), s);
        }
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "",
            "a..b",
            "host:0",
            "host:99999",
            "10.0.0.0/33",
            "[::1",
            "a b",
            "x**y.com",
        ] {
            assert!(s.parse::<Destination>().is_err(), "{s}");
        }
    }

    #[test]
    fn single_star_is_one_label() {
        let g = d("*.googleapis.com");
        assert!(g.matches("storage.googleapis.com", None, 443));
        assert!(!g.matches("a.b.googleapis.com", None, 443));
        assert!(!g.matches("googleapis.com", None, 443));
    }

    #[test]
    fn double_star_is_one_or_more_labels() {
        let g = d("**.googleapis.com");
        assert!(g.matches("storage.googleapis.com", None, 443));
        assert!(g.matches("a.b.googleapis.com", None, 443));
        assert!(!g.matches("googleapis.com", None, 443));
    }

    #[test]
    fn matching_is_case_insensitive_and_ignores_trailing_dot() {
        assert!(d("GitHub.com").matches("github.COM.", None, 443));
    }

    #[test]
    fn portless_rule_covers_only_web_ports() {
        let g = d("github.com");
        assert!(g.matches("github.com", None, 80));
        assert!(g.matches("github.com", None, 443));
        assert!(!g.matches("github.com", None, 22));
        assert!(d("github.com:22").matches("github.com", None, 22));
        assert!(!d("github.com:22").matches("github.com", None, 443));
    }

    #[test]
    fn bare_double_star_covers_everything() {
        assert!(d("**").matches("anything.example", None, 5432));
    }

    #[test]
    fn ip_and_cidr() {
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(d("10.0.0.0/8").matches("10.1.2.3", Some(ip), 443));
        assert!(d("10.1.2.3").matches("whatever", Some(ip), 80));
        assert!(!d("192.168.0.0/16").matches("10.1.2.3", Some(ip), 443));
        // a hostname rule never matches a bare IP and vice versa
        assert!(!d("example.com").matches("10.1.2.3", Some(ip), 443));
        let v6: IpAddr = "::1".parse().unwrap();
        assert!(d("[::1]:22").matches("::1", Some(v6), 22));
        assert!(d("::/0").matches("::1", Some(v6), 80));
        assert!(!d("0.0.0.0/0").matches("::1", Some(v6), 80));
    }
}
