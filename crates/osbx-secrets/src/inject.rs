//! Outbound header rewriting: the proxy-side half of credential handling.

use osbx_policy::Destination;

/// How to present a credential to one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectRule {
    /// Host pattern (`api.github.com`, `*.example.com`).
    pub domain: String,
    /// Header to set (case-insensitive when replacing).
    pub header: String,
    /// Value template; `%s` is replaced by the secret.
    pub format: String,
    /// When set, present as HTTP Basic with this username and the secret as the password
    /// (`scheme: basic`); `header`/`format` are then ignored and `Authorization` is used.
    pub basic_user: Option<String>,
}

/// Rewrite `headers` for a request to `host`, replacing any existing header of the same
/// name (that is where the sandbox's sentinel sits). Returns whether a rule matched.
pub fn inject(
    rules: &[InjectRule],
    host: &str,
    secret: &str,
    headers: &mut Vec<(String, String)>,
) -> bool {
    let Some(rule) = rules.iter().find(|r| {
        r.domain
            .parse::<Destination>()
            .is_ok_and(|d| d.matches(host, None, 443))
    }) else {
        return false;
    };
    let (name, value) = match &rule.basic_user {
        Some(u) => (
            "Authorization".to_owned(),
            format!("Basic {}", base64(format!("{u}:{secret}").as_bytes())),
        ),
        None => (rule.header.clone(), rule.format.replace("%s", secret)),
    };
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
    headers.push((name, value));
    true
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(domain: &str, header: &str, format: &str) -> InjectRule {
        InjectRule {
            domain: domain.into(),
            header: header.into(),
            format: format.into(),
            basic_user: None,
        }
    }

    #[test]
    fn replaces_sentinel_header_case_insensitively() {
        let rules = [rule("api.github.com", "Authorization", "Bearer %s")];
        let mut h = vec![
            ("authorization".into(), "Bearer proxy-managed".into()),
            ("accept".into(), "*/*".into()),
        ];
        assert!(inject(&rules, "api.github.com", "ghp_real", &mut h));
        assert_eq!(h.len(), 2);
        assert!(h.contains(&("Authorization".to_owned(), "Bearer ghp_real".to_owned())));
        assert!(!h.iter().any(|(_, v)| v.contains("proxy-managed")));
    }

    #[test]
    fn only_matching_hosts_get_the_secret() {
        let rules = [rule("api.github.com", "Authorization", "Bearer %s")];
        let mut h = Vec::new();
        assert!(!inject(&rules, "evil.example", "ghp_real", &mut h));
        assert!(!inject(
            &rules,
            "api.github.com.evil.example",
            "ghp_real",
            &mut h
        ));
        assert!(h.is_empty());
    }

    #[test]
    fn basic_scheme() {
        let rules = [InjectRule {
            basic_user: Some("x-access-token".into()),
            ..rule("github.com", "", "")
        }];
        let mut h = Vec::new();
        assert!(inject(&rules, "github.com", "tok", &mut h));
        // base64("x-access-token:tok")
        assert_eq!(
            h[0],
            (
                "Authorization".to_owned(),
                "Basic eC1hY2Nlc3MtdG9rZW46dG9r".to_owned()
            )
        );
    }

    #[test]
    fn base64_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }
}
