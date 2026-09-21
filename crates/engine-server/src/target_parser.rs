#![forbid(unsafe_code)]

use crate::scope;

/// A resolved, validated scan target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTarget {
    pub ip: String,
    pub origin: String, // the original token that produced this IP
}

/// Errors from target parsing or scope validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    InvalidToken(String),
    OutOfScope(String),
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetError::InvalidToken(s) => write!(f, "Invalid target token: {}", s),
            TargetError::OutOfScope(s) => write!(f, "Out-of-scope target: {}", s),
        }
    }
}

/// Parse and scope-validate one or more target tokens.
/// Accepts: single IPv4, CIDR (expand up to /24 only), range (a.b.c.1-254).
/// Rejects the ENTIRE input if ANY resolved IP is out of scope.
/// `scope_patterns` comes from the case scope_allowlist; pass &[] for localhost-only.
pub fn parse_and_validate(
    tokens: &[&str],
    scope_patterns: &[String],
) -> Result<Vec<ScanTarget>, TargetError> {
    let mut targets: Vec<ScanTarget> = Vec::new();

    for &token in tokens {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        let resolved = resolve_token(token)?;
        for ip in resolved {
            if !scope::is_in_scope(&ip, scope_patterns) {
                return Err(TargetError::OutOfScope(ip));
            }
            targets.push(ScanTarget {
                ip,
                origin: token.to_string(),
            });
        }
    }

    Ok(targets)
}

/// Resolves a single token to a list of IPs.
/// Supports: single IPv4, CIDR (/16 minimum — limit expansion to /16..=/32),
/// range notation a.b.c.X-Y.
fn resolve_token(token: &str) -> Result<Vec<String>, TargetError> {
    // Range: 192.168.1.1-254
    if let Some(dash_pos) = token.rfind('-') {
        let prefix_part = &token[..dash_pos]; // e.g. 192.168.1.1
        let end_str = &token[dash_pos + 1..]; // e.g. 254

        if let (Some(last_dot), Ok(end_last)) = (prefix_part.rfind('.'), end_str.parse::<u8>()) {
            let network_prefix = &prefix_part[..=last_dot]; // e.g. "192.168.1."
            let start_last: u8 = prefix_part[last_dot + 1..]
                .parse()
                .map_err(|_| TargetError::InvalidToken(token.to_string()))?;

            if start_last > end_last {
                return Err(TargetError::InvalidToken(format!(
                    "range start {} > end {}",
                    start_last, end_last
                )));
            }

            let ips: Vec<String> = (start_last..=end_last)
                .map(|i| format!("{}{}", network_prefix, i))
                .collect();
            return Ok(ips);
        }
    }

    // CIDR: 192.168.1.0/24
    if let Some(slash) = token.find('/') {
        let base_str = &token[..slash];
        let prefix_len: u8 = token[slash + 1..]
            .parse()
            .map_err(|_| TargetError::InvalidToken(token.to_string()))?;

        if !(16..=32).contains(&prefix_len) {
            return Err(TargetError::InvalidToken(format!(
                "CIDR prefix /{} not supported (only /16.../32 allowed)",
                prefix_len
            )));
        }

        let base_u32 =
            parse_ipv4(base_str).ok_or_else(|| TargetError::InvalidToken(token.to_string()))?;

        let host_bits = 32 - prefix_len;
        let count = 1u32 << host_bits;
        let network = if prefix_len == 0 {
            0
        } else {
            base_u32 & (!0u32 << host_bits)
        };

        let ips: Vec<String> = (0..count).map(|i| u32_to_ipv4(network + i)).collect();
        return Ok(ips);
    }

    // Single IPv4
    if parse_ipv4(token).is_some() {
        return Ok(vec![token.to_string()]);
    }

    Err(TargetError::InvalidToken(token.to_string()))
}

pub(crate) fn parse_ipv4(ip: &str) -> Option<u32> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut res = 0u32;
    for part in parts {
        let val: u32 = part.parse().ok()?;
        if val > 255 {
            return None;
        }
        res = (res << 8) | val;
    }
    Some(res)
}

fn u32_to_ipv4(n: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (n >> 24) & 0xff,
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_ip() {
        let scope = vec!["127.0.0.1".to_string()];
        let r = parse_and_validate(&["127.0.0.1"], &scope).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].ip, "127.0.0.1");
    }

    #[test]
    fn test_cidr_24() {
        let scope = vec!["192.168.1.0/24".to_string()];
        let r = parse_and_validate(&["192.168.1.0/24"], &scope).unwrap();
        assert_eq!(r.len(), 256);
    }

    #[test]
    fn test_range() {
        let scope = vec!["10.0.0.0/24".to_string()];
        let r = parse_and_validate(&["10.0.0.1-10"], &scope).unwrap();
        assert_eq!(r.len(), 10);
        assert_eq!(r[0].ip, "10.0.0.1");
        assert_eq!(r[9].ip, "10.0.0.10");
    }

    #[test]
    fn test_out_of_scope_rejects_all() {
        let scope = vec!["192.168.1.0/24".to_string()];
        // 10.0.0.1 is outside scope
        let r = parse_and_validate(&["10.0.0.1"], &scope);
        assert!(matches!(r, Err(TargetError::OutOfScope(_))));
    }

    #[test]
    fn test_cidr_too_large() {
        let scope: Vec<String> = vec![];
        let r = parse_and_validate(&["10.0.0.0/8"], &scope);
        assert!(matches!(r, Err(TargetError::InvalidToken(_))));
    }

    #[test]
    fn test_empty_scope_allows_only_localhost() {
        let scope: Vec<String> = vec![];
        let r = parse_and_validate(&["127.0.0.1"], &scope);
        assert!(r.is_ok());
        let r2 = parse_and_validate(&["10.0.0.1"], &scope);
        assert!(matches!(r2, Err(TargetError::OutOfScope(_))));
    }
}
