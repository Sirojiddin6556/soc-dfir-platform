pub fn is_in_scope(target_ip: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return is_localhost(target_ip);
    }

    let target = match parse_ipv4(target_ip) {
        Some(ip) => ip,
        None => return patterns.iter().any(|p| p == target_ip), // Exact match for non-IPv4
    };

    for pattern in patterns {
        if pattern.contains('/') {
            let parts: Vec<&str> = pattern.splitn(2, '/').collect();
            if parts.len() != 2 {
                continue;
            }
            if let (Some(base_ip), Ok(prefix_len)) = (parse_ipv4(parts[0]), parts[1].parse::<u8>())
            {
                if prefix_len > 32 {
                    continue;
                }
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0 << (32 - prefix_len)
                };
                if (target & mask) == (base_ip & mask) {
                    return true;
                }
            }
        } else {
            if let Some(base_ip) = parse_ipv4(pattern) {
                if target == base_ip {
                    return true;
                }
            } else {
                if target_ip == pattern {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_ipv4(ip: &str) -> Option<u32> {
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

pub fn is_localhost(target: &str) -> bool {
    target.starts_with("127.") || target == "localhost" || target == "::1"
}
