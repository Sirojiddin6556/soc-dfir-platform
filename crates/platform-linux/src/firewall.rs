#![forbid(unsafe_code)]

//! Netfilter rules from `iptables -S` / `ip6tables -S` (filter table).

use host_snapshot::FirewallRule;

pub fn chain_direction(chain: &str) -> String {
    match chain {
        "INPUT" => "Inbound".to_string(),
        "OUTPUT" => "Outbound".to_string(),
        "FORWARD" => "Forward".to_string(),
        other => other.to_string(),
    }
}

/// Parses `iptables -S` output. Chain policies (`-P INPUT DROP`) and rules
/// (`-A INPUT -p tcp --dport 22 -j ACCEPT`) are both reported; `family` is
/// "ipv4" or "ipv6".
pub fn parse_iptables_s(output: &str, family: &str) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens.as_slice() {
            ["-P", chain, policy, ..] => rules.push(FirewallRule {
                name: format!("policy {} ({})", chain, family),
                direction: chain_direction(chain),
                action: policy.to_string(),
                enabled: true,
                table: Some("filter".to_string()),
                protocol: None,
            }),
            ["-A", chain, rest @ ..] => {
                let value_after = |flag: &str| {
                    rest.iter()
                        .position(|t| *t == flag)
                        .and_then(|i| rest.get(i + 1))
                        .map(|s| s.to_string())
                };
                let action = value_after("-j")
                    .or_else(|| value_after("-g"))
                    .unwrap_or_else(|| "(no target)".to_string());
                rules.push(FirewallRule {
                    name: format!("{} ({})", line.trim(), family),
                    direction: chain_direction(chain),
                    action,
                    enabled: true,
                    table: Some("filter".to_string()),
                    protocol: value_after("-p"),
                });
            }
            _ => {}
        }
    }
    rules
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::*;

    /// Runs `iptables -S` and `ip6tables -S` (static arguments). Returns the
    /// rules and the reasons any of them could not be read.
    pub fn collect() -> (Vec<FirewallRule>, Vec<String>) {
        let mut rules = Vec::new();
        let mut errors = Vec::new();
        for (bin, family) in [("iptables", "ipv4"), ("ip6tables", "ipv6")] {
            match std::process::Command::new(bin).arg("-S").output() {
                Ok(out) if out.status.success() => {
                    rules.extend(parse_iptables_s(
                        &String::from_utf8_lossy(&out.stdout),
                        family,
                    ));
                }
                Ok(out) => errors.push(format!(
                    "{} -S завершился с ошибкой: {}",
                    bin,
                    String::from_utf8_lossy(&out.stderr).trim()
                )),
                Err(e) => errors.push(format!("{} недоступен: {}", bin, e)),
            }
        }
        (rules, errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policies_and_rules() {
        let output = "-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
-A FORWARD -o docker0 -g DOCKER
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 5432 -j ACCEPT
";
        let rules = parse_iptables_s(output, "ipv4");
        assert_eq!(rules.len(), 7);
        assert_eq!(rules[0].name, "policy INPUT (ipv4)");
        assert_eq!(rules[0].direction, "Inbound");
        assert_eq!(rules[0].action, "DROP");
        assert_eq!(rules[2].direction, "Outbound");
        assert_eq!(rules[4].protocol.as_deref(), Some("tcp"));
        assert_eq!(rules[4].action, "ACCEPT");
        assert_eq!(rules[5].direction, "Forward");
        assert_eq!(rules[5].action, "DOCKER");
        assert_eq!(rules[6].direction, "DOCKER");
        assert!(rules.iter().all(|r| r.table.as_deref() == Some("filter")));
    }
}
