#![forbid(unsafe_code)]

/// Result of discovering a single host.
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub method: DiscoveryMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMethod {
    ArpCache, // parsed from `arp -a` output
    TcpProbe, // responded to TCP connect on a common port
}

/// Parse the Windows ARP cache by running `arp -a` and extracting IP entries.
/// Returns every IP that appears in the ARP table (excluding multicast/broadcast).
pub fn discover_via_arp(subnet_prefix: &str) -> Vec<DiscoveredHost> {
    // Run: arp -a
    // Output lines look like:
    //   Interface: 192.168.1.100 --- 0x3
    //     Internet Address      Physical Address      Type
    //     192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
    //     192.168.1.255         ff-ff-ff-ff-ff-ff     static  <- skip
    //     224.0.0.22            ...                           <- skip (multicast)
    let output = std::process::Command::new("arp").arg("-a").output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return vec![],
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut hosts = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        // First token should be an IP address
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let ip = parts[0];

        // Validate it's an IPv4 in the right prefix
        if !is_valid_unicast_ipv4(ip) {
            continue;
        }
        if !subnet_prefix.is_empty() && !ip.starts_with(subnet_prefix) {
            continue;
        }
        // Skip broadcast/multicast
        if ip.ends_with(".255") || ip.starts_with("224.") || ip.starts_with("239.") {
            continue;
        }

        hosts.push(DiscoveredHost {
            ip: ip.to_string(),
            hostname: None,
            method: DiscoveryMethod::ArpCache,
        });
    }
    hosts
}

/// TCP-probe fallback: attempt connect on a few common ports to detect live hosts.
/// Works where ICMP is blocked. Runs synchronously with short timeouts.
pub fn discover_via_tcp_probe(ips: &[String]) -> Vec<DiscoveredHost> {
    let probe_ports: &[u16] = &[80, 135, 443, 445, 22, 3389, 8080];
    let mut found = Vec::new();

    for ip in ips {
        'outer: for &port in probe_ports {
            let addr = format!("{}:{}", ip, port);
            if std::net::TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                std::time::Duration::from_millis(100),
            )
            .is_ok()
            {
                found.push(DiscoveredHost {
                    ip: ip.clone(),
                    hostname: None,
                    method: DiscoveryMethod::TcpProbe,
                });
                break 'outer;
            }
        }
    }
    found
}

fn is_valid_unicast_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}
