#![forbid(unsafe_code)]

use crate::types::{DiscoveryMethod, LiveHost, ScanProfile};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Reads system ARP table to find responsive neighbors
pub fn read_arp_table() -> Vec<LiveHost> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("arp").arg("-a").output();
        let output = match output {
            Ok(o) => o,
            Err(_) => return vec![],
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut hosts = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                if ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() {
                    continue;
                }
                let mac = if parts.len() >= 2 && parts[1].contains('-') {
                    Some(parts[1].to_uppercase())
                } else {
                    None
                };
                hosts.push(LiveHost {
                    ip,
                    mac,
                    hostname: None,
                    discovery_method: DiscoveryMethod::ArpCache,
                });
            }
        }
        hosts
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            let mut hosts = Vec::new();
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                        let mac = parts[3];
                        if mac != "00:00:00:00:00:00" {
                            hosts.push(LiveHost {
                                ip,
                                mac: Some(mac.to_uppercase()),
                                hostname: None,
                                discovery_method: DiscoveryMethod::ArpCache,
                            });
                        }
                    }
                }
            }
            hosts
        } else {
            vec![]
        }
    }
}

/// TCP probe: attempts connecting to common ports to identify responsive hosts
pub async fn tcp_ping_hosts(
    ips: &[Ipv4Addr],
    probe_ports: &[u16],
    timeout_ms: u64,
) -> Vec<LiveHost> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let sem = Arc::new(Semaphore::new(64));
    let mut handles = Vec::new();

    for &ip in ips {
        for &port in probe_ports {
            let sem_clone = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem_clone.acquire_owned().await.ok()?;
                let addr = format!("{}:{}", ip, port);
                let res =
                    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await;
                match res {
                    Ok(Ok(_stream)) => Some((ip, true)),
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        // Received RST/ACK => Host is definitely UP!
                        Some((ip, true))
                    }
                    _ => None,
                }
            }));
        }
    }

    let mut responsive = std::collections::HashSet::new();
    for h in handles {
        if let Ok(Some((ip, _))) = h.await {
            responsive.insert(ip);
        }
    }

    responsive
        .into_iter()
        .map(|ip| LiveHost {
            ip,
            mac: None,
            hostname: None,
            discovery_method: DiscoveryMethod::TcpProbe,
        })
        .collect()
}

/// Discovery according to ScanProfile
pub async fn discover_hosts(targets: &[Ipv4Addr], profile: &ScanProfile) -> Vec<LiveHost> {
    let mut discovered: std::collections::HashMap<Ipv4Addr, LiveHost> =
        std::collections::HashMap::new();

    // 1. ARP Cache check
    let arp_hosts = read_arp_table();
    let target_set: std::collections::HashSet<Ipv4Addr> = targets.iter().copied().collect();

    for host in arp_hosts {
        if target_set.contains(&host.ip) {
            discovered.insert(host.ip, host);
        }
    }

    // Loopback targets are always live locally
    for &target_ip in targets {
        if target_ip.is_loopback() {
            discovered.insert(
                target_ip,
                LiveHost {
                    ip: target_ip,
                    mac: Some("00:00:00:00:00:00".into()),
                    hostname: Some("localhost".into()),
                    discovery_method: DiscoveryMethod::TcpProbe,
                },
            );
        }
    }

    // 2. TCP ping probe for hosts not yet confirmed or when verifying
    let probe_ports: &[u16] = match profile {
        ScanProfile::Quick => &[80, 443, 445, 135, 22, 3389, 8080],
        ScanProfile::Standard => &[
            21, 22, 25, 53, 80, 88, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5985, 8080,
        ],
        ScanProfile::Deep => &[
            21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 1433, 1521, 3306,
            3389, 5432, 5985, 8080, 8443,
        ],
    };

    let tcp_timeout = match profile {
        ScanProfile::Quick => 120,
        ScanProfile::Standard => 250,
        ScanProfile::Deep => 500,
    };

    let ping_hosts = tcp_ping_hosts(targets, probe_ports, tcp_timeout).await;
    for host in ping_hosts {
        discovered
            .entry(host.ip)
            .and_modify(|existing| {
                if existing.discovery_method == DiscoveryMethod::ArpCache {
                    existing.discovery_method = DiscoveryMethod::Combined;
                }
            })
            .or_insert(host);
    }

    discovered.into_values().collect()
}
