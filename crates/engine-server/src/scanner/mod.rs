#![forbid(unsafe_code)]

pub mod network;
pub mod probe;

pub use network::{execute_cve_scan, execute_network_scan};
pub use probe::{
    fingerprint_os, probe_service_details, resolve_hostname, Confidence, DiscoveredService,
    ScanMethod,
};

/// Discovers live hosts using ARP cache + TCP probe fallback.
pub async fn execute_host_discovery(subnet_prefix: &str) -> serde_json::Value {
    #[cfg(target_os = "windows")]
    {
        let arp_hosts = platform_windows::discover_via_arp(subnet_prefix);
        let tcp_hosts = if arp_hosts.is_empty() {
            let guesses: Vec<String> = (1u8..=10)
                .map(|i| format!("{}{}", subnet_prefix, i))
                .collect();
            platform_windows::discover_via_tcp_probe(&guesses)
        } else {
            vec![]
        };
        let mut all_hosts = Vec::new();
        for h in arp_hosts.iter().chain(tcp_hosts.iter()) {
            all_hosts.push(serde_json::json!({
                "ip": h.ip,
                "hostname": h.hostname,
                "method": format!("{:?}", h.method),
            }));
        }
        return serde_json::json!({
            "subnet_prefix": subnet_prefix,
            "hosts_found": all_hosts.len(),
            "hosts": all_hosts,
        });
    }
    #[allow(unreachable_code)]
    serde_json::json!({
        "subnet_prefix": subnet_prefix,
        "hosts_found": 0,
        "hosts": [],
        "note": "Host discovery not implemented on this platform"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_scan_local() {
        let quick = execute_network_scan("127.0.0.1", "quick").await;
        assert_eq!(quick["subnet"], "127.0.0.1");
        assert_eq!(quick["hosts_up"], 1);
        let hosts = quick["discovered_hosts"].as_array().unwrap();
        assert!(!hosts.is_empty());
        assert_eq!(hosts[0]["ip"], "127.0.0.1");
    }

    #[tokio::test]
    async fn test_service_probe_details() {
        let s = probe_service_details("127.0.0.1", 135).await;
        assert_eq!(s.port, 135);
        assert_eq!(s.service_name, "MSRPC");
    }

    #[test]
    fn test_cve_scan() {
        let cve_h1 = execute_cve_scan("h_local");
        assert_eq!(cve_h1["host_id"], "h_local");
        assert_eq!(cve_h1["calculated_risk"], 1.0);
        let vulns = cve_h1["vulnerabilities"].as_array().unwrap();
        assert!(vulns.is_empty());
    }
}
