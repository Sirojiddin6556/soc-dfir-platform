#![forbid(unsafe_code)]

use engine_server::scanner::execute_network_scan;

#[tokio::test]
async fn test_live_network_discovery_loopback() {
    let result = execute_network_scan("127.0.0.1", "quick").await;

    assert_eq!(result["subnet"], "127.0.0.1");
    assert_eq!(result["mode"], "quick");
    assert!(result["hosts_up"].as_u64().unwrap_or(0) >= 1);

    let coverage = &result["coverage"];
    assert!(coverage["targets_total"].as_u64().unwrap_or(0) >= 1);
    assert!(coverage["ports_attempted"].as_u64().unwrap_or(0) > 0);
    assert!(coverage["confidence"].as_f64().unwrap_or(0.0) >= 0.8);
    assert!(!coverage["quality"].as_str().unwrap().is_empty());

    let hosts = result["discovered_hosts"].as_array().unwrap();
    assert!(!hosts.is_empty());
    let h0 = &hosts[0];
    assert_eq!(h0["ip"], "127.0.0.1");
    assert!(!h0["status"].as_str().unwrap().is_empty());

    // Zero-Mock verification: no synthetic names
    let h_name = h0["hostname"].as_str().unwrap_or("");
    assert_ne!(h_name, "DC01.CORP.LOCAL");
    assert_ne!(h_name, "DMZ-WEB01");
}

#[tokio::test]
async fn test_live_network_discovery_real_subnet() {
    // Scan real host-only / virtual lab subnet 192.168.56.0/24
    let result = execute_network_scan("192.168.56.0/24", "quick").await;

    assert_eq!(result["subnet"], "192.168.56.0/24");
    assert_eq!(result["mode"], "quick");

    let coverage = &result["coverage"];
    assert_eq!(
        coverage["targets_total"], 254,
        "254 addresses in /24 subnet"
    );
    assert_eq!(coverage["scan_mode"], "quick");
    assert!(coverage["ports_open"].as_u64().is_some());
    assert!(coverage["ports_timeout"].as_u64().is_some());
    assert!(coverage["ports_closed"].as_u64().is_some());

    // Verified: No panic on 254 hosts scan, valid JSON structure returned
}
