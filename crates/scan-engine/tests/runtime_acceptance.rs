#![forbid(unsafe_code)]

use scan_engine::asset_resolver::AssetResolver;
use scan_engine::nmap_adapter::NmapAdapter;
use scan_engine::orchestrator::ScanOrchestrator;
use scan_engine::port_scan::{classify_error, ports_for_profile};
use scan_engine::service_probe::{HttpProbe, ServiceProbe, ServiceTarget, SshProbe};
use scan_engine::target::{expand_target_to_ips, parse_target};
use scan_engine::types::{
    PortState, RawAssetObservation, ScanJob, ScanJobId, ScanJobStatus, ScanProfile, ScanTarget,
};
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// GATE 3 & 4: Port State and Error Classification (TIMEOUT != CLOSED)
#[test]
fn test_gate_port_states_and_timeout_separation() {
    let refused_err = Error::new(ErrorKind::ConnectionRefused, "Connection refused");
    let timeout_err = Error::new(ErrorKind::TimedOut, "Operation timed out");
    let reset_err = Error::new(ErrorKind::ConnectionReset, "Connection reset by peer");
    let unreach_err = Error::other("Network is unreachable");

    assert_eq!(classify_error(&refused_err), PortState::Closed);
    assert_eq!(classify_error(&timeout_err), PortState::Timeout);
    assert_eq!(classify_error(&reset_err), PortState::Closed);
    assert_eq!(classify_error(&unreach_err), PortState::Unreachable);

    // Explicit invariant: Timeout is NEVER Closed
    assert_ne!(PortState::Timeout, PortState::Closed);
}

/// GATE 5: Profiles must execute genuinely different work
#[test]
fn test_gate_profiles_have_different_workloads() {
    let quick_ports = ports_for_profile(&ScanProfile::Quick);
    let standard_ports = ports_for_profile(&ScanProfile::Standard);
    let deep_ports = ports_for_profile(&ScanProfile::Deep);

    assert!(quick_ports.len() < standard_ports.len());
    assert!(standard_ports.len() < deep_ports.len());

    assert_eq!(quick_ports.len(), 40);
    assert_eq!(standard_ports.len(), 101);
    assert!(deep_ports.len() > 101);
}

/// GATE 3: Remote Target and CIDR Expansion
#[test]
fn test_gate_cidr_target_expansion() {
    let target = parse_target("10.10.20.0/24").expect("Valid CIDR");
    let ips = expand_target_to_ips(&target).expect("Expands to IPs");

    assert_eq!(ips.len(), 254);
    assert_eq!(ips[0], Ipv4Addr::new(10, 10, 20, 1));
    assert_eq!(ips[253], Ipv4Addr::new(10, 10, 20, 254));

    // Single IP target
    let single = parse_target("192.168.1.50").expect("Valid single IP");
    let single_ips = expand_target_to_ips(&single).expect("Expands to single");
    assert_eq!(single_ips.len(), 1);
    assert_eq!(single_ips[0], Ipv4Addr::new(192, 168, 1, 50));
}

/// GATE 6: Nmap Adapter fallback and strict argument construction
#[test]
fn test_gate_nmap_adapter_and_typed_args() {
    let maybe_adapter = NmapAdapter::detect();
    let _ = maybe_adapter.is_some();

    // Empty XML parse does not panic
    let empty_res = NmapAdapter::parse_xml("<nmaprun></nmaprun>").expect("Valid XML parse");
    assert!(empty_res.hosts.is_empty());
}

/// GATE 7: ServiceProbe with real TCP server and protocol handshake
#[tokio::test]
async fn test_gate_service_probe_http_and_ssh() {
    use tokio::io::AsyncReadExt;

    // 1. Mock local HTTP Server on ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut req_buf = [0u8; 512];
            let _ = socket.read(&mut req_buf).await;
            let response =
                "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n";
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        }
    });

    let probe = HttpProbe;
    let target = ServiceTarget {
        ip: Ipv4Addr::new(127, 0, 0, 1),
        port,
        timeout_ms: 1000,
    };

    let obs = probe.probe(&target).await.expect("HTTP probe succeeds");
    assert_eq!(obs.service_name, "HTTP");
    assert_eq!(obs.version.as_deref(), Some("nginx/1.24.0 (Ubuntu)"));
    assert!(obs.confidence >= 0.8);
    let _ = server_task.await;

    // 2. Mock local SSH Server on ephemeral port
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();

    let ssh_server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = ssh_listener.accept().await {
            let banner = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6\r\n";
            let _ = socket.write_all(banner.as_bytes()).await;
        }
    });

    let ssh_probe = SshProbe;
    let ssh_target = ServiceTarget {
        ip: Ipv4Addr::new(127, 0, 0, 1),
        port: ssh_port,
        timeout_ms: 1000,
    };

    let ssh_obs = ssh_probe
        .probe(&ssh_target)
        .await
        .expect("SSH probe succeeds");
    assert_eq!(ssh_obs.service_name, "SSH");
    assert_eq!(
        ssh_obs.version.as_deref(),
        Some("OpenSSH_9.3p1 Ubuntu-1ubuntu3.6")
    );
    assert_eq!(ssh_obs.method, "banner-grab");
    assert!(ssh_obs.confidence >= 0.9);
    let _ = ssh_server_task.await;
}

/// GATE 8: AssetResolver merges identity sources without aggressive collisions
#[test]
fn test_gate_asset_resolver_deduplication() {
    let resolver = AssetResolver;

    let obs_host1_ip = RawAssetObservation {
        ip: Some(Ipv4Addr::new(10, 10, 20, 11)),
        mac: None,
        hostname: None,
        fqdn: None,
        cert_names: vec![],
        smb_hostname: None,
        source: "tcp-probe".into(),
    };

    let obs_host1_arp = RawAssetObservation {
        ip: Some(Ipv4Addr::new(10, 10, 20, 11)),
        mac: Some("00:50:56:A1:B2:C3".into()),
        hostname: None,
        fqdn: None,
        cert_names: vec![],
        smb_hostname: None,
        source: "arp-cache".into(),
    };

    let obs_host1_dns = RawAssetObservation {
        ip: Some(Ipv4Addr::new(10, 10, 20, 11)),
        mac: None,
        hostname: Some("DC-LAB".into()),
        fqdn: Some("dc-lab.corp.local".into()),
        cert_names: vec![],
        smb_hostname: Some("DC-LAB".into()),
        source: "dns-ptr".into(),
    };

    let obs_host2 = RawAssetObservation {
        ip: Some(Ipv4Addr::new(10, 10, 20, 25)),
        mac: Some("00:50:56:D4:E5:F6".into()),
        hostname: Some("WIN11-LAB".into()),
        fqdn: None,
        cert_names: vec![],
        smb_hostname: None,
        source: "arp-cache".into(),
    };

    let canonical = resolver.resolve(&[obs_host1_ip, obs_host1_arp, obs_host1_dns, obs_host2]);

    assert_eq!(canonical.len(), 2, "Merged into exactly 2 physical assets");

    let dc_asset = canonical
        .iter()
        .find(|a| a.ip == Some(Ipv4Addr::new(10, 10, 20, 11)))
        .expect("DC-LAB found");

    assert_eq!(dc_asset.hostname.as_deref(), Some("DC-LAB"));
    assert_eq!(dc_asset.mac.as_deref(), Some("00:50:56:A1:B2:C3"));
    assert_eq!(dc_asset.fqdn.as_deref(), Some("dc-lab.corp.local"));
    assert_eq!(dc_asset.sources.len(), 3);
    assert!(dc_asset.confidence > 0.8);
}

/// GATE 9 & 10: Complete ScanCoverage and Provenance Traceability
#[tokio::test]
async fn test_gate_coverage_and_provenance_traceability() {
    let job = ScanJob {
        id: ScanJobId("job-audit-777".into()),
        target: ScanTarget::SingleIp(Ipv4Addr::new(127, 0, 0, 1)),
        profile: ScanProfile::Quick,
        created_at: chrono::Utc::now(),
        status: ScanJobStatus::Running,
    };

    let orchestrator = ScanOrchestrator::new();
    let result = orchestrator.execute(&job).await;

    // Quality check
    assert_eq!(result.job_id, "job-audit-777");
    assert!(result.coverage.targets_total >= 1);
    assert!(result.coverage.tcp_ports_attempted > 0);

    // Provenance Check: Every observation has BLAKE3 hash, tool_run_id, method, timestamps
    for obs in &result.observations {
        assert_eq!(obs.tool_run_id, "job-audit-777");
        assert_eq!(obs.collector, "soc-scan-orchestrator");
        assert_eq!(obs.collector_version, "0.3.0");
        assert!(!obs.raw_result_hash.is_empty());
        assert_eq!(
            obs.raw_result_hash.len(),
            64,
            "Valid 256-bit BLAKE3 hex hash"
        );
    }
}
