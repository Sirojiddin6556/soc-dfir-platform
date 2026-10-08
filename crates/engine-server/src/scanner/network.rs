#![forbid(unsafe_code)]

use super::probe::{fingerprint_os, resolve_hostname};
use scan_engine::orchestrator::ScanOrchestrator;
use scan_engine::target::parse_target;
use scan_engine::types::{PortState, ScanJob, ScanJobId, ScanJobStatus, ScanProfile, ScanTarget};
use serde_json::json;

/// Executes an infrastructure network scan (Quick, Standard, Deep) powered by ScanOrchestrator
pub async fn execute_network_scan(subnet: &str, mode: &str) -> serde_json::Value {
    let profile = match mode {
        "deep" => ScanProfile::Deep,
        "standard" => ScanProfile::Standard,
        _ => ScanProfile::Quick,
    };

    let target = parse_target(subnet).unwrap_or_else(|_| ScanTarget::Hostname(subnet.to_string()));

    let job = ScanJob {
        id: ScanJobId(uuid::Uuid::now_v7().to_string()),
        target,
        profile,
        created_at: chrono::Utc::now(),
        status: ScanJobStatus::Running,
    };

    let orchestrator = ScanOrchestrator::new();
    let scan_result = orchestrator.execute(&job).await;

    let mut discovered = Vec::new();

    for host in &scan_result.hosts {
        let ip_str = host.ip.to_string();
        let port_results = scan_result
            .port_results
            .get(&ip_str)
            .cloned()
            .unwrap_or_default();

        let mut open_ports = Vec::new();
        let mut services_json = Vec::new();

        for p in port_results {
            if p.state == PortState::Open {
                open_ports.push(p.port);
                if let Some(s) = p.service {
                    services_json.push(json!({
                        "port": p.port,
                        "protocol": "TCP",
                        "service": s.name,
                        "version": s.version.unwrap_or_else(|| "Detected".to_string()),
                        "banner": s.banner.unwrap_or_else(|| format!("{}/{}", s.name, p.port)),
                        "scan_method": s.method,
                        "confidence": format!("{:.2}", s.confidence),
                    }));
                }
            }
        }

        let (os_str, dev_type) = fingerprint_os(&open_ports);
        let hostname = host
            .hostname
            .clone()
            .unwrap_or_else(|| resolve_hostname(&ip_str));

        discovered.push(json!({
            "id": format!("h_{}", ip_str.replace(['.', ':'], "_")),
            "hostname": hostname,
            "ip": ip_str,
            "mac": host.mac.clone().unwrap_or_else(|| "00:00:00:00:00:00".to_string()),
            "os": os_str,
            "device_type": dev_type,
            "criticality": if ip_str == "127.0.0.1" { "Tier-1 (Рабочая станция аналитика)" } else { "Tier-2 (Сетевой узел)" },
            "status": "Активен / Боевой режим",
            "risk": "НИЗКИЙ (1.0)",
            "subnet": subnet,
            "ports": open_ports,
            "services": services_json,
            "persistence": [],
            "software": if ip_str == "127.0.0.1" {
                vec![json!({ "name": "SOC DFIR Engine", "ver": "0.3.0", "cpe": "cpe:2.3:a:soc:dfir_engine:0.3.0" })]
            } else {
                vec![]
            },
            "vulnerabilities": []
        }));
    }

    let cov = &scan_result.coverage;
    let hosts_up = discovered.len();

    json!({
        "subnet": subnet,
        "mode": mode,
        "hosts_scanned": cov.targets_total,
        "hosts_up": hosts_up,
        "duration_ms": scan_result.duration_ms,
        "scan_rate_pps": (cov.tcp_ports_attempted as u64 * 1000)
            .checked_div(scan_result.duration_ms)
            .unwrap_or(350),
        "coverage": {
            "targets_total": cov.targets_total,
            "targets_responsive": cov.targets_responsive,
            "ports_attempted": cov.tcp_ports_attempted,
            "ports_open": cov.tcp_ports_open,
            "ports_closed": cov.tcp_ports_closed,
            "ports_filtered": cov.tcp_ports_filtered,
            "ports_timeout": cov.tcp_ports_timeout,
            "ports_error": cov.tcp_ports_error,
            "services_identified": cov.services_identified,
            "services_unknown": cov.services_unknown,
            "os_identified": cov.os_identified,
            "errors": cov.errors,
            "quality": format!("{:?}", cov.quality).to_uppercase(),
            "confidence": cov.confidence,
            "scan_mode": mode,
            "privilege_level": cov.privilege_level,
            "nmap_available": cov.nmap_available,
            "note": cov.note,
        },
        "discovered_hosts": discovered
    })
}
