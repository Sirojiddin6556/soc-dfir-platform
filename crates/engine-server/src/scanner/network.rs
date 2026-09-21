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

/// Correlates asset software stack against persistent VulnDB (data/vulndb/vuln.db)
/// with real OS telemetry (Build, UBR, KBs) and ecosystem-aware applicability filtering.
pub fn execute_cve_scan(host_id: &str) -> serde_json::Value {
    let hostname = if host_id == "h_local" {
        crate::default_host_id()
    } else {
        host_id
    };
    let snap = crate::host_inspector::get_or_collect_snapshot(hostname);

    // VULN-H01: Подключение к реальной persistent БД data/vulndb/vuln.db
    let db_path = std::path::Path::new("data/vulndb/vuln.db");
    let repo = match vulnerability_engine::VulnDbRepository::open_or_create(db_path) {
        Ok(r) => r,
        Err(e) => {
            // VULN-H02: Ошибка никогда не должна маскироваться под отсутствие CVE!
            return json!({
                "host_id": host_id,
                "hostname": hostname,
                "status": "DATASET_UNAVAILABLE",
                "error": format!("Failed to open persistent VulnDB at {:?}: {}", db_path, e),
                "calculated_risk": 1.0,
                "software_scanned": 0,
                "scanned_software": [],
                "vulnerabilities": [],
                "feed_metadata": {
                    "status": "ERROR",
                    "available": false
                }
            });
        }
    };

    let db_snapshot = match repo.get_snapshot_info() {
        Ok(s) => s,
        Err(e) => {
            return json!({
                "host_id": host_id,
                "hostname": hostname,
                "status": "DATASET_CORRUPT",
                "error": format!("Failed to read VulnDB snapshot manifest: {}", e),
                "calculated_risk": 1.0,
                "software_scanned": 0,
                "scanned_software": [],
                "vulnerabilities": [],
            });
        }
    };

    let orchestrator = vulnerability_engine::VulnerabilityOrchestrator::new(repo);

    // VULN-H03: Определение экосистемы хоста из реальной ОС, а не по подстроке имени продукта
    let os_lower = snap.os.to_lowercase();
    let is_windows = os_lower.contains("windows");
    let default_eco = if is_windows {
        vulnerability_engine::PackageEcosystem::Windows
    } else if os_lower.contains("ubuntu") {
        vulnerability_engine::PackageEcosystem::Ubuntu
    } else if os_lower.contains("debian") {
        vulnerability_engine::PackageEcosystem::Debian
    } else if os_lower.contains("red hat") || os_lower.contains("rhel") {
        vulnerability_engine::PackageEcosystem::RedHat
    } else {
        vulnerability_engine::PackageEcosystem::Generic
    };

    let mut scanned_software = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut max_risk_score = 1.0f32;
    let mut had_evaluation_errors = false;

    for sw in &snap.software {
        let norm =
            normalization_engine::resolve_cpe_and_purl(&sw.product, &sw.publisher, &sw.version);

        // VULN-H04: Передаем реальные Windows Build, UBR и установленные KB из телеметрии
        let product_id = vulnerability_engine::ProductIdentity {
            raw_name: sw.product.clone(),
            raw_version: sw.version.clone(),
            publisher: if sw.publisher.is_empty() {
                None
            } else {
                Some(sw.publisher.clone())
            },
            ecosystem: default_eco,
            cpe: Some(norm.cpe23.clone()),
            purl: Some(norm.purl.clone()),
            os_family: Some(if is_windows { "Windows" } else { "Linux" }.to_string()),
            os_release: Some(snap.os.clone()),
            os_build: snap.os_build,
            os_ubr: snap.os_ubr,
            installed_kbs: snap.installed_kbs.clone(),
        };

        match orchestrator.evaluate_product(
            &product_id,
            vulnerability_engine::ExposureLevel::InternetFacing,
            vulnerability_engine::AssetCriticality::Tier1,
            vulnerability_engine::ExploitationState::NoEvidence,
        ) {
            Ok(eval) => {
                for finding in &eval.findings {
                    let risk = &finding.risk;
                    if risk.contextual_risk_score > max_risk_score {
                        max_risk_score = risk.contextual_risk_score;
                    }

                    vulnerabilities.push(json!({
                        "cve": finding.vulnerability.id,
                        "name": format!("{} - {}", sw.product, finding.vulnerability.summary),
                        "cvss_base": risk.cvss_base_score,
                        "contextual_risk_score": risk.contextual_risk_score,
                        "severity": risk.severity_label,
                        "epss": risk.epss_score,
                        "cisa_kev": risk.cisa_kev,
                        "applicability_status": format!("{:?}", finding.applicability.status),
                        "confidence": finding.applicability.confidence,
                        "reason": finding.applicability.reason,
                        "cpe": norm.cpe23,
                        "purl": norm.purl,
                        "evidence": finding.applicability.evidence,
                    }));
                }

                let sw_status = if eval.affected_count > 0 {
                    "AFFECTED".to_string()
                } else if eval.fixed_count > 0 {
                    "PATCHED / BACKPORT_FIXED".to_string()
                } else {
                    "NO_KNOWN_MATCHED_VULNERABILITIES".to_string()
                };

                scanned_software.push(json!({
                    "name": sw.product,
                    "ver": sw.version,
                    "publisher": sw.publisher,
                    "cpe": norm.cpe23,
                    "purl": norm.purl,
                    "status": sw_status,
                    "confidence": 0.95,
                }));
            }
            Err(e) => {
                // Ошибка не маскируется под "NO_KNOWN_MATCHED"!
                had_evaluation_errors = true;
                scanned_software.push(json!({
                    "name": sw.product,
                    "ver": sw.version,
                    "publisher": sw.publisher,
                    "cpe": norm.cpe23,
                    "purl": norm.purl,
                    "status": "EVALUATION_ERROR",
                    "error": e.to_string(),
                    "confidence": 0.0,
                }));
            }
        }
    }

    let overall_status = if had_evaluation_errors {
        "PARTIAL_EVALUATION_ERROR"
    } else if !vulnerabilities.is_empty() {
        "VULNERABILITIES_DETECTED"
    } else {
        "NO_KNOWN_MATCHED_VULNERABILITIES"
    };

    json!({
        "host_id": host_id,
        "hostname": hostname,
        "status": overall_status,
        "software_scanned": scanned_software.len(),
        "calculated_risk": max_risk_score,
        "scanned_software": scanned_software,
        "vulnerabilities": vulnerabilities,
        "feed_metadata": {
            "snapshot_id": db_snapshot.snapshot_id,
            "is_stale": db_snapshot.is_stale,
            "feeds_count": db_snapshot.feeds.len(),
            "created_at": db_snapshot.created_at.to_rfc3339(),
        }
    })
}
