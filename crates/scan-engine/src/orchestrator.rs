#![forbid(unsafe_code)]

use crate::coverage::compute_coverage;
use crate::discovery::discover_hosts;
use crate::nmap_adapter::NmapAdapter;
use crate::port_scan::{ports_for_profile, scan_tcp_ports};
use crate::resolver::resolve_hostname;
use crate::service_probe::{ProbeRegistry, ServiceTarget};
use crate::target::expand_target_to_ips;
use crate::types::{
    LiveHost, PortResult, PortState, ScanCoverage, ScanError, ScanJob, ScanObservation, ServiceInfo,
};
use chrono::Utc;
use std::collections::HashMap;

pub struct ScanResult {
    pub job_id: String,
    pub hosts: Vec<LiveHost>,
    pub port_results: HashMap<String, Vec<PortResult>>,
    pub coverage: ScanCoverage,
    pub observations: Vec<ScanObservation>,
    pub errors: Vec<ScanError>,
    pub duration_ms: u64,
}

pub struct ScanOrchestrator {
    pub nmap: Option<NmapAdapter>,
    pub probes: ProbeRegistry,
}

impl ScanOrchestrator {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        ScanOrchestrator {
            nmap: NmapAdapter::detect(),
            probes: ProbeRegistry::default(),
        }
    }

    pub async fn execute(&self, job: &ScanJob) -> ScanResult {
        let start_instant = std::time::Instant::now();
        let started_at = Utc::now();
        let mut errors = Vec::new();

        // 1. Target Expansion
        let target_ips = match expand_target_to_ips(&job.target) {
            Ok(ips) => ips,
            Err(e) => {
                errors.push(ScanError {
                    target: format!("{:?}", job.target),
                    stage: "target_expansion".into(),
                    message: e.to_string(),
                });
                vec![]
            }
        };

        let targets_total = target_ips.len() as u32;

        // 2. Host Discovery
        let mut live_hosts = if !target_ips.is_empty() {
            discover_hosts(&target_ips, &job.profile).await
        } else {
            vec![]
        };

        // 3. Port Scanning & Service Probing per live host
        let ports_to_scan = ports_for_profile(&job.profile);
        let mut port_results = HashMap::new();
        let timeout_ms = match job.profile {
            crate::types::ScanProfile::Quick => 150,
            crate::types::ScanProfile::Standard => 300,
            crate::types::ScanProfile::Deep => 600,
        };

        for host in &mut live_hosts {
            let ip_str = host.ip.to_string();

            // Resolve Hostname
            if host.hostname.is_none() {
                host.hostname = resolve_hostname(host.ip).await;
            }

            // Port scanning
            let mut ports = scan_tcp_ports(host.ip, &ports_to_scan, timeout_ms).await;

            // Service probing on OPEN ports
            for p in &mut ports {
                if p.state == PortState::Open {
                    let target = ServiceTarget {
                        ip: host.ip,
                        port: p.port,
                        timeout_ms,
                    };
                    if let Some(obs) = self.probes.probe_port(&target).await {
                        p.service = Some(ServiceInfo {
                            name: obs.service_name,
                            version: obs.version,
                            banner: obs.banner,
                            extra: obs.extra,
                            confidence: obs.confidence,
                            method: obs.method,
                        });
                    }
                }
            }

            port_results.insert(ip_str, ports);
        }

        let completed_at = Utc::now();
        let duration_ms = start_instant.elapsed().as_millis() as u64;

        // 4. Build Observations
        let mut observations = Vec::new();
        for host in &live_hosts {
            let hash_input = format!(
                "{}:{}:{:?}",
                host.ip,
                host.hostname.as_deref().unwrap_or(""),
                job.id.0
            );
            let raw_hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

            observations.push(ScanObservation {
                tool_run_id: job.id.0.clone(),
                collector: "soc-scan-orchestrator".into(),
                collector_version: "0.3.0".into(),
                method: format!("{:?}", host.discovery_method),
                source_target: host.ip.to_string(),
                started_at,
                completed_at,
                confidence: 0.90,
                privilege_level: "user".into(),
                raw_result_hash: raw_hash,
            });
        }

        let mut preliminary_result = ScanResult {
            job_id: job.id.0.clone(),
            hosts: live_hosts,
            port_results,
            coverage: ScanCoverage {
                targets_total,
                targets_responsive: 0,
                tcp_ports_attempted: 0,
                tcp_ports_open: 0,
                tcp_ports_filtered: 0,
                tcp_ports_timeout: 0,
                tcp_ports_closed: 0,
                tcp_ports_error: 0,
                udp_ports_attempted: 0,
                services_identified: 0,
                services_unknown: 0,
                os_identified: 0,
                errors: errors.len() as u32,
                quality: crate::types::CoverageQuality::Full,
                confidence: 1.0,
                scan_duration_ms: duration_ms,
                privilege_level: "user".into(),
                nmap_available: self.nmap.is_some(),
                note: None,
            },
            observations,
            errors,
            duration_ms,
        };

        let coverage =
            compute_coverage(job, &preliminary_result, targets_total, self.nmap.is_some());
        preliminary_result.coverage = coverage;

        preliminary_result
    }
}
