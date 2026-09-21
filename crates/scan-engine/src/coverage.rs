#![forbid(unsafe_code)]

use crate::orchestrator::ScanResult;
use crate::types::{CoverageQuality, PortState, ScanCoverage, ScanJob};

pub fn compute_coverage(
    _job: &ScanJob,
    result: &ScanResult,
    targets_total: u32,
    nmap_available: bool,
) -> ScanCoverage {
    let mut tcp_attempted = 0u32;
    let mut tcp_open = 0u32;
    let mut tcp_filtered = 0u32;
    let mut tcp_timeout = 0u32;
    let mut tcp_closed = 0u32;
    let mut tcp_error = 0u32;
    let mut services_identified = 0u32;
    let mut services_unknown = 0u32;

    for ports in result.port_results.values() {
        for p in ports {
            tcp_attempted += 1;
            match p.state {
                PortState::Open => {
                    tcp_open += 1;
                    if let Some(ref svc) = p.service {
                        if svc.name != "TCP-Service" && !svc.name.is_empty() {
                            services_identified += 1;
                        } else {
                            services_unknown += 1;
                        }
                    } else {
                        services_unknown += 1;
                    }
                }
                PortState::Closed => tcp_closed += 1,
                PortState::Filtered | PortState::OpenFiltered => tcp_filtered += 1,
                PortState::Timeout => tcp_timeout += 1,
                PortState::Unreachable | PortState::Unknown => tcp_error += 1,
            }
        }
    }

    let quality = if !result.errors.is_empty() || tcp_error > 0 {
        CoverageQuality::Partial
    } else if tcp_timeout > tcp_attempted / 2 && tcp_attempted > 0 {
        CoverageQuality::Degraded
    } else {
        CoverageQuality::Full
    };

    let confidence = if nmap_available { 0.95 } else { 0.85 };

    ScanCoverage {
        targets_total: targets_total.max(result.hosts.len() as u32),
        targets_responsive: result.hosts.len() as u32,
        tcp_ports_attempted: tcp_attempted,
        tcp_ports_open: tcp_open,
        tcp_ports_filtered: tcp_filtered,
        tcp_ports_timeout: tcp_timeout,
        tcp_ports_closed: tcp_closed,
        tcp_ports_error: tcp_error,
        udp_ports_attempted: 0,
        services_identified,
        services_unknown,
        os_identified: result.hosts.len() as u32,
        errors: result.errors.len() as u32,
        quality,
        confidence,
        scan_duration_ms: result.duration_ms,
        privilege_level: if nmap_available {
            "user-nmap".into()
        } else {
            "user".into()
        },
        nmap_available,
        note: if !nmap_available {
            Some("Nmap not detected in PATH; utilized high-speed Rust native TCP probe".into())
        } else {
            None
        },
    }
}

pub fn to_json(coverage: &ScanCoverage) -> serde_json::Value {
    serde_json::to_value(coverage).unwrap_or(serde_json::Value::Null)
}
