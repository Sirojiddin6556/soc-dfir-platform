#![forbid(unsafe_code)]

use chrono::Utc;
use core_domain::epistemic::{PainLevel, Severity};
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use correlation_engine::DeterministicCorrelationEngine;
use platform_windows::{WindowsHostSnapshot, WindowsPlatformHooks};
use serde_json::json;
use std::sync::Mutex;
use storage_sqlite::SqliteStorage;

static LATEST_SNAPSHOT: Mutex<Option<WindowsHostSnapshot>> = Mutex::new(None);

/// Collects or gets cached deep Windows host snapshot
pub fn get_or_collect_snapshot(host_id: &str) -> WindowsHostSnapshot {
    let mut guard = LATEST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(ref snap) = *guard {
        return snap.clone();
    }

    let hooks = WindowsPlatformHooks::new();
    let snap = hooks
        .collect_snapshot(host_id)
        .unwrap_or_else(|_| platform_windows::collect_windows_snapshot(host_id, vec![]));

    *guard = Some(snap.clone());
    snap
}

/// Forces a fresh live snapshot collection
pub fn refresh_snapshot(host_id: &str) -> WindowsHostSnapshot {
    let mut guard = LATEST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner());
    let hooks = WindowsPlatformHooks::new();
    let snap = hooks
        .collect_snapshot(host_id)
        .unwrap_or_else(|_| platform_windows::collect_windows_snapshot(host_id, vec![]));
    *guard = Some(snap.clone());
    snap
}

/// Returns host overview and telemetry counts
pub fn handle_host_overview(host_id: &str) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    json!({
        "snapshot_id": snap.snapshot_id,
        "host": snap.host,
        "host_ip": snap.host_ip,
        "os": snap.os,
        "collected_at": snap.collected_at,
        "counts": {
            "processes": snap.processes.len(),
            "sockets": snap.sockets.len(),
            "services": snap.services.len(),
            "scheduled_tasks": snap.scheduled_tasks.len(),
            "autoruns": snap.autoruns.len(),
            "software": snap.software.len(),
            "users": snap.users.len(),
            "firewall_rules": snap.firewall_rules.len(),
        }
    })
}

/// Returns process telemetry formatted for both Table and Tree rendering
pub fn handle_host_processes(host_id: &str) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    json!({
        "host": snap.host,
        "count": snap.processes.len(),
        "processes": snap.processes
    })
}

/// Returns network socket telemetry mapped to PIDs
pub fn handle_host_sockets(host_id: &str) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    json!({
        "host": snap.host,
        "count": snap.sockets.len(),
        "sockets": snap.sockets
    })
}

/// Returns Windows services telemetry with unquoted path analysis
pub fn handle_host_services(host_id: &str) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    json!({
        "host": snap.host,
        "count": snap.services.len(),
        "services": snap.services
    })
}

/// Returns persistence points (autoruns and scheduled tasks)
pub fn handle_host_persistence(host_id: &str) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    json!({
        "host": snap.host,
        "autoruns": snap.autoruns,
        "scheduled_tasks": snap.scheduled_tasks
    })
}

/// Returns installed software inventory
pub fn handle_host_software(host_id: &str) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    json!({
        "host": snap.host,
        "count": snap.software.len(),
        "software": snap.software
    })
}

/// Correlates live host snapshot telemetry against detection rules
pub fn handle_host_correlation(
    host_id: &str,
    case_id: EntityId,
    storage: &SqliteStorage,
    correlator: &DeterministicCorrelationEngine,
) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    let mut observations = Vec::new();

    let pid_map: std::collections::HashMap<u32, &str> = snap
        .processes
        .iter()
        .map(|p| (p.pid, p.name.as_str()))
        .collect();

    for p in &snap.processes {
        let parent_name = pid_map.get(&p.ppid).copied().unwrap_or("");
        observations.push(Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: "windows_process_collector".to_string(),
            raw_event_type: "process".to_string(),
            source_timestamp: Utc::now(),
            ingest_timestamp: Utc::now(),
            data: json!({
                "process_name": p.name,
                "pid": p.pid,
                "ppid": p.ppid,
                "parent_name": parent_name,
                "executable_path": p.executable_path,
                "command_line": p.command_line,
                "username": p.username,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        });
    }

    for s in &snap.sockets {
        observations.push(Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: "windows_socket_collector".to_string(),
            raw_event_type: "network_socket".to_string(),
            source_timestamp: Utc::now(),
            ingest_timestamp: Utc::now(),
            data: json!({
                "local_address": s.local_address,
                "local_port": s.local_port,
                "destination_ip": s.remote_address,
                "destination_port": s.remote_port,
                "state": s.state,
                "owning_pid": s.pid,
                "process_name": s.process_name,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        });
    }

    for srv in &snap.services {
        observations.push(Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: "windows_service_collector".to_string(),
            raw_event_type: "service".to_string(),
            source_timestamp: Utc::now(),
            ingest_timestamp: Utc::now(),
            data: json!({
                "service_name": srv.service_name,
                "display_name": srv.display_name,
                "status": srv.state,
                "binary_path": srv.binary_path,
                "unquoted_risk": srv.unquoted_risk,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        });
    }

    for a in &snap.autoruns {
        observations.push(Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: "windows_autorun_collector".to_string(),
            raw_event_type: "autorun".to_string(),
            source_timestamp: Utc::now(),
            ingest_timestamp: Utc::now(),
            data: json!({
                "autorun_key": a.key,
                "item_name": a.value_name,
                "target_path": a.resolved_executable,
                "value_data": a.value_data,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        });
    }

    for t in &snap.scheduled_tasks {
        observations.push(Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: "windows_task_collector".to_string(),
            raw_event_type: "scheduled_task".to_string(),
            source_timestamp: Utc::now(),
            ingest_timestamp: Utc::now(),
            data: json!({
                "task_name": t.task_name,
                "task_path": t.task_path,
                "state": t.state,
                "action": t.action,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        });
    }

    let raw_facts = correlator.correlate(&observations).unwrap_or_default();

    // Filter only genuine findings (non-info or risk >= 20.0)
    let findings: Vec<_> = raw_facts
        .into_iter()
        .filter(|f| f.severity != Severity::Info && f.risk_score >= 20.0)
        .collect();

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut ttps_count = 0;
    let mut tools_count = 0;
    let mut artifacts_count = 0;
    let mut ips_count = 0;
    let mut domains_count = 0;
    let mut hashes_count = 0;
    let mut max_risk = 1.0f32;

    let mut findings_json = Vec::new();
    let mut mitre_entries = Vec::new();

    for f in &findings {
        if f.severity == Severity::Critical {
            critical_count += 1;
        } else if f.severity == Severity::High {
            high_count += 1;
        }
        if f.risk_score > max_risk {
            max_risk = f.risk_score;
        }

        match f.pain_level {
            Some(PainLevel::TTPs) => ttps_count += 1,
            Some(PainLevel::Tools) => tools_count += 1,
            Some(PainLevel::HostArtifacts) | Some(PainLevel::NetworkArtifacts) => {
                artifacts_count += 1
            }
            Some(PainLevel::IpAddresses) => ips_count += 1,
            Some(PainLevel::DomainNames) => domains_count += 1,
            Some(PainLevel::HashValues) => hashes_count += 1,
            None => {}
        }

        if let (Some(tech), Some(tac)) = (
            f.data.get("mitre_technique").and_then(|v| v.as_str()),
            f.data.get("mitre_tactic").and_then(|v| v.as_str()),
        ) {
            mitre_entries.push(json!({
                "tactic": tac,
                "technique_id": tech,
                "name": f.data.get("title").and_then(|v| v.as_str()).unwrap_or(&f.fact_type),
                "confidence": f.confidence.value(),
                "severity": format!("{:?}", f.severity)
            }));
        }

        findings_json.push(json!({
            "id": f.id.to_string(),
            "fact_type": f.fact_type,
            "title": f.data.get("title").and_then(|v| v.as_str()).unwrap_or(&f.fact_type),
            "severity": format!("{:?}", f.severity),
            "risk_score": f.risk_score,
            "entity_key": f.entity_key,
            "rule_id": f.data.get("rule_id").and_then(|v| v.as_str()).unwrap_or(""),
            "mitre_technique": f.data.get("mitre_technique").and_then(|v| v.as_str()),
            "mitre_tactic": f.data.get("mitre_tactic").and_then(|v| v.as_str()),
            "verification_state": format!("{:?}", f.verification_state),
            "created_at": f.created_at.to_rfc3339()
        }));

        let _ = storage.insert_fact(f);
    }

    let risk_level = if max_risk >= 80.0 {
        "КРИТИЧЕСКИЙ"
    } else if max_risk >= 50.0 {
        "ВЫСОКИЙ"
    } else if max_risk >= 20.0 {
        "СРЕДНИЙ"
    } else {
        "НИЗКИЙ"
    };

    json!({
        "host": snap.host,
        "case_id": case_id.to_string(),
        "status": if findings.is_empty() { "baseline_clean" } else { "anomalies_detected" },
        "findings_count": findings.len(),
        "critical_count": critical_count,
        "high_count": high_count,
        "risk_score": max_risk,
        "risk_level": risk_level,
        "findings": findings_json,
        "mitre_matrix": mitre_entries,
        "pyramid": {
            "ttps": ttps_count,
            "tools": tools_count,
            "artifacts": artifacts_count,
            "domains": domains_count,
            "ips": ips_count,
            "hashes": hashes_count
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_inspector_handlers() {
        let overview = handle_host_overview("PC-3002");
        assert!(overview.get("host").is_some());
        assert!(overview.get("counts").is_some());

        let procs = handle_host_processes("PC-3002");
        assert!(procs.get("processes").is_some());

        let socks = handle_host_sockets("PC-3002");
        assert!(socks.get("sockets").is_some());

        let srvs = handle_host_services("PC-3002");
        assert!(srvs.get("services").is_some());

        let persist = handle_host_persistence("PC-3002");
        assert!(persist.get("autoruns").is_some());

        let soft = handle_host_software("PC-3002");
        assert!(soft.get("software").is_some());

        let storage = SqliteStorage::open_in_memory().unwrap();
        let correlator = DeterministicCorrelationEngine::new();
        let cid = EntityId::new_v7();
        let res = handle_host_correlation("PC-3002", cid, &storage, &correlator);
        assert!(res.get("findings").is_some());
        assert!(res.get("pyramid").is_some());
        assert!(res.get("mitre_matrix").is_some());
    }
}
