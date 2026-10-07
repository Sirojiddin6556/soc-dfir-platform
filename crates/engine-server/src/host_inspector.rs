#![forbid(unsafe_code)]

//! Live inspection of the machine the engine runs on.
//!
//! Collection is dispatched at compile time to the collector for the
//! running OS (`platform-linux` on Linux, `platform-windows` on Windows).
//! Live collection can only observe the local machine: a `host_id` that
//! does not designate it is answered with an empty snapshot that says so in
//! `collection_errors` -- never with this machine's data relabelled.

use chrono::Utc;
use core_domain::epistemic::{PainLevel, Severity};
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use correlation_engine::DeterministicCorrelationEngine;
use host_snapshot::HostSnapshot;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Mutex;
use storage_sqlite::SqliteStorage;

/// Snapshots keyed by canonical host key. Only the local machine can be
/// collected, so in practice this holds at most one entry: the real
/// hostname.
static SNAPSHOTS: Mutex<BTreeMap<String, HostSnapshot>> = Mutex::new(BTreeMap::new());

/// Returns the canonical cache key (the real hostname) when `host_id`
/// designates the machine the engine runs on: an empty id, a loopback alias
/// (`local`, `localhost`, `h_local`, `127.0.0.1`, `::1`), the hostname (or
/// its short form) or the primary IP address.
pub fn local_host_key(host_id: &str) -> Option<String> {
    let hostname = crate::default_host_id();
    let id = host_id.trim().to_ascii_lowercase();
    let host_lower = hostname.to_ascii_lowercase();
    let short = host_lower.split('.').next().unwrap_or(&host_lower);
    let is_local = id.is_empty()
        || matches!(
            id.as_str(),
            "local" | "localhost" | "h_local" | "127.0.0.1" | "::1"
        )
        || id == host_lower
        || id == short
        || host_snapshot::primary_ip().is_some_and(|ip| ip.to_string() == id);
    is_local.then(|| hostname.to_string())
}

fn collect_local() -> HostSnapshot {
    #[cfg(target_os = "linux")]
    {
        platform_linux::collect_host_snapshot()
    }
    #[cfg(target_os = "windows")]
    {
        platform_windows::collect_windows_snapshot()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let mut snap = HostSnapshot::empty(
            format!("SNAP-{}", uuid::Uuid::now_v7()),
            crate::default_host_id().to_string(),
            std::env::consts::OS,
            Utc::now().to_rfc3339(),
        );
        snap.collection_errors.push(format!(
            "Live-инспекция для ОС '{}' не реализована",
            std::env::consts::OS
        ));
        snap
    }
}

/// Answer for a host that is not this machine: nothing is collected.
fn not_local_snapshot(host_id: &str) -> HostSnapshot {
    let mut snap = HostSnapshot::empty(
        format!("SNAP-{}", uuid::Uuid::now_v7()),
        host_id.to_string(),
        "unknown",
        Utc::now().to_rfc3339(),
    );
    snap.collection_errors.push(format!(
        "Хост '{}' не является машиной, на которой работает движок ({}): live-инспекция \
         выполняется только локально, данные не собирались",
        host_id,
        crate::default_host_id()
    ));
    snap
}

/// Returns the cached live snapshot of the local machine, collecting it on
/// first use.
pub fn get_or_collect_snapshot(host_id: &str) -> HostSnapshot {
    let Some(key) = local_host_key(host_id) else {
        return not_local_snapshot(host_id);
    };
    // Held during collection so concurrent first requests collect once.
    let mut guard = SNAPSHOTS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(snap) = guard.get(&key) {
        return snap.clone();
    }
    let snap = collect_local();
    guard.insert(key, snap.clone());
    snap
}

/// Forces a fresh live collection of the local machine.
pub fn refresh_snapshot(host_id: &str) -> HostSnapshot {
    let Some(key) = local_host_key(host_id) else {
        return not_local_snapshot(host_id);
    };
    let mut guard = SNAPSHOTS.lock().unwrap_or_else(|p| p.into_inner());
    let snap = collect_local();
    guard.insert(key, snap.clone());
    snap
}

/// Returns host overview and telemetry counts
pub fn handle_host_overview(host_id: &str) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    json!({
        "snapshot_id": snap.snapshot_id,
        "host": snap.host,
        "host_ip": snap.host_ip,
        "ip_addresses": snap.ip_addresses,
        "os": snap.os,
        "platform": snap.platform,
        "os_family": snap.os_family,
        "os_version": snap.os_version,
        "os_codename": snap.os_codename,
        "kernel": snap.kernel,
        "architecture": snap.architecture,
        "collected_at": snap.collected_at,
        "collector_version": snap.collector_version,
        "collection_errors": snap.collection_errors,
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

/// Returns services (Windows SCM / systemd / SysV)
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

/// Turns a snapshot into correlation observations. Field names follow the
/// conventions the correlation rules read (`process_name`, `command_line`,
/// `destination_ip`, `mechanism`, ...); `platform` lets rules scope
/// OS-specific semantics.
pub fn snapshot_observations(snap: &HostSnapshot, case_id: EntityId) -> Vec<Observation> {
    let platform = if snap.platform.is_empty() {
        "host"
    } else {
        snap.platform.as_str()
    };
    let now = Utc::now();
    let observation = |collector: &str, event_type: &str, data: serde_json::Value| Observation {
        id: EntityId::new_v7(),
        case_id,
        artifact_id: None,
        tool_run_id: None,
        source_tool: format!("{}_{}_collector", platform, collector),
        raw_event_type: event_type.to_string(),
        source_timestamp: Some(now),
        ingest_timestamp: now,
        data,
        network_quality: None,
        network_provenance: None,
    };
    let mut observations = Vec::new();

    let pid_map: std::collections::HashMap<u32, &str> = snap
        .processes
        .iter()
        .map(|p| (p.pid, p.name.as_str()))
        .collect();

    for p in &snap.processes {
        let parent_name = pid_map.get(&p.ppid).copied().unwrap_or("");
        observations.push(observation(
            "process",
            "process",
            json!({
                "process_name": p.name,
                "pid": p.pid,
                "ppid": p.ppid,
                "parent_name": parent_name,
                "executable_path": p.executable_path,
                "command_line": p.command_line,
                "username": p.username,
                "uid": p.uid,
                "exe_deleted": p.exe_deleted,
                "sha256": p.sha256,
                "started_at": p.started_at,
                "platform": platform,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        ));
    }

    for s in &snap.sockets {
        observations.push(observation(
            "socket",
            "network_socket",
            json!({
                "protocol": s.protocol,
                "local_address": s.local_address,
                "local_port": s.local_port,
                "destination_ip": s.remote_address,
                "destination_port": s.remote_port,
                "state": s.state,
                "owning_pid": s.pid,
                "process_name": s.process_name,
                "platform": platform,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        ));
    }

    for srv in &snap.services {
        observations.push(observation(
            "service",
            "service",
            json!({
                "service_name": srv.service_name,
                "display_name": srv.display_name,
                "status": srv.state,
                "start_type": srv.start_type,
                "binary_path": srv.binary_path,
                "account": srv.account,
                "unquoted_risk": srv.unquoted_risk,
                "platform": platform,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        ));
    }

    for a in &snap.autoruns {
        observations.push(observation(
            "autorun",
            "autorun",
            json!({
                "autorun_key": a.key,
                "item_name": a.value_name,
                "target_path": a.resolved_executable,
                "value_data": a.value_data,
                "mechanism": a.mechanism,
                "owner": a.owner,
                "platform": platform,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        ));
    }

    for t in &snap.scheduled_tasks {
        // The full command (executable + arguments) is what runs.
        let action = match (&t.action, &t.arguments) {
            (Some(a), Some(args)) if !args.trim().is_empty() => Some(format!("{} {}", a, args)),
            (a, _) => a.clone(),
        };
        observations.push(observation(
            "task",
            "scheduled_task",
            json!({
                "task_name": t.task_name,
                "task_path": t.task_path,
                "state": t.state,
                "action": action,
                "arguments": t.arguments,
                "mechanism": t.mechanism,
                "schedule": t.schedule,
                "user": t.user,
                "platform": platform,
                "host": snap.host,
                "host_ip": snap.host_ip
            }),
        ));
    }
    observations
}

/// Correlates live host snapshot telemetry against detection rules
pub fn handle_host_correlation(
    host_id: &str,
    case_id: EntityId,
    storage: &SqliteStorage,
    correlator: &DeterministicCorrelationEngine,
) -> serde_json::Value {
    let snap = get_or_collect_snapshot(host_id);
    let observations = snapshot_observations(&snap, case_id);

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
        // Same finding seen again keeps its original id and first-seen time.
        let (fact_id, first_seen) = storage.insert_fact_dedup(f).unwrap_or((f.id, f.created_at));
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
            "id": fact_id.to_string(),
            "fact_type": f.fact_type,
            "title": f.data.get("title").and_then(|v| v.as_str()).unwrap_or(&f.fact_type),
            "severity": format!("{:?}", f.severity),
            "risk_score": f.risk_score,
            "entity_key": f.entity_key,
            "rule_id": f.data.get("rule_id").and_then(|v| v.as_str()).unwrap_or(""),
            "mitre_technique": f.data.get("mitre_technique").and_then(|v| v.as_str()),
            "mitre_tactic": f.data.get("mitre_tactic").and_then(|v| v.as_str()),
            "pid": f.data.get("pid").or_else(|| f.data.get("owning_pid")),
            "verification_state": format!("{:?}", f.verification_state),
            "created_at": first_seen.to_rfc3339()
        }));
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
        "platform": snap.platform,
        "case_id": case_id.to_string(),
        "status": if findings.is_empty() { "baseline_clean" } else { "anomalies_detected" },
        "observations_evaluated": observations.len(),
        "collection_errors": snap.collection_errors,
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
    fn local_aliases_resolve_to_the_real_hostname() {
        let hostname = crate::default_host_id();
        for alias in ["", "local", "localhost", "h_local", "127.0.0.1", hostname] {
            assert_eq!(local_host_key(alias).as_deref(), Some(hostname), "{alias}");
        }
        assert_eq!(
            local_host_key(&hostname.to_ascii_uppercase()).as_deref(),
            Some(hostname)
        );
        assert_eq!(local_host_key("PC-3002-definitely-not-this-host"), None);
    }

    #[test]
    fn remote_host_ids_are_not_answered_with_local_data() {
        let remote = "PC-3002-definitely-not-this-host";
        let overview = handle_host_overview(remote);
        assert_eq!(overview["host"], remote);
        assert_eq!(overview["counts"]["processes"], 0);
        assert_eq!(overview["host_ip"], "");
        assert!(!overview["collection_errors"].as_array().unwrap().is_empty());
        assert_eq!(handle_host_processes(remote)["count"], 0);
        assert_eq!(handle_host_software(remote)["count"], 0);

        let storage = SqliteStorage::open_in_memory().unwrap();
        let res = handle_host_correlation(
            remote,
            EntityId::new_v7(),
            &storage,
            &DeterministicCorrelationEngine::new(),
        );
        assert_eq!(res["findings_count"], 0);
        assert_eq!(res["observations_evaluated"], 0);
    }

    #[test]
    fn handlers_return_the_expected_shape() {
        let local = crate::default_host_id();
        assert!(handle_host_processes(local).get("processes").is_some());
        assert!(handle_host_sockets(local).get("sockets").is_some());
        assert!(handle_host_services(local).get("services").is_some());
        let persist = handle_host_persistence(local);
        assert!(persist.get("autoruns").is_some());
        assert!(persist.get("scheduled_tasks").is_some());
        assert!(handle_host_software(local).get("software").is_some());

        let storage = SqliteStorage::open_in_memory().unwrap();
        let res = handle_host_correlation(
            local,
            EntityId::new_v7(),
            &storage,
            &DeterministicCorrelationEngine::new(),
        );
        assert!(res.get("findings").is_some());
        assert!(res.get("pyramid").is_some());
        assert!(res.get("mitre_matrix").is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_overview_describes_this_machine() {
        let local = crate::default_host_id();
        let overview = handle_host_overview(local);
        assert_eq!(overview["platform"], "linux");
        assert_eq!(overview["host"], local);
        assert_ne!(overview["host_ip"], "127.0.0.1");
        assert!(!overview["os"].as_str().unwrap().contains("Windows"));
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
        assert_eq!(overview["kernel"], kernel.trim());
        assert!(overview["counts"]["processes"].as_u64().unwrap() > 0);
        assert!(overview["counts"]["users"].as_u64().unwrap() > 0);

        let procs = handle_host_processes("localhost");
        let me = std::process::id();
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        // Every snapshot taken inside this test binary includes the binary
        // itself, whichever test triggered the collection.
        let mine = procs["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["pid"] == me)
            .expect("current process in snapshot");
        assert_eq!(mine["executable_path"], exe.to_str().unwrap());
    }

    /// End to end on the real host: a process genuinely running from /tmp
    /// must be collected and flagged by CORR-LIN-001b.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_correlation_flags_real_process_running_from_tmp() {
        let dir = std::path::Path::new("/tmp")
            .join(format!("soc-dfir-inspector-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let sleeper = dir.join("sleep");
        let src = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .expect("coreutils sleep");
        std::fs::copy(src, &sleeper).unwrap();
        let mut child = std::process::Command::new(&sleeper)
            .arg("60")
            .spawn()
            .expect("/tmp must allow exec for this test");

        let local = crate::default_host_id();
        refresh_snapshot(local);
        let storage = SqliteStorage::open_in_memory().unwrap();
        let case = EntityId::new_v7();
        storage
            .insert_case(case, "Live /tmp execution", None)
            .unwrap();
        let res = handle_host_correlation(
            local,
            case,
            &storage,
            &DeterministicCorrelationEngine::new(),
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);

        let finding = res["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["rule_id"] == "CORR-LIN-001b" && f["pid"] == child.id())
            .unwrap_or_else(|| panic!("no CORR-LIN-001b finding for pid {}: {}", child.id(), res));
        assert_eq!(finding["mitre_technique"], "T1036.005");
        assert!(finding["title"]
            .as_str()
            .unwrap()
            .contains(sleeper.to_str().unwrap()));
        let stored = storage.get_facts_for_case(case).unwrap();
        assert!(stored
            .iter()
            .any(|f| f.data["rule_id"] == "CORR-LIN-001b" && f.data["pid"] == child.id()));
    }
}
