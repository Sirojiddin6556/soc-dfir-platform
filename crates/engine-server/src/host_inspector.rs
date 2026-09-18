#![forbid(unsafe_code)]

use platform_windows::{WindowsHostSnapshot, WindowsPlatformHooks};
use serde_json::json;
use std::sync::Mutex;

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
    }
}
