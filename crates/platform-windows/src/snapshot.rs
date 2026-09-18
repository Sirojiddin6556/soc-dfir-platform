#![forbid(unsafe_code)]

use crate::persistence::{
    enumerate_registry_autoruns, enumerate_scheduled_tasks, RegistryAutorunObservation,
    ScheduledTaskObservation,
};
use crate::process::{enumerate_processes_deep, ProcessObservation};
use crate::service::{enumerate_services_deep, ServiceObservation};
use crate::socket::{enumerate_sockets_deep, SocketObservation};
use crate::software::{enumerate_installed_software, SoftwareObservation};
use crate::WindowsFirewallRule;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsHostSnapshot {
    pub snapshot_id: String,
    pub host: String,
    pub host_ip: String,
    pub os: String,
    pub processes: Vec<ProcessObservation>,
    pub sockets: Vec<SocketObservation>,
    pub services: Vec<ServiceObservation>,
    pub scheduled_tasks: Vec<ScheduledTaskObservation>,
    pub autoruns: Vec<RegistryAutorunObservation>,
    pub software: Vec<SoftwareObservation>,
    pub users: Vec<String>,
    pub firewall_rules: Vec<WindowsFirewallRule>,
    pub collected_at: String,
    pub collector_version: String,
}

pub fn collect_windows_snapshot(
    host_id: &str,
    firewall_rules: Vec<WindowsFirewallRule>,
) -> WindowsHostSnapshot {
    let now = Utc::now().to_rfc3339();
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| host_id.to_string());
    let snap_id = format!("SNAP-{}", uuid::Uuid::now_v7());

    let processes = enumerate_processes_deep(&hostname);
    let mut sockets = enumerate_sockets_deep();

    // Map process names onto sockets using PID map
    let proc_map: std::collections::HashMap<u32, String> =
        processes.iter().map(|p| (p.pid, p.name.clone())).collect();

    for sock in &mut sockets {
        if let Some(name) = proc_map.get(&sock.pid) {
            sock.process_name = Some(name.clone());
        }
    }

    let services = enumerate_services_deep();
    let autoruns = enumerate_registry_autoruns();
    let scheduled_tasks = enumerate_scheduled_tasks();
    let software = enumerate_installed_software();

    let users = vec![
        format!("{}\\Administrator", hostname),
        format!("{}\\Siroj", hostname),
        "NT AUTHORITY\\SYSTEM".to_string(),
        "NT AUTHORITY\\LocalService".to_string(),
        "NT AUTHORITY\\NetworkService".to_string(),
    ];

    WindowsHostSnapshot {
        snapshot_id: snap_id,
        host: hostname,
        host_ip: "127.0.0.1".to_string(),
        os: "Windows 11 Enterprise (x86_64)".to_string(),
        processes,
        sockets,
        services,
        scheduled_tasks,
        autoruns,
        software,
        users,
        firewall_rules,
        collected_at: now,
        collector_version: "0.2.0".to_string(),
    }
}
