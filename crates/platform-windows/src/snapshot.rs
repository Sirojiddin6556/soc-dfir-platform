#![forbid(unsafe_code)]

use crate::persistence::{enumerate_registry_autoruns, enumerate_scheduled_tasks};
use crate::process::enumerate_processes_deep;
use crate::service::enumerate_services_deep;
use crate::socket::enumerate_sockets_deep;
use crate::software::enumerate_installed_software;
use crate::system::{collect_os_info, collect_users};
use chrono::Utc;
pub use host_snapshot::HostSnapshot;

/// Backwards compatible name.
pub type WindowsHostSnapshot = HostSnapshot;

/// Collects a live snapshot of the Windows machine this process runs on.
/// Each section that fails stays empty and its error is recorded in
/// `collection_errors`; nothing is substituted. On non-Windows builds every
/// section reports that it requires Windows.
pub fn collect_windows_snapshot() -> HostSnapshot {
    let now = Utc::now().to_rfc3339();
    let hostname = crate::local_hostname();
    let mut snap = HostSnapshot::empty(
        format!("SNAP-{}", uuid::Uuid::now_v7()),
        hostname.clone(),
        "windows",
        now,
    );
    snap.os_family = "windows".to_string();
    let mut errors = Vec::new();
    fn take<T>(r: Result<Vec<T>, String>, errors: &mut Vec<String>) -> Vec<T> {
        r.unwrap_or_else(|e| {
            errors.push(e);
            Vec::new()
        })
    }

    match collect_os_info() {
        Ok(os) => {
            snap.os = os.display_name();
            snap.os_version = os.version.clone();
            snap.kernel = os.kernel();
            snap.architecture = os.architecture.clone();
            snap.os_build = os.build;
            snap.os_ubr = os.ubr;
            snap.installed_kbs = os.kbs.clone();
            snap.ip_addresses = os.ip_addresses.clone();
            if !os.display_version.is_empty() {
                snap.os_codename = Some(os.display_version.clone());
            }
        }
        Err(e) => errors.push(e),
    }
    snap.host_ip = host_snapshot::primary_ip()
        .map(|ip| ip.to_string())
        .or_else(|| snap.ip_addresses.first().cloned())
        .unwrap_or_default();
    if snap.host_ip.is_empty() {
        errors.push("Не удалось определить основной IP-адрес (нет маршрута)".to_string());
    }

    match collect_users() {
        Ok((names, accounts)) => {
            snap.users = names;
            snap.user_accounts = accounts;
        }
        Err(e) => errors.push(e),
    }

    snap.processes = take(enumerate_processes_deep(&hostname), &mut errors);
    snap.sockets = take(enumerate_sockets_deep(), &mut errors);
    let names: std::collections::HashMap<u32, String> = snap
        .processes
        .iter()
        .map(|p| (p.pid, p.name.clone()))
        .collect();
    for sock in &mut snap.sockets {
        sock.process_name = names.get(&sock.pid).cloned();
    }
    snap.services = take(enumerate_services_deep(), &mut errors);
    snap.autoruns = take(enumerate_registry_autoruns(), &mut errors);
    snap.scheduled_tasks = take(enumerate_scheduled_tasks(), &mut errors);
    snap.software = take(enumerate_installed_software(), &mut errors);
    match crate::WindowsPlatformHooks::new().query_firewall_rules() {
        Ok(rules) => snap.firewall_rules = rules,
        Err(e) => errors.push(e.to_string()),
    }
    snap.collection_errors = errors;
    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_build_reports_instead_of_fabricating() {
        let snap = collect_windows_snapshot();
        assert_eq!(snap.platform, "windows");
        assert!(snap.os.is_empty(), "no hardcoded Windows edition");
        assert!(snap.users.is_empty(), "no hardcoded accounts");
        assert!(snap.processes.is_empty());
        assert_ne!(snap.host_ip, "127.0.0.1");
        assert!(!snap.collection_errors.is_empty());
    }

    /// Live: runs only on Windows and checks the snapshot against facts the
    /// test establishes independently.
    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_deep_snapshot() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let snap = collect_windows_snapshot();
        let me = std::process::id();

        assert_eq!(snap.host, std::env::var("COMPUTERNAME").unwrap());
        assert!(snap.os.contains("Windows"), "os = {}", snap.os);
        assert!(snap.os_build.is_some());
        assert_ne!(snap.host_ip, "127.0.0.1");
        let proc_me = snap
            .processes
            .iter()
            .find(|p| p.pid == me)
            .expect("current process listed");
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            proc_me
                .executable_path
                .as_deref()
                .map(str::to_ascii_lowercase),
            exe.to_str().map(str::to_ascii_lowercase)
        );
        // Local accounts come from Get-LocalUser and are qualified with the
        // real computer name (the current user may be a domain account, so
        // it is not required to be among them).
        assert!(!snap.user_accounts.is_empty());
        let prefix = format!("{}\\", snap.host).to_ascii_lowercase();
        assert!(snap
            .users
            .iter()
            .all(|u| u.to_ascii_lowercase().starts_with(&prefix)));
        assert!(snap.user_accounts.iter().all(|u| u.sid.is_some()));
        assert!(snap
            .sockets
            .iter()
            .any(|s| s.local_port == port && s.pid == me && s.state == "Listen"));
        assert!(!snap.services.is_empty());
        assert!(!snap.scheduled_tasks.is_empty());
        assert!(!snap.software.is_empty());
        drop(listener);
    }
}
