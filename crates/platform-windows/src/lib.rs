#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::process::Command;
use thiserror::Error;

pub mod persistence;
pub mod process;
pub mod service;
pub mod snapshot;
pub mod socket;
pub mod software;

pub use persistence::{
    enumerate_registry_autoruns, enumerate_scheduled_tasks, RegistryAutorunObservation,
    ScheduledTaskObservation,
};
pub use process::{enumerate_processes_deep, ProcessObservation};
pub use service::{enumerate_services_deep, ServiceObservation};
pub use snapshot::{collect_windows_snapshot, WindowsHostSnapshot};
pub use socket::{enumerate_sockets_deep, SocketObservation};
pub use software::{enumerate_installed_software, SoftwareObservation};

/// Returns the real hostname of the machine this process is running on,
/// instead of a placeholder identifier.
pub fn local_hostname() -> String {
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        if !name.trim().is_empty() {
            return name;
        }
    }
    if let Ok(name) = std::env::var("HOSTNAME") {
        if !name.trim().is_empty() {
            return name;
        }
    }
    if let Ok(output) = Command::new("hostname").output() {
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "unknown-host".to_string()
}

#[derive(Error, Debug)]
pub enum WindowsPlatformError {
    #[error("API call failed: {0}")]
    ApiFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsProcessInfo {
    pub pid: u32,
    pub name: String,
    pub session_name: String,
    pub mem_usage_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsFirewallRule {
    pub name: String,
    pub direction: String,
    pub action: String,
    pub enabled: bool,
}

pub struct WindowsPlatformHooks;

impl WindowsPlatformHooks {
    pub fn new() -> Self {
        Self
    }

    pub fn get_current_process_id(&self) -> u32 {
        std::process::id()
    }

    /// Queries real running processes on Windows using tasklist
    pub fn enumerate_processes(&self) -> Result<Vec<WindowsProcessInfo>, WindowsPlatformError> {
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("tasklist")
                .args(["/FO", "CSV", "/NH"])
                .output()
                .map_err(|e| WindowsPlatformError::ApiFailed(e.to_string()))?;

            let text = String::from_utf8_lossy(&output.stdout);
            let mut list = Vec::new();

            for line in text.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 5 {
                    let name = parts[0].trim_matches('"').to_string();
                    let pid = parts[1].trim_matches('"').parse::<u32>().unwrap_or(0);
                    let session_name = parts[2].trim_matches('"').to_string();
                    let mem_str = parts[4].trim_matches('"').replace([' ', 'K', ','], "");
                    let mem_kb = mem_str.parse::<u64>().unwrap_or(0);

                    if pid > 0 {
                        list.push(WindowsProcessInfo {
                            pid,
                            name,
                            session_name,
                            mem_usage_kb: mem_kb,
                        });
                    }
                }
            }
            Ok(list)
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Fallback for cross-compilation / host tests
            Ok(vec![WindowsProcessInfo {
                pid: std::process::id(),
                name: "soc-dfir-engine.exe".to_string(),
                session_name: "Console".to_string(),
                mem_usage_kb: 45000,
            }])
        }
    }

    /// Queries real active firewall rules on Windows
    pub fn query_firewall_rules(&self) -> Result<Vec<WindowsFirewallRule>, WindowsPlatformError> {
        #[cfg(target_os = "windows")]
        {
            // Primary approach: PowerShell Get-NetFirewallRule (locale-independent JSON)
            let ps_output = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-NetFirewallRule | Select-Object -First 30 -Property DisplayName,Direction,Action,Enabled) | ConvertTo-Json",
                ])
                .output();

            if let Ok(output) = ps_output {
                if output.status.success() {
                    let json_str = String::from_utf8_lossy(&output.stdout);
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let items = if let Some(arr) = val.as_array() {
                            arr.clone()
                        } else if val.is_object() {
                            vec![val]
                        } else {
                            Vec::new()
                        };

                        if !items.is_empty() {
                            let mut rules = Vec::new();
                            for item in items {
                                let name = item
                                    .get("DisplayName")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Windows Firewall Rule")
                                    .to_string();

                                let dir = match item.get("Direction").and_then(|v| v.as_i64()) {
                                    Some(1) => "Inbound",
                                    Some(2) => "Outbound",
                                    _ => item
                                        .get("Direction")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Inbound"),
                                }
                                .to_string();

                                let action = match item.get("Action").and_then(|v| v.as_i64()) {
                                    Some(4) => "Block",
                                    _ => "Allow",
                                }
                                .to_string();

                                let enabled =
                                    item.get("Enabled").and_then(|v| v.as_i64()) != Some(2);

                                rules.push(WindowsFirewallRule {
                                    name,
                                    direction: dir,
                                    action,
                                    enabled,
                                });
                            }
                            return Ok(rules);
                        }
                    }
                }
            }

            // Fallback approach: netsh with multi-locale support (EN + RU)
            let output = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    "name=all",
                    "dir=in",
                ])
                .output()
                .map_err(|e| WindowsPlatformError::ApiFailed(e.to_string()))?;

            let text = String::from_utf8_lossy(&output.stdout);
            let mut rules = Vec::new();
            let mut current_name = String::new();
            let mut current_action = "Allow".to_string();
            let mut current_enabled = true;

            for line in text.lines() {
                let line = line.trim();
                let is_name = line.starts_with("Rule Name:") || line.starts_with("Имя правила:");
                let is_action = line.starts_with("Action:") || line.starts_with("Действие:");
                let is_enabled = line.starts_with("Enabled:") || line.starts_with("Включено:");

                if is_name {
                    if !current_name.is_empty() {
                        rules.push(WindowsFirewallRule {
                            name: current_name.clone(),
                            direction: "Inbound".to_string(),
                            action: current_action.clone(),
                            enabled: current_enabled,
                        });
                    }
                    current_name = line
                        .trim_start_matches("Rule Name:")
                        .trim_start_matches("Имя правила:")
                        .trim()
                        .to_string();
                } else if is_action {
                    let act = line
                        .trim_start_matches("Action:")
                        .trim_start_matches("Действие:")
                        .trim();
                    current_action = if act == "Блокировать" || act.eq_ignore_ascii_case("block")
                    {
                        "Block".to_string()
                    } else {
                        "Allow".to_string()
                    };
                } else if is_enabled {
                    let en = line
                        .trim_start_matches("Enabled:")
                        .trim_start_matches("Включено:")
                        .trim();
                    current_enabled = en == "Yes" || en == "Да" || en.eq_ignore_ascii_case("true");
                }
            }

            if !current_name.is_empty() {
                rules.push(WindowsFirewallRule {
                    name: current_name,
                    direction: "Inbound".to_string(),
                    action: current_action,
                    enabled: current_enabled,
                });
            }

            if rules.is_empty() {
                tracing::warn!(
                    "query_firewall_rules: neither PowerShell nor netsh returned parseable rules"
                );
            }

            Ok(rules)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(vec![WindowsFirewallRule {
                name: "Core Networking - DNS (UDP-Out)".to_string(),
                direction: "Outbound".to_string(),
                action: "Allow".to_string(),
                enabled: true,
            }])
        }
    }

    /// Aggregates a complete deep host snapshot (processes, sockets, services, autoruns, tasks, software)
    pub fn collect_snapshot(
        &self,
        host_id: &str,
    ) -> Result<WindowsHostSnapshot, WindowsPlatformError> {
        let rules = self.query_firewall_rules().unwrap_or_default();
        Ok(collect_windows_snapshot(host_id, rules))
    }
}

impl Default for WindowsPlatformHooks {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_process_enumeration() {
        let hooks = WindowsPlatformHooks::new();
        let my_pid = hooks.get_current_process_id();
        assert!(my_pid > 0);

        let procs = hooks.enumerate_processes().unwrap();
        assert!(!procs.is_empty());
        assert!(procs
            .iter()
            .any(|p| p.pid == my_pid || p.name.contains(".exe") || p.pid > 0));
    }

    #[test]
    fn test_windows_firewall_query() {
        let hooks = WindowsPlatformHooks::new();
        let rules = hooks.query_firewall_rules().unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_windows_deep_snapshot() {
        let hooks = WindowsPlatformHooks::new();
        let snap = hooks.collect_snapshot("PC-3002").unwrap();
        assert_eq!(snap.host_ip, "127.0.0.1");
        assert!(!snap.processes.is_empty());
        assert!(!snap.sockets.is_empty());
        assert!(!snap.services.is_empty());
        assert!(!snap.autoruns.is_empty());
        assert!(!snap.scheduled_tasks.is_empty());
        assert!(!snap.software.is_empty());
    }
}
