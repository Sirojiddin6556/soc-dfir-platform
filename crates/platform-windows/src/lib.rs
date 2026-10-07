#![forbid(unsafe_code)]

//! Live Windows host collector. Every PowerShell script is a static string
//! (see [`ps`]); every parser is a pure function unit-tested with captured
//! output, so the parsing logic is verified on any build host while the
//! live collection itself only runs on Windows.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod discovery;
pub mod persistence;
pub mod process;
pub mod ps;
pub mod service;
pub mod snapshot;
pub mod socket;
pub mod software;
pub mod system;

pub use discovery::{discover_via_arp, discover_via_tcp_probe, DiscoveredHost, DiscoveryMethod};
pub use host_snapshot::{FirewallRule, HostSnapshot, UserAccount};
pub use persistence::{
    enumerate_registry_autoruns, enumerate_scheduled_tasks, AutorunObservation,
    RegistryAutorunObservation, ScheduledTaskObservation,
};
pub use process::{enumerate_processes_deep, ProcessObservation};
pub use service::{enumerate_services_deep, ServiceObservation};
pub use snapshot::{collect_windows_snapshot, WindowsHostSnapshot};
pub use socket::{enumerate_sockets_deep, SocketObservation};
pub use software::{enumerate_installed_software, SoftwareObservation};

/// Backwards compatible name for firewall rules.
pub type WindowsFirewallRule = FirewallRule;

/// Real hostname of the machine this process is running on.
pub fn local_hostname() -> String {
    host_snapshot::local_hostname()
}

#[derive(Error, Debug)]
pub enum WindowsPlatformError {
    #[error("API call failed: {0}")]
    ApiFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Not supported on this platform: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsProcessInfo {
    pub pid: u32,
    pub name: String,
    pub session_name: String,
    pub mem_usage_kb: u64,
}

/// Splits one CSV record, honouring double quotes (tasklist puts thousands
/// separators inside quoted memory values: `"12,345 K"`).
pub fn split_csv_record(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

/// Parses `tasklist /FO CSV /NH` output.
pub fn parse_tasklist_csv(text: &str) -> Vec<WindowsProcessInfo> {
    text.lines()
        .filter_map(|line| {
            let parts = split_csv_record(line.trim());
            if parts.len() < 5 {
                return None;
            }
            let pid = parts[1].trim().parse::<u32>().ok()?;
            let mem_kb = parts[4]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u64>()
                .unwrap_or(0);
            Some(WindowsProcessInfo {
                pid,
                name: parts[0].clone(),
                session_name: parts[2].clone(),
                mem_usage_kb: mem_kb,
            })
        })
        .collect()
}

pub const FIREWALL_SCRIPT: &str = r#"
$items = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{ DisplayName=[string]$_.DisplayName; Direction=[string]$_.Direction; Action=[string]$_.Action; Enabled=[string]$_.Enabled }
})
ConvertTo-Json -InputObject $items -Compress
"#;

/// Parses `Get-NetFirewallRule` JSON. Accepts both the string form produced
/// by [`FIREWALL_SCRIPT`] and the numeric enum form of a bare
/// `Select-Object | ConvertTo-Json` on Windows PowerShell 5.1.
pub fn parse_firewall_json(json: &str) -> Vec<FirewallRule> {
    host_snapshot::json_items(json)
        .iter()
        .filter_map(|item| {
            let name = ps::get_str(item, "DisplayName")?;
            let direction = match item.get("Direction") {
                Some(serde_json::Value::Number(n)) if n.as_i64() == Some(2) => {
                    "Outbound".to_string()
                }
                Some(serde_json::Value::Number(_)) => "Inbound".to_string(),
                Some(serde_json::Value::String(s)) => s.clone(),
                _ => "Unknown".to_string(),
            };
            let action = match item.get("Action") {
                Some(serde_json::Value::Number(n)) => match n.as_i64() {
                    Some(2) => "Allow",
                    Some(4) => "Block",
                    _ => "NotConfigured",
                }
                .to_string(),
                Some(serde_json::Value::String(s)) => s.clone(),
                _ => "Unknown".to_string(),
            };
            let enabled = match item.get("Enabled") {
                Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1),
                Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
                Some(serde_json::Value::Bool(b)) => *b,
                _ => false,
            };
            Some(FirewallRule {
                name,
                direction,
                action,
                enabled,
                table: None,
                protocol: None,
            })
        })
        .collect()
}

/// Parses `netsh advfirewall firewall show rule name=all dir=in` output in
/// English or Russian locales.
pub fn parse_netsh_firewall(text: &str) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    let mut current: Option<FirewallRule> = None;
    for line in text.lines() {
        let line = line.trim();
        let value_of = |prefixes: &[&str]| {
            prefixes
                .iter()
                .find_map(|p| line.strip_prefix(p))
                .map(|v| v.trim().to_string())
        };
        if let Some(name) = value_of(&["Rule Name:", "Имя правила:"]) {
            if let Some(rule) = current.take() {
                rules.push(rule);
            }
            current = Some(FirewallRule {
                name,
                direction: "Inbound".to_string(),
                action: "Unknown".to_string(),
                enabled: false,
                table: None,
                protocol: None,
            });
        } else if let Some(rule) = current.as_mut() {
            if let Some(act) = value_of(&["Action:", "Действие:"]) {
                rule.action = if act.eq_ignore_ascii_case("block") || act == "Блокировать"
                {
                    "Block".to_string()
                } else if act.eq_ignore_ascii_case("allow") || act == "Разрешить" {
                    "Allow".to_string()
                } else {
                    act
                };
            } else if let Some(en) = value_of(&["Enabled:", "Включено:"]) {
                rule.enabled = en.eq_ignore_ascii_case("yes") || en == "Да";
            } else if let Some(dir) = value_of(&["Direction:", "Направление:"]) {
                rule.direction = if dir.eq_ignore_ascii_case("out") || dir == "Исходящее" {
                    "Outbound".to_string()
                } else {
                    "Inbound".to_string()
                };
            } else if let Some(proto) = value_of(&["Protocol:", "Протокол:"]) {
                rule.protocol = Some(proto);
            }
        }
    }
    if let Some(rule) = current {
        rules.push(rule);
    }
    rules
}

pub struct WindowsPlatformHooks;

impl WindowsPlatformHooks {
    pub fn new() -> Self {
        Self
    }

    pub fn get_current_process_id(&self) -> u32 {
        std::process::id()
    }

    /// Running processes via `tasklist`.
    pub fn enumerate_processes(&self) -> Result<Vec<WindowsProcessInfo>, WindowsPlatformError> {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("tasklist")
                .args(["/FO", "CSV", "/NH"])
                .output()
                .map_err(|e| WindowsPlatformError::ApiFailed(e.to_string()))?;
            let list = parse_tasklist_csv(&String::from_utf8_lossy(&output.stdout));
            if list.is_empty() {
                return Err(WindowsPlatformError::ParseError(
                    "tasklist returned no parseable rows".to_string(),
                ));
            }
            Ok(list)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(WindowsPlatformError::Unsupported(
                "tasklist is only available on Windows".to_string(),
            ))
        }
    }

    /// Active firewall rules (Get-NetFirewallRule, falling back to netsh).
    pub fn query_firewall_rules(&self) -> Result<Vec<FirewallRule>, WindowsPlatformError> {
        #[cfg(target_os = "windows")]
        {
            if let Ok(json) = ps::run(FIREWALL_SCRIPT) {
                let rules = parse_firewall_json(&json);
                if !rules.is_empty() {
                    return Ok(rules);
                }
            }
            let output = std::process::Command::new("netsh")
                .args(["advfirewall", "firewall", "show", "rule", "name=all"])
                .output()
                .map_err(|e| WindowsPlatformError::ApiFailed(e.to_string()))?;
            let rules = parse_netsh_firewall(&String::from_utf8_lossy(&output.stdout));
            if rules.is_empty() {
                return Err(WindowsPlatformError::ParseError(
                    "neither Get-NetFirewallRule nor netsh returned parseable rules".to_string(),
                ));
            }
            Ok(rules)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(WindowsPlatformError::Unsupported(
                "Windows Firewall is only available on Windows".to_string(),
            ))
        }
    }

    /// Complete live host snapshot.
    pub fn collect_snapshot(&self) -> HostSnapshot {
        collect_windows_snapshot()
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
    fn parses_tasklist_csv_with_thousands_separators() {
        let text = "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\r\n\"chrome.exe\",\"7344\",\"Console\",\"1\",\"123,456 K\"\r\n\"weird, name.exe\",\"99\",\"Console\",\"1\",\"1 024 K\"\r\nINFO: garbage\r\n";
        let procs = parse_tasklist_csv(text);
        assert_eq!(procs.len(), 3);
        assert_eq!(procs[1].name, "chrome.exe");
        assert_eq!(procs[1].mem_usage_kb, 123456);
        assert_eq!(procs[2].name, "weird, name.exe");
        assert_eq!(procs[2].mem_usage_kb, 1024);
    }

    #[test]
    fn parses_firewall_json_string_and_numeric_forms() {
        let strings = r#"[{"DisplayName":"Core Networking - DNS (UDP-Out)","Direction":"Outbound","Action":"Allow","Enabled":"True"},{"DisplayName":"Block SMB","Direction":"Inbound","Action":"Block","Enabled":"False"}]"#;
        let rules = parse_firewall_json(strings);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].direction, "Outbound");
        assert!(rules[0].enabled);
        assert_eq!(rules[1].action, "Block");
        assert!(!rules[1].enabled);

        let numeric = r#"{"DisplayName":"Remote Desktop","Direction":1,"Action":2,"Enabled":1}"#;
        let rules = parse_firewall_json(numeric);
        assert_eq!(rules[0].direction, "Inbound");
        assert_eq!(rules[0].action, "Allow");
        assert!(rules[0].enabled);
    }

    #[test]
    fn parses_netsh_in_english_and_russian() {
        let en = "\r\nRule Name:                            Remote Desktop - User Mode (TCP-In)\r\n----------------------------------------------------------------------\r\nEnabled:                              No\r\nDirection:                            In\r\nProtocol:                             TCP\r\nAction:                               Allow\r\n\r\nRule Name:                            Block 4444\r\nEnabled:                              Yes\r\nDirection:                            Out\r\nAction:                               Block\r\n";
        let rules = parse_netsh_firewall(en);
        assert_eq!(rules.len(), 2);
        assert!(!rules[0].enabled);
        assert_eq!(rules[0].protocol.as_deref(), Some("TCP"));
        assert_eq!(rules[1].direction, "Outbound");
        assert_eq!(rules[1].action, "Block");

        let ru = "Имя правила:                          Удаленный рабочий стол\r\nВключено:                             Да\r\nНаправление:                          Входящее\r\nДействие:                             Разрешить\r\n";
        let rules = parse_netsh_firewall(ru);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].enabled);
        assert_eq!(rules[0].action, "Allow");
        assert_eq!(rules[0].direction, "Inbound");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn live_hooks_refuse_off_windows_instead_of_faking() {
        let hooks = WindowsPlatformHooks::new();
        assert!(matches!(
            hooks.enumerate_processes(),
            Err(WindowsPlatformError::Unsupported(_))
        ));
        assert!(matches!(
            hooks.query_firewall_rules(),
            Err(WindowsPlatformError::Unsupported(_))
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_process_enumeration() {
        let hooks = WindowsPlatformHooks::new();
        let procs = hooks.enumerate_processes().unwrap();
        let exe = std::env::current_exe().unwrap();
        let exe_name = exe.file_name().unwrap().to_str().unwrap();
        assert!(procs
            .iter()
            .any(|p| p.pid == std::process::id() && p.name.eq_ignore_ascii_case(exe_name)));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_firewall_query() {
        let hooks = WindowsPlatformHooks::new();
        let rules = hooks.query_firewall_rules().unwrap();
        assert!(!rules.is_empty());
        assert!(rules.iter().all(|r| !r.name.is_empty()));
    }
}
