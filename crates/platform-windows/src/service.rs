#![forbid(unsafe_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub service_name: String,
    pub display_name: String,
    pub state: String,
    pub start_type: String,
    pub binary_path: String,
    pub account: String,
    pub pid: Option<u32>,
    pub executable_hash: Option<String>,
    pub path_quoted: bool,
    pub unquoted_risk: bool,
    pub collected_at: String,
}

fn check_unquoted_path_risk(raw_path: &str) -> (bool, bool) {
    let trimmed = raw_path.trim();
    let is_quoted = trimmed.starts_with('"') || trimmed.starts_with('\'');
    let exe_sub = if let Some(idx) = trimmed.to_lowercase().find(".exe") {
        &trimmed[..idx + 4]
    } else {
        trimmed
    };
    let has_spaces = exe_sub.contains(' ');
    let risk = !is_quoted && has_spaces;
    (is_quoted, risk)
}

/// Enumerates real Windows services with unquoted path vulnerability analysis
pub fn enumerate_services_deep() -> Vec<ServiceObservation> {
    let now = Utc::now().to_rfc3339();
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = "(Get-CimInstance Win32_Service | Select-Object -First 50 -Property Name,DisplayName,State,StartMode,PathName,StartName,ProcessId) | ConvertTo-Json -Compress";
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let json_str = String::from_utf8_lossy(&out.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let items = if let Some(arr) = val.as_array() {
                        arr.clone()
                    } else if val.is_object() {
                        vec![val]
                    } else {
                        Vec::new()
                    };

                    let mut list = Vec::new();
                    for item in items {
                        let name = item
                            .get("Name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let display = item
                            .get("DisplayName")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&name)
                            .to_string();
                        let state = item
                            .get("State")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Stopped")
                            .to_string();
                        let start_mode = item
                            .get("StartMode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Manual")
                            .to_string();
                        let path = item
                            .get("PathName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let account = item
                            .get("StartName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("LocalSystem")
                            .to_string();
                        let pid = item
                            .get("ProcessId")
                            .and_then(|v| v.as_u64())
                            .map(|p| p as u32);

                        let (quoted, unquoted_risk) = check_unquoted_path_risk(&path);

                        list.push(ServiceObservation {
                            service_name: name,
                            display_name: display,
                            state,
                            start_type: start_mode,
                            binary_path: path,
                            account,
                            pid,
                            executable_hash: None,
                            path_quoted: quoted,
                            unquoted_risk,
                            collected_at: now.clone(),
                        });
                    }

                    if !list.is_empty() {
                        return list;
                    }
                }
            }
        }
    }

    // Live collection failed or is unavailable on this platform. Return an
    // honest empty result rather than fabricating a forensic finding.
    tracing::warn!("enumerate_services_deep: live collection unavailable, returning empty result");
    let _ = now;
    Vec::new()
}
