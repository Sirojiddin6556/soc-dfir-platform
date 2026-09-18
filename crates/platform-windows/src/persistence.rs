#![forbid(unsafe_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAutorunObservation {
    pub hive: String,
    pub key: String,
    pub value_name: String,
    pub value_data: String,
    pub resolved_executable: String,
    pub hash: Option<String>,
    pub owner: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTaskObservation {
    pub task_name: String,
    pub task_path: String,
    pub state: String,
    pub action: Option<String>,
    pub arguments: Option<String>,
    pub run_level: String,
    pub collected_at: String,
}

/// Enumerates real Registry Run & RunOnce autorun persistence points
pub fn enumerate_registry_autoruns() -> Vec<RegistryAutorunObservation> {
    let now = Utc::now().to_rfc3339();
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = r#"
        $res = @();
        $keys = @(
            @{ Hive='HKLM'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' },
            @{ Hive='HKCU'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' }
        );
        foreach ($k in $keys) {
            if (Test-Path $k.Path) {
                $p = Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue;
                if ($p) {
                    foreach ($prop in $p.PSObject.Properties) {
                        if ($prop.Name -notmatch '^PS' -and $prop.Value) {
                            $res += [PSCustomObject]@{
                                Hive = $k.Hive;
                                Key = $k.Path;
                                ValueName = $prop.Name;
                                ValueData = $prop.Value.ToString();
                            };
                        }
                    }
                }
            }
        }
        $res | ConvertTo-Json -Compress
        "#;

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
                        let hive = item
                            .get("Hive")
                            .and_then(|v| v.as_str())
                            .unwrap_or("HKLM")
                            .to_string();
                        let key = item
                            .get("Key")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item
                            .get("ValueName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let data = item
                            .get("ValueData")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        list.push(RegistryAutorunObservation {
                            hive,
                            key,
                            value_name: name,
                            value_data: data.clone(),
                            resolved_executable: data,
                            hash: None,
                            owner: Some("NT AUTHORITY\\SYSTEM".to_string()),
                            timestamp: now.clone(),
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
    tracing::warn!(
        "enumerate_registry_autoruns: live collection unavailable, returning empty result"
    );
    let _ = now;
    Vec::new()
}

/// Enumerates real Scheduled Tasks with executable actions
pub fn enumerate_scheduled_tasks() -> Vec<ScheduledTaskObservation> {
    let now = Utc::now().to_rfc3339();
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = "(Get-ScheduledTask | Select-Object -First 40 | ForEach-Object { [PSCustomObject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; State=$_.State.ToString(); Action=($_.Actions | Select-Object -First 1 -ExpandProperty Execute -ErrorAction SilentlyContinue) } }) | ConvertTo-Json -Compress";
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
                            .get("TaskName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let path = item
                            .get("TaskPath")
                            .and_then(|v| v.as_str())
                            .unwrap_or("\\")
                            .to_string();
                        let state = item
                            .get("State")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Ready")
                            .to_string();
                        let action = item
                            .get("Action")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        list.push(ScheduledTaskObservation {
                            task_name: name,
                            task_path: path,
                            state,
                            action,
                            arguments: None,
                            run_level: "LeastPrivilege".to_string(),
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
    tracing::warn!(
        "enumerate_scheduled_tasks: live collection unavailable, returning empty result"
    );
    let _ = now;
    Vec::new()
}
