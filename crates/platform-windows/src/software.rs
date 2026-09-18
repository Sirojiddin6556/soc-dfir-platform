#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareObservation {
    pub product: String,
    pub version: String,
    pub publisher: String,
    pub install_location: String,
    pub install_date: String,
    pub architecture: String,
    pub source: String,
    pub confidence: f32,
}

/// Enumerates real installed software from Windows Registry Uninstall hives
pub fn enumerate_installed_software() -> Vec<SoftwareObservation> {
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = r#"
        $res = @();
        $keys = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        );
        foreach ($k in $keys) {
            Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
                $res += [PSCustomObject]@{
                    DisplayName = $_.DisplayName;
                    DisplayVersion = if ($_.DisplayVersion) { $_.DisplayVersion.ToString() } else { '1.0' };
                    Publisher = if ($_.Publisher) { $_.Publisher } else { 'Unknown' };
                    InstallLocation = if ($_.InstallLocation) { $_.InstallLocation } else { '' };
                    InstallDate = if ($_.InstallDate) { $_.InstallDate.ToString() } else { '' };
                };
            }
        }
        $res | Select-Object -First 60 | ConvertTo-Json -Compress
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
                        let name = item
                            .get("DisplayName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if name.trim().is_empty() {
                            continue;
                        }
                        let ver = item
                            .get("DisplayVersion")
                            .and_then(|v| v.as_str())
                            .unwrap_or("1.0")
                            .to_string();
                        let publ = item
                            .get("Publisher")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string();
                        let loc = item
                            .get("InstallLocation")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let date = item
                            .get("InstallDate")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        list.push(SoftwareObservation {
                            product: name,
                            version: ver,
                            publisher: publ,
                            install_location: loc,
                            install_date: date,
                            architecture: "x64".to_string(),
                            source: "RegistryUninstall".to_string(),
                            confidence: 0.95,
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
        "enumerate_installed_software: live collection unavailable, returning empty result"
    );
    Vec::new()
}
