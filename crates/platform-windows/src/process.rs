#![forbid(unsafe_code)]

use crate::ps::{get_str, get_u64, ps_datetime};
pub use host_snapshot::ProcessObservation;
use host_snapshot::{json_items, COLLECTOR_VERSION};

/// Win32_Process plus process owners. `Get-Process -IncludeUserName` needs
/// elevation; without it owners stay null rather than being guessed.
pub const PROCESS_SCRIPT: &str = r#"
$owners = @{}
try {
  Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { if ($_.UserName) { $owners[[int]$_.Id] = [string]$_.UserName } }
} catch {}
$items = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{
    ProcessId = [int]$_.ProcessId
    ParentProcessId = [int]$_.ParentProcessId
    Name = [string]$_.Name
    ExecutablePath = $_.ExecutablePath
    CommandLine = $_.CommandLine
    SessionId = [int]$_.SessionId
    CreationDate = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
    UserName = $owners[[int]$_.ProcessId]
  }
})
ConvertTo-Json -InputObject $items -Compress
"#;

/// Parses [`PROCESS_SCRIPT`] output. Hashes are filled in separately.
pub fn parse_processes_json(json: &str, host: &str, collected_at: &str) -> Vec<ProcessObservation> {
    json_items(json)
        .iter()
        .filter_map(|item| {
            let pid = get_u64(item, "ProcessId")? as u32;
            Some(ProcessObservation {
                host_id: host.to_string(),
                pid,
                ppid: get_u64(item, "ParentProcessId").unwrap_or(0) as u32,
                name: get_str(item, "Name").unwrap_or_default(),
                executable_path: get_str(item, "ExecutablePath"),
                command_line: get_str(item, "CommandLine"),
                username: get_str(item, "UserName"),
                session_id: get_u64(item, "SessionId").unwrap_or(0) as u32,
                started_at: get_str(item, "CreationDate").and_then(|d| ps_datetime(&d)),
                sha256: None,
                signer: None,
                architecture: "unknown".to_string(),
                integrity_level: "unknown".to_string(),
                collected_at: collected_at.to_string(),
                collector_version: COLLECTOR_VERSION.to_string(),
                source: "WindowsCimProcessCollector".to_string(),
                uid: None,
                exe_deleted: false,
            })
        })
        .collect()
}

/// Queries running processes (Win32_Process) with real owners, start times
/// and SHA-256 of their images.
#[cfg(target_os = "windows")]
pub fn enumerate_processes_deep(host: &str) -> Result<Vec<ProcessObservation>, String> {
    use host_snapshot::{FileHashCache, MAX_HASH_BYTES};
    static HASHES: FileHashCache = FileHashCache::new();

    let now = chrono::Utc::now().to_rfc3339();
    let json = crate::ps::run(PROCESS_SCRIPT)?;
    let mut list = parse_processes_json(&json, host, &now);
    if list.is_empty() {
        return Err("Win32_Process вернул пустой результат".to_string());
    }
    for p in &mut list {
        let Some(path) = p.executable_path.as_deref() else {
            continue;
        };
        let path = std::path::Path::new(path);
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = format!("{}|{}|{}", path.display(), meta.len(), mtime);
        p.sha256 = HASHES.get_or_compute(&key, path, MAX_HASH_BYTES);
    }
    Ok(list)
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_processes_deep(_host: &str) -> Result<Vec<ProcessObservation>, String> {
    Err(crate::ps::unsupported("Win32_Process"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shape of `ConvertTo-Json -Compress` output from Windows PowerShell 5.1
    // for PROCESS_SCRIPT (non-elevated: UserName is null for other users).
    const SAMPLE: &str = r#"[{"ProcessId":0,"ParentProcessId":0,"Name":"System Idle Process","ExecutablePath":null,"CommandLine":null,"SessionId":0,"CreationDate":null,"UserName":null},{"ProcessId":4,"ParentProcessId":0,"Name":"System","ExecutablePath":null,"CommandLine":null,"SessionId":0,"CreationDate":"2026-10-07T06:12:01.5000000Z","UserName":null},{"ProcessId":1188,"ParentProcessId":812,"Name":"svchost.exe","ExecutablePath":"C:\\Windows\\system32\\svchost.exe","CommandLine":"C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p","SessionId":0,"CreationDate":"2026-10-07T06:12:09.1250000Z","UserName":"NT AUTHORITY\\SYSTEM"},{"ProcessId":7344,"ParentProcessId":6120,"Name":"WINWORD.EXE","ExecutablePath":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","CommandLine":"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\Сирож\\Downloads\\invoice.docm\"","SessionId":1,"CreationDate":"/Date(1791356400000)/","UserName":"DESKTOP-7Q2\\Сирож"}]"#;

    #[test]
    fn parses_win32_process_json() {
        let procs = parse_processes_json(SAMPLE, "DESKTOP-7Q2", "2026-10-07T08:00:00Z");
        assert_eq!(procs.len(), 4);
        assert_eq!(procs[0].name, "System Idle Process");
        assert_eq!(procs[0].executable_path, None);

        let svc = &procs[2];
        assert_eq!(svc.pid, 1188);
        assert_eq!(svc.ppid, 812);
        assert_eq!(
            svc.executable_path.as_deref(),
            Some("C:\\Windows\\system32\\svchost.exe")
        );
        assert_eq!(svc.username.as_deref(), Some("NT AUTHORITY\\SYSTEM"));
        assert_eq!(
            svc.started_at.as_deref(),
            Some("2026-10-07T06:12:09.125+00:00")
        );
        assert_eq!(
            svc.signer, None,
            "signatures are not verified, so none is claimed"
        );

        let word = &procs[3];
        assert_eq!(word.username.as_deref(), Some("DESKTOP-7Q2\\Сирож"));
        assert_eq!(word.session_id, 1);
        assert!(word
            .command_line
            .as_deref()
            .unwrap()
            .contains("invoice.docm"));
        assert_eq!(
            word.started_at.as_deref(),
            Some("2026-10-07T07:00:00+00:00")
        );
    }

    #[test]
    fn single_process_object_and_garbage() {
        let one = r#"{"ProcessId":10,"ParentProcessId":4,"Name":"smss.exe"}"#;
        assert_eq!(parse_processes_json(one, "h", "t").len(), 1);
        assert!(parse_processes_json("", "h", "t").is_empty());
        assert!(parse_processes_json("Access denied", "h", "t").is_empty());
    }
}
