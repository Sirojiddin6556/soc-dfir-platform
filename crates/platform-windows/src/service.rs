#![forbid(unsafe_code)]

use crate::ps::{get_str, get_u64};
use host_snapshot::json_items;
pub use host_snapshot::ServiceObservation;

pub const SERVICE_SCRIPT: &str = r#"
$items = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ProcessId)
ConvertTo-Json -InputObject $items -Compress
"#;

/// (path is quoted, unquoted-path hijack risk) for a service ImagePath.
pub fn check_unquoted_path_risk(raw_path: &str) -> (bool, bool) {
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

pub fn parse_services_json(json: &str, collected_at: &str) -> Vec<ServiceObservation> {
    json_items(json)
        .iter()
        .filter_map(|item| {
            let name = get_str(item, "Name")?;
            let path = get_str(item, "PathName").unwrap_or_default();
            let (path_quoted, unquoted_risk) = check_unquoted_path_risk(&path);
            Some(ServiceObservation {
                display_name: get_str(item, "DisplayName").unwrap_or_else(|| name.clone()),
                service_name: name,
                state: get_str(item, "State").unwrap_or_else(|| "Unknown".to_string()),
                start_type: get_str(item, "StartMode").unwrap_or_else(|| "Unknown".to_string()),
                binary_path: path,
                account: get_str(item, "StartName").unwrap_or_default(),
                // Win32_Service reports ProcessId 0 for stopped services.
                pid: get_u64(item, "ProcessId")
                    .filter(|p| *p != 0)
                    .map(|p| p as u32),
                executable_hash: None,
                path_quoted,
                unquoted_risk,
                collected_at: collected_at.to_string(),
                source: "scm".to_string(),
                unit_file: None,
            })
        })
        .collect()
}

/// Enumerates Windows services with unquoted path analysis.
#[cfg(target_os = "windows")]
pub fn enumerate_services_deep() -> Result<Vec<ServiceObservation>, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let json = crate::ps::run(SERVICE_SCRIPT)?;
    Ok(parse_services_json(&json, &now))
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_services_deep() -> Result<Vec<ServiceObservation>, String> {
    Err(crate::ps::unsupported("Win32_Service"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[{"Name":"AdobeARMservice","DisplayName":"Adobe Acrobat Update Service","State":"Running","StartMode":"Auto","PathName":"\"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\armsvc.exe\"","StartName":"LocalSystem","ProcessId":4012},{"Name":"VulnSvc","DisplayName":"Vendor Agent","State":"Stopped","StartMode":"Manual","PathName":"C:\\Program Files\\Vendor App\\agent.exe -service","StartName":"LocalSystem","ProcessId":0},{"Name":"Dhcp","DisplayName":"DHCP Client","State":"Running","StartMode":"Auto","PathName":"C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p","StartName":"NT Authority\\LocalService","ProcessId":1544}]"#;

    #[test]
    fn parses_services_and_flags_unquoted_paths() {
        let svcs = parse_services_json(SAMPLE, "t");
        assert_eq!(svcs.len(), 3);
        assert!(svcs[0].path_quoted && !svcs[0].unquoted_risk);
        assert_eq!(svcs[0].pid, Some(4012));
        assert!(svcs[1].unquoted_risk);
        assert_eq!(svcs[1].pid, None, "stopped service has no pid");
        assert_eq!(svcs[1].state, "Stopped");
        assert!(!svcs[2].unquoted_risk, "no spaces before .exe");
        assert_eq!(svcs[2].account, "NT Authority\\LocalService");
        assert!(svcs.iter().all(|s| s.source == "scm"));
    }
}
