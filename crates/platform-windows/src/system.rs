#![forbid(unsafe_code)]

//! OS identity (Win32_OperatingSystem + CurrentVersion), hotfixes, local IP
//! addresses and local accounts (Get-LocalUser / Win32_UserAccount).

use crate::ps::{get_str, get_u64, value_items};
use host_snapshot::UserAccount;

pub const OS_SCRIPT: &str = r#"
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$kbs = @(Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID)
$ips = @(Get-NetIPAddress -AddressState Preferred -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -ne '::1' } | ForEach-Object { [string]$_.IPAddress })
[PSCustomObject]@{
  Caption = [string]$os.Caption
  Version = [string]$os.Version
  Build = if ($os.BuildNumber) { [int]$os.BuildNumber } else { $null }
  OSArchitecture = [string]$os.OSArchitecture
  Arch = if ($env:PROCESSOR_ARCHITEW6432) { [string]$env:PROCESSOR_ARCHITEW6432 } else { [string]$env:PROCESSOR_ARCHITECTURE }
  UBR = if ($cv -and $cv.UBR -ne $null) { [int]$cv.UBR } else { $null }
  DisplayVersion = if ($cv) { [string]$cv.DisplayVersion } else { '' }
  KBs = $kbs
  IPs = $ips
} | ConvertTo-Json -Compress -Depth 3
"#;

pub const USERS_SCRIPT: &str = r#"
$admins = @()
try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch {}
$users = @()
try {
  $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{ Name=[string]$_.Name; SID=[string]$_.SID.Value; Enabled=[bool]$_.Enabled; FullName=[string]$_.FullName; LastLogon=if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('o') } else { $null }; Source='Get-LocalUser' }
  })
} catch {
  $users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{ Name=[string]$_.Name; SID=[string]$_.SID; Enabled=(-not $_.Disabled); FullName=[string]$_.FullName; LastLogon=$null; Source='Win32_UserAccount' }
  })
}
[PSCustomObject]@{ Computer=[string]$env:COMPUTERNAME; Users=$users; Admins=$admins } | ConvertTo-Json -Compress -Depth 4
"#;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsOsInfo {
    pub caption: String,
    pub version: String,
    pub build: Option<u32>,
    pub ubr: Option<u32>,
    pub display_version: String,
    pub os_architecture: String,
    pub architecture: String,
    pub kbs: Vec<String>,
    pub ip_addresses: Vec<String>,
}

impl WindowsOsInfo {
    /// e.g. "Microsoft Windows 11 Pro 23H2 (64-bit)".
    pub fn display_name(&self) -> String {
        let mut s = self.caption.trim().to_string();
        if !self.display_version.is_empty() {
            s = format!("{} {}", s, self.display_version);
        }
        if !self.os_architecture.is_empty() {
            s = format!("{} ({})", s, self.os_architecture);
        }
        s
    }

    /// NT kernel version including the update build revision,
    /// e.g. "10.0.22631.4037".
    pub fn kernel(&self) -> String {
        match self.ubr {
            Some(ubr) if !self.version.is_empty() => format!("{}.{}", self.version, ubr),
            _ => self.version.clone(),
        }
    }
}

fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
        _ => Vec::new(),
    }
}

pub fn map_processor_arch(arch: &str) -> String {
    match arch.to_ascii_uppercase().as_str() {
        "AMD64" | "X64" => "x86_64".to_string(),
        "ARM64" => "aarch64".to_string(),
        "X86" => "x86".to_string(),
        "" => String::new(),
        other => other.to_ascii_lowercase(),
    }
}

pub fn parse_os_json(json: &str) -> Option<WindowsOsInfo> {
    let v: serde_json::Value =
        serde_json::from_str(json.trim().trim_start_matches('\u{feff}')).ok()?;
    if !v.is_object() {
        return None;
    }
    Some(WindowsOsInfo {
        caption: get_str(&v, "Caption").unwrap_or_default(),
        version: get_str(&v, "Version").unwrap_or_default(),
        build: get_u64(&v, "Build").map(|b| b as u32),
        ubr: get_u64(&v, "UBR").map(|b| b as u32),
        display_version: get_str(&v, "DisplayVersion").unwrap_or_default(),
        os_architecture: get_str(&v, "OSArchitecture").unwrap_or_default(),
        architecture: map_processor_arch(&get_str(&v, "Arch").unwrap_or_default()),
        kbs: strings(v.get("KBs")),
        ip_addresses: strings(v.get("IPs")),
    })
}

/// Parses [`USERS_SCRIPT`] output into (`COMPUTER\name` list, accounts).
pub fn parse_users_json(json: &str) -> (Vec<String>, Vec<UserAccount>) {
    let Ok(v) =
        serde_json::from_str::<serde_json::Value>(json.trim().trim_start_matches('\u{feff}'))
    else {
        return (Vec::new(), Vec::new());
    };
    let computer = get_str(&v, "Computer").unwrap_or_default();
    let admins: Vec<String> = strings(v.get("Admins"))
        .into_iter()
        .map(|a| a.to_ascii_lowercase())
        .collect();
    let mut names = Vec::new();
    let mut accounts = Vec::new();
    for item in value_items(v.get("Users")) {
        let Some(name) = get_str(&item, "Name") else {
            continue;
        };
        let qualified = if computer.is_empty() {
            name.clone()
        } else {
            format!("{}\\{}", computer, name)
        };
        let enabled = item.get("Enabled").and_then(|e| e.as_bool());
        let admin = admins
            .iter()
            .any(|a| *a == qualified.to_ascii_lowercase() || *a == name.to_ascii_lowercase());
        names.push(qualified);
        accounts.push(UserAccount {
            name,
            uid: None,
            gid: None,
            sid: get_str(&item, "SID"),
            full_name: get_str(&item, "FullName"),
            home: None,
            shell: None,
            enabled,
            interactive: enabled.unwrap_or(false),
            admin,
            last_logon: get_str(&item, "LastLogon").and_then(|d| crate::ps::ps_datetime(&d)),
            source: get_str(&item, "Source").unwrap_or_default(),
        });
    }
    (names, accounts)
}

#[cfg(target_os = "windows")]
pub fn collect_os_info() -> Result<WindowsOsInfo, String> {
    let json = crate::ps::run(OS_SCRIPT)?;
    parse_os_json(&json)
        .ok_or_else(|| "Win32_OperatingSystem: не удалось разобрать ответ".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn collect_os_info() -> Result<WindowsOsInfo, String> {
    Err(crate::ps::unsupported("Win32_OperatingSystem"))
}

#[cfg(target_os = "windows")]
pub fn collect_users() -> Result<(Vec<String>, Vec<UserAccount>), String> {
    let json = crate::ps::run(USERS_SCRIPT)?;
    let parsed = parse_users_json(&json);
    if parsed.1.is_empty() {
        return Err("Get-LocalUser/Win32_UserAccount не вернули учётных записей".to_string());
    }
    Ok(parsed)
}

#[cfg(not(target_os = "windows"))]
pub fn collect_users() -> Result<(Vec<String>, Vec<UserAccount>), String> {
    Err(crate::ps::unsupported("Get-LocalUser"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OS_SAMPLE: &str = r#"{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22631","Build":22631,"OSArchitecture":"64-bit","Arch":"AMD64","UBR":4037,"DisplayVersion":"23H2","KBs":["KB5042099","KB5043080"],"IPs":["192.168.1.105","fe80::3c1a:9d2b:7e44:12af%12"]}"#;

    #[test]
    fn parses_os_info() {
        let os = parse_os_json(OS_SAMPLE).unwrap();
        assert_eq!(os.display_name(), "Microsoft Windows 11 Pro 23H2 (64-bit)");
        assert_eq!(os.build, Some(22631));
        assert_eq!(os.ubr, Some(4037));
        assert_eq!(os.kernel(), "10.0.22631.4037");
        assert_eq!(os.architecture, "x86_64");
        assert_eq!(os.kbs, vec!["KB5042099", "KB5043080"]);
        assert_eq!(os.ip_addresses[0], "192.168.1.105");
    }

    #[test]
    fn parses_os_info_with_single_kb_and_missing_ubr() {
        let os = parse_os_json(
            r#"{"Caption":"Microsoft Windows Server 2022 Standard","Version":"10.0.20348","Build":20348,"OSArchitecture":"64-bit","Arch":"AMD64","UBR":null,"DisplayVersion":"","KBs":"KB5012170","IPs":[]}"#,
        )
        .unwrap();
        assert_eq!(os.kbs, vec!["KB5012170"]);
        assert_eq!(os.ubr, None);
        assert_eq!(os.kernel(), "10.0.20348");
        assert_eq!(
            os.display_name(),
            "Microsoft Windows Server 2022 Standard (64-bit)"
        );
        assert!(parse_os_json("[]").is_none());
    }

    const USERS_SAMPLE: &str = r#"{"Computer":"DESKTOP-7Q2","Users":[{"Name":"Administrator","SID":"S-1-5-21-1004336348-1177238915-682003330-500","Enabled":false,"FullName":"","LastLogon":null,"Source":"Get-LocalUser"},{"Name":"Guest","SID":"S-1-5-21-1004336348-1177238915-682003330-501","Enabled":false,"FullName":"","LastLogon":null,"Source":"Get-LocalUser"},{"Name":"Сирож","SID":"S-1-5-21-1004336348-1177238915-682003330-1001","Enabled":true,"FullName":"Сирожиддин","LastLogon":"2026-10-07T05:58:11.0000000Z","Source":"Get-LocalUser"}],"Admins":["DESKTOP-7Q2\\Administrator","DESKTOP-7Q2\\Сирож"]}"#;

    #[test]
    fn parses_local_users() {
        let (names, accounts) = parse_users_json(USERS_SAMPLE);
        assert_eq!(
            names,
            vec![
                "DESKTOP-7Q2\\Administrator",
                "DESKTOP-7Q2\\Guest",
                "DESKTOP-7Q2\\Сирож"
            ]
        );
        let siroj = &accounts[2];
        assert!(siroj.admin && siroj.interactive);
        assert_eq!(siroj.enabled, Some(true));
        assert_eq!(
            siroj.sid.as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        assert_eq!(
            siroj.last_logon.as_deref(),
            Some("2026-10-07T05:58:11+00:00")
        );
        assert!(accounts[0].admin && !accounts[0].interactive);
        assert!(!accounts[1].admin);
    }

    #[test]
    fn parses_single_user_object_from_cim_fallback() {
        let (names, accounts) = parse_users_json(
            r#"{"Computer":"SRV01","Users":{"Name":"svc_backup","SID":"S-1-5-21-1-2-3-1005","Enabled":true,"FullName":"","LastLogon":null,"Source":"Win32_UserAccount"},"Admins":[]}"#,
        );
        assert_eq!(names, vec!["SRV01\\svc_backup"]);
        assert_eq!(accounts[0].source, "Win32_UserAccount");
        assert!(!accounts[0].admin);
        assert_eq!(parse_users_json("not json").0.len(), 0);
    }
}
