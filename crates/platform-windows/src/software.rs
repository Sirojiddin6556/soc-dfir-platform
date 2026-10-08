#![forbid(unsafe_code)]

use crate::ps::get_str;
use host_snapshot::json_items;
pub use host_snapshot::SoftwareObservation;

/// Installed programs from the Uninstall registry hives. Missing values are
/// left empty -- never defaulted to made-up versions or publishers.
pub const SOFTWARE_SCRIPT: &str = r#"
$keys = @(
  @{ Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch='x64' },
  @{ Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch='x86' },
  @{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch='' }
)
$res = foreach ($k in $keys) {
  Get-ItemProperty $k.Path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
    [PSCustomObject]@{
      DisplayName = [string]$_.DisplayName
      DisplayVersion = [string]$_.DisplayVersion
      Publisher = [string]$_.Publisher
      InstallLocation = [string]$_.InstallLocation
      InstallDate = [string]$_.InstallDate
      Architecture = $k.Arch
    }
  }
}
ConvertTo-Json -InputObject @($res) -Compress
"#;

pub fn parse_software_json(json: &str) -> Vec<SoftwareObservation> {
    let mut seen = std::collections::BTreeSet::new();
    json_items(json)
        .iter()
        .filter_map(|item| {
            let product = get_str(item, "DisplayName")?.trim().to_string();
            let version = get_str(item, "DisplayVersion").unwrap_or_default();
            let architecture = get_str(item, "Architecture").unwrap_or_default();
            // The same product is often registered in more than one hive.
            if !seen.insert((product.clone(), version.clone(), architecture.clone())) {
                return None;
            }
            Some(SoftwareObservation {
                product,
                version,
                publisher: get_str(item, "Publisher").unwrap_or_default(),
                install_location: get_str(item, "InstallLocation").unwrap_or_default(),
                install_date: get_str(item, "InstallDate").unwrap_or_default(),
                architecture,
                source: "RegistryUninstall".to_string(),
                confidence: 0.95,
                purl: None,
                ecosystem: None,
                source_package: None,
                source_version: None,
            })
        })
        .collect()
}

/// Installed software from the Windows Uninstall registry hives.
#[cfg(target_os = "windows")]
pub fn enumerate_installed_software() -> Result<Vec<SoftwareObservation>, String> {
    let json = crate::ps::run(SOFTWARE_SCRIPT)?;
    Ok(parse_software_json(&json))
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_installed_software() -> Result<Vec<SoftwareObservation>, String> {
    Err(crate::ps::unsupported("Uninstall registry"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[{"DisplayName":"7-Zip 23.01 (x64)","DisplayVersion":"23.01","Publisher":"Igor Pavlov","InstallLocation":"C:\\Program Files\\7-Zip\\","InstallDate":"","Architecture":"x64"},{"DisplayName":"Google Chrome","DisplayVersion":"129.0.6668.90","Publisher":"Google LLC","InstallLocation":"C:\\Program Files\\Google\\Chrome\\Application","InstallDate":"20241002","Architecture":"x64"},{"DisplayName":"Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33135","DisplayVersion":"14.38.33135.0","Publisher":"Microsoft Corporation","InstallLocation":"","InstallDate":"20240115","Architecture":"x86"},{"DisplayName":"Google Chrome","DisplayVersion":"129.0.6668.90","Publisher":"Google LLC","InstallLocation":"","InstallDate":"20241002","Architecture":"x64"},{"DisplayName":"Portable Tool","DisplayVersion":"","Publisher":"","InstallLocation":"","InstallDate":"","Architecture":""}]"#;

    #[test]
    fn parses_uninstall_entries_without_inventing_values() {
        let sw = parse_software_json(SAMPLE);
        assert_eq!(sw.len(), 4, "duplicate Chrome registration collapsed");
        assert_eq!(sw[0].product, "7-Zip 23.01 (x64)");
        assert_eq!(sw[1].install_date, "20241002");
        assert_eq!(sw[2].architecture, "x86");
        let portable = &sw[3];
        assert_eq!(portable.version, "", "no fabricated 1.0 default");
        assert_eq!(portable.publisher, "", "no fabricated Unknown publisher");
    }
}
