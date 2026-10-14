//! Turns a connected [`CommandRunner`] into a [`RemoteScanReport`]: collect the
//! inventory, then match it with the shared OSV package matcher. The status
//! categories mirror the local package scan exactly, so remote findings are
//! produced by the same logic and carry the same guarantees.

use vulnerability_engine::package_scan::{self, is_supported_ecosystem};
use vulnerability_engine::{app_scan, msrc, VulnDbRepository};

use crate::cis::audit_cis;
use crate::command::{CommandRunner, WinCommandRunner};
use crate::inventory::collect_inventory;
use crate::types::{
    HostKey, RemoteError, RemotePlatform, RemoteScanReport, RemoteScanStatus, RemoteTarget,
    WindowsOsStatus, WindowsRemoteReport,
};
use crate::win_cis::audit_windows_cis;
use crate::win_inventory::collect_windows;

/// Collects the host over `runner` and matches its packages against the
/// advisories imported for its ecosystem.
pub fn scan_remote(
    repo: &VulnDbRepository,
    target: &RemoteTarget,
    host_key: Option<HostKey>,
    runner: &mut dyn CommandRunner,
) -> Result<RemoteScanReport, RemoteError> {
    let inv = collect_inventory(runner)?;

    // The CIS configuration audit is distribution-independent: it reads generic
    // Linux config files and judges each setting only from what it actually
    // read. It runs even when the packages cannot be matched, so the operator
    // still gets a hardening picture of an "unsupported" distribution.
    let cis_report = Some(audit_cis(runner));

    let mut report = RemoteScanReport {
        host: target.host.clone(),
        port: target.port,
        username: target.username.clone(),
        host_key,
        platform: RemotePlatform::Linux,
        status: RemoteScanStatus::UnsupportedPlatform,
        os_name: inv.os_name.clone(),
        ecosystem: inv.ecosystem.clone(),
        kernel: inv.kernel.clone(),
        architecture: inv.architecture.clone(),
        package_report: None,
        cis_report,
        windows: None,
        collection_errors: inv.collection_errors.clone(),
    };

    let Some(ecosystem) = inv
        .ecosystem
        .as_deref()
        .filter(|e| is_supported_ecosystem(e))
    else {
        report.status = RemoteScanStatus::UnsupportedPlatform;
        return Ok(report);
    };

    if inv.packages.is_empty() {
        report.status = RemoteScanStatus::NoPackageInventory;
        return Ok(report);
    }

    let pkg_report = package_scan::scan_installed_packages(repo, ecosystem, &inv.packages)?;
    report.status = if pkg_report.ecosystem_rows == 0 {
        RemoteScanStatus::VulndbEmpty
    } else if pkg_report.findings.is_empty() {
        RemoteScanStatus::NoKnownMatchedVulnerabilities
    } else {
        RemoteScanStatus::VulnerabilitiesFound
    };
    report.package_report = Some(pkg_report);
    Ok(report)
}

/// Collects a **Windows** host over `runner` and matches it with the same MSRC
/// (OS/KB) and NVD (installed-program) logic the local Windows scan uses, plus
/// the Windows CIS configuration audit. The CIS audit runs regardless of
/// whether the CVE data is loaded, so the operator always gets a hardening
/// picture.
pub fn scan_remote_windows(
    repo: &VulnDbRepository,
    target: &RemoteTarget,
    host_key: Option<HostKey>,
    runner: &mut dyn WinCommandRunner,
) -> Result<RemoteScanReport, RemoteError> {
    let inv = collect_windows(runner);
    let cis_report = Some(audit_windows_cis(runner));
    let facts = &inv.facts;

    let mut win = WindowsRemoteReport {
        caption: if facts.caption.is_empty() {
            "Windows".to_string()
        } else {
            facts.caption.clone()
        },
        full_build: facts.full_build(),
        display_version: facts.display_version.clone(),
        product: None,
        installed_updates: facts.installed_kbs.len(),
        os_status: WindowsOsStatus::Unsupported,
        os_cve: None,
        app_cve: None,
    };

    if inv.identified {
        // OS/KB match via MSRC, exactly as the local Windows scan does.
        match msrc::msrc_product_name(facts) {
            Ok(product) => {
                win.product = Some(product.clone());
                let os = msrc::scan_windows_host(repo, facts, &product)?;
                win.os_status = if os.documents.is_empty() {
                    WindowsOsStatus::VulndbEmpty
                } else if !os.product_known {
                    WindowsOsStatus::ProductNotInDatabase
                } else if os.findings.is_empty() {
                    WindowsOsStatus::NoKnownMatchedVulnerabilities
                } else {
                    WindowsOsStatus::VulnerabilitiesFound
                };
                win.os_cve = Some(os);
            }
            // Product not recognised: the OS half cannot be matched, but the
            // CIS audit and the app scan still run.
            Err(_) => win.os_status = WindowsOsStatus::Unsupported,
        }

        // Installed-program CVE match via NVD.
        if !inv.apps.is_empty() {
            win.app_cve = Some(app_scan::scan_installed_apps(repo, &inv.apps)?);
        }
    }

    // The top-level status is an aggregate; the Windows detail lives in `windows`.
    let os_found = matches!(win.os_status, WindowsOsStatus::VulnerabilitiesFound);
    let app_found = win
        .app_cve
        .as_ref()
        .map(|a| !a.findings.is_empty())
        .unwrap_or(false);
    let status = if !inv.identified {
        RemoteScanStatus::UnsupportedPlatform
    } else if os_found || app_found {
        RemoteScanStatus::VulnerabilitiesFound
    } else {
        RemoteScanStatus::NoKnownMatchedVulnerabilities
    };

    Ok(RemoteScanReport {
        host: target.host.clone(),
        port: target.port,
        username: target.username.clone(),
        host_key,
        platform: RemotePlatform::Windows,
        status,
        os_name: win.caption.clone(),
        ecosystem: None,
        kernel: None,
        architecture: Some(facts.architecture.clone()),
        package_report: None,
        cis_report,
        windows: Some(win),
        collection_errors: inv.collection_errors.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{MapRunner, ReadCommand};
    use std::io::{Cursor, Write};
    use vulnerability_engine::feeds::import_osv_archive;

    const UBUNTU_OS_RELEASE: &str = "NAME=\"Ubuntu\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n";

    // libssl3 built from source openssl, at a version below the advisory's fix.
    const DPKG_STATUS: &str = "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.2-0ubuntu1.10\nSource: openssl\nMaintainer: Ubuntu <x@y>\n\nPackage: coreutils\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.32-4.1ubuntu1\nMaintainer: Ubuntu <x@y>\n";

    fn zip_one(name: &str, body: &str) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(body.as_bytes()).unwrap();
        w.finish().unwrap().into_inner()
    }

    fn ubuntu_repo() -> VulnDbRepository {
        let repo = VulnDbRepository::open_in_memory().unwrap();
        let eco = "Ubuntu:22.04:LTS";
        // openssl affected below 3.0.2-0ubuntu1.15, which the installed
        // 3.0.2-0ubuntu1.10 is below → a true finding.
        let advisory = format!(
            r#"{{"id":"UBUNTU-CVE-2024-9999","details":"openssl flaw",
            "severity":[{{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
            "affected":[{{"package":{{"name":"openssl","ecosystem":"{eco}"}},
            "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"3.0.2-0ubuntu1.15"}}]}}],
            "ecosystem_specific":{{"ubuntu_priority":"high"}}}}]}}"#
        );
        import_osv_archive(
            &repo,
            Cursor::new(zip_one("openssl.json", &advisory)),
            eco,
            "t",
            |_, _| {},
        )
        .unwrap();
        repo
    }

    fn runner() -> MapRunner {
        MapRunner::new()
            .with(ReadCommand::OsRelease, UBUNTU_OS_RELEASE)
            .with(ReadCommand::KernelRelease, "5.15.0-105-generic\n")
            .with(ReadCommand::Architecture, "x86_64\n")
            .with(ReadCommand::DpkgStatus, DPKG_STATUS)
    }

    fn target() -> RemoteTarget {
        RemoteTarget::new("server.example", 22, "ops")
    }

    #[test]
    fn reports_only_the_truly_affected_package() {
        let repo = ubuntu_repo();
        let mut r = runner();
        let report = scan_remote(&repo, &target(), None, &mut r).unwrap();

        assert_eq!(report.status, RemoteScanStatus::VulnerabilitiesFound);
        let pkg = report.package_report.unwrap();
        assert_eq!(pkg.findings.len(), 1);
        let f = &pkg.findings[0];
        assert_eq!(f.component, "openssl");
        assert_eq!(f.id, "CVE-2024-9999");
        assert_eq!(f.fixed_version.as_deref(), Some("3.0.2-0ubuntu1.15"));
        // coreutils has no advisory and must not be reported.
        assert!(pkg.findings.iter().all(|f| f.component != "coreutils"));
    }

    #[test]
    fn empty_database_proves_nothing() {
        let repo = VulnDbRepository::open_in_memory().unwrap();
        let mut r = runner();
        let report = scan_remote(&repo, &target(), None, &mut r).unwrap();
        assert_eq!(report.status, RemoteScanStatus::VulndbEmpty);
    }

    #[test]
    fn patched_host_reports_no_findings() {
        let repo = ubuntu_repo();
        // Same host but openssl already at the fixed version.
        let patched = DPKG_STATUS.replace("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.15");
        let mut r = runner();
        r.insert(
            ReadCommand::DpkgStatus,
            crate::command::CommandOutput::ok(patched),
        );
        let report = scan_remote(&repo, &target(), None, &mut r).unwrap();
        assert_eq!(
            report.status,
            RemoteScanStatus::NoKnownMatchedVulnerabilities
        );
    }

    #[test]
    fn unsupported_distribution_is_flagged_not_scanned() {
        let repo = ubuntu_repo();
        let mut r = MapRunner::new().with(
            ReadCommand::OsRelease,
            "ID=plan9\nNAME=\"Plan 9\"\nVERSION_ID=\"4\"\n",
        );
        let report = scan_remote(&repo, &target(), None, &mut r).unwrap();
        assert_eq!(report.status, RemoteScanStatus::UnsupportedPlatform);
        assert!(report.package_report.is_none());
    }

    const WIN_OS_INFO: &str = "ProductName=Windows Server 2022 Datacenter\n\
        CurrentVersion=10.0.20348\nCurrentBuild=20348\nUBR=2340\n\
        DisplayVersion=21H2\nInstallationType=Server\n\
        Caption=Microsoft Windows Server 2022 Datacenter\nProductType=3\nArchitecture=64-bit\n";

    #[test]
    fn windows_host_runs_cis_even_with_empty_db() {
        let repo = VulnDbRepository::open_in_memory().unwrap();
        let mut r = crate::command::MapRunner::new()
            .with_win(crate::command::WinReadCommand::OsInfo, WIN_OS_INFO)
            .with_win(
                crate::command::WinReadCommand::Smb1,
                "EnableSMB1Protocol=True\n",
            )
            .with_win(crate::command::WinReadCommand::Uac, "EnableLUA=1\n");
        let report = scan_remote_windows(&repo, &target(), None, &mut r).unwrap();
        assert_eq!(report.platform, RemotePlatform::Windows);
        let win = report.windows.as_ref().unwrap();
        // The product was recognised and the (empty) DB yields VULNDB_EMPTY.
        assert!(win.product.is_some());
        assert_eq!(win.os_status, WindowsOsStatus::VulndbEmpty);
        assert_eq!(win.full_build, "10.0.20348.2340");
        // CIS ran regardless of the empty CVE DB and caught the SMBv1 fail.
        let cis = report.cis_report.as_ref().unwrap();
        assert!(cis
            .checks
            .iter()
            .any(|c| c.id == "WIN-SMB1" && matches!(c.status, crate::cis::CheckStatus::Fail)));
    }

    #[test]
    fn unreadable_windows_host_is_unsupported_not_invented() {
        let repo = VulnDbRepository::open_in_memory().unwrap();
        // No OsInfo output at all → cannot identify the host.
        let mut r = crate::command::MapRunner::new();
        let report = scan_remote_windows(&repo, &target(), None, &mut r).unwrap();
        assert_eq!(report.status, RemoteScanStatus::UnsupportedPlatform);
        let win = report.windows.as_ref().unwrap();
        assert_eq!(win.os_status, WindowsOsStatus::Unsupported);
        assert!(win.os_cve.is_none());
    }
}
