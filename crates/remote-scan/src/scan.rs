//! Turns a connected [`CommandRunner`] into a [`RemoteScanReport`]: collect the
//! inventory, then match it with the shared OSV package matcher. The status
//! categories mirror the local package scan exactly, so remote findings are
//! produced by the same logic and carry the same guarantees.

use vulnerability_engine::package_scan::{self, is_supported_ecosystem};
use vulnerability_engine::VulnDbRepository;

use crate::command::CommandRunner;
use crate::inventory::collect_inventory;
use crate::types::{HostKey, RemoteError, RemoteScanReport, RemoteScanStatus, RemoteTarget};

/// Collects the host over `runner` and matches its packages against the
/// advisories imported for its ecosystem.
pub fn scan_remote(
    repo: &VulnDbRepository,
    target: &RemoteTarget,
    host_key: Option<HostKey>,
    runner: &mut dyn CommandRunner,
) -> Result<RemoteScanReport, RemoteError> {
    let inv = collect_inventory(runner)?;

    let mut report = RemoteScanReport {
        host: target.host.clone(),
        port: target.port,
        username: target.username.clone(),
        host_key,
        status: RemoteScanStatus::UnsupportedPlatform,
        os_name: inv.os_name.clone(),
        ecosystem: inv.ecosystem.clone(),
        kernel: inv.kernel.clone(),
        architecture: inv.architecture.clone(),
        package_report: None,
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
}
