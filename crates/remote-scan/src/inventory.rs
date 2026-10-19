//! Collects the host's OS identity, kernel and installed-package inventory by
//! running the read-only commands and parsing their output with the *same*
//! parsers the local Linux scan uses. Nothing here is remote-specific beyond
//! the source of the text: a byte of dpkg status read over SSH is parsed
//! exactly as one read from local disk, so the resulting packages feed the CVE
//! matcher identically.

use platform_linux::os::parse_os_release;
use platform_linux::software::{
    apk_to_observation, dpkg_to_observation, parse_apk_installed, parse_dpkg_status, parse_rpm_qa,
    rpm_to_observation,
};

use crate::command::{observation_to_package, CommandRunner, ReadCommand};
use crate::types::{RemoteError, RemoteInventory};

/// Which package manager an ecosystem's packages come from — decides which
/// read command and parser to use. Mirrors the family split in
/// `vulnerability_engine::package_scan`.
enum PkgSource {
    Dpkg,
    Rpm,
    Apk,
}

fn package_source(ecosystem: &str) -> Option<PkgSource> {
    match ecosystem.split(':').next().unwrap_or("") {
        "Debian" | "Ubuntu" => Some(PkgSource::Dpkg),
        "AlmaLinux" | "Rocky Linux" | "openSUSE" => Some(PkgSource::Rpm),
        "Alpine" | "Wolfi" | "Chainguard" => Some(PkgSource::Apk),
        _ => None,
    }
}

fn non_empty(output: &str) -> bool {
    output.lines().any(|l| !l.trim().is_empty())
}

/// Runs the collection commands and returns the parsed inventory. Transport
/// errors on the OS-identity command are fatal (we cannot classify the host);
/// a failure to read packages is recorded but not fatal, so the operator still
/// learns what the host is.
pub fn collect_inventory(runner: &mut dyn CommandRunner) -> Result<RemoteInventory, RemoteError> {
    let os_text = runner.run(ReadCommand::OsRelease)?.stdout;
    let os = parse_os_release(&os_text);
    let ecosystem = os.osv_ecosystem();

    let mut errors = Vec::new();
    if os.id.is_empty() {
        errors.push("/etc/os-release не найден или пуст: дистрибутив не определён".to_string());
    }

    let kernel = runner
        .run(ReadCommand::KernelRelease)
        .ok()
        .map(|o| o.stdout.trim().to_string())
        .filter(|s| !s.is_empty());
    let architecture = runner
        .run(ReadCommand::Architecture)
        .ok()
        .map(|o| o.stdout.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut packages = Vec::new();
    match ecosystem.as_deref().and_then(package_source) {
        Some(PkgSource::Dpkg) => match runner.run(ReadCommand::DpkgStatus) {
            Ok(out) if non_empty(&out.stdout) => {
                for pkg in parse_dpkg_status(&out.stdout) {
                    if let Some(p) =
                        observation_to_package(&dpkg_to_observation(&pkg, &os, String::new()))
                    {
                        packages.push(p);
                    }
                }
            }
            Ok(_) => errors
                .push("/var/lib/dpkg/status пуст или недоступен: пакеты не собраны".to_string()),
            Err(e) => errors.push(format!("не удалось прочитать список пакетов dpkg: {e}")),
        },
        Some(PkgSource::Rpm) => match runner.run(ReadCommand::RpmQuery) {
            Ok(out) if non_empty(&out.stdout) => {
                for pkg in parse_rpm_qa(&out.stdout) {
                    if let Some(p) = observation_to_package(&rpm_to_observation(&pkg, &os)) {
                        packages.push(p);
                    }
                }
            }
            Ok(_) => errors.push("rpm -qa вернул пустой список пакетов".to_string()),
            Err(e) => errors.push(format!("не удалось получить список пакетов rpm: {e}")),
        },
        Some(PkgSource::Apk) => match runner.run(ReadCommand::ApkInstalled) {
            Ok(out) if non_empty(&out.stdout) => {
                for pkg in parse_apk_installed(&out.stdout) {
                    if let Some(p) = observation_to_package(&apk_to_observation(&pkg, &os)) {
                        packages.push(p);
                    }
                }
            }
            Ok(_) => errors
                .push("/lib/apk/db/installed пуст или недоступен: пакеты не собраны".to_string()),
            Err(e) => errors.push(format!("не удалось прочитать список пакетов apk: {e}")),
        },
        None => {
            // Unknown or unsupported distribution: no package command is safe
            // to guess. The caller reports UNSUPPORTED_PLATFORM.
        }
    }

    Ok(RemoteInventory {
        os_name: format!(
            "{} ({})",
            os.display_name(),
            architecture.clone().unwrap_or_else(|| "?".to_string())
        ),
        ecosystem,
        kernel,
        architecture,
        packages,
        collection_errors: errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::MapRunner;

    const UBUNTU_OS_RELEASE: &str = "NAME=\"Ubuntu\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n";

    // A tiny real-shaped dpkg status: openssl is the source of libssl3.
    const DPKG_STATUS: &str = "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.2-0ubuntu1.15\nSource: openssl\nMaintainer: Ubuntu <x@y>\n\nPackage: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.1-6ubuntu1\nMaintainer: Ubuntu <x@y>\n";

    #[test]
    fn classifies_ubuntu_and_collects_dpkg_packages() {
        let mut runner = MapRunner::new()
            .with(ReadCommand::OsRelease, UBUNTU_OS_RELEASE)
            .with(ReadCommand::KernelRelease, "5.15.0-105-generic\n")
            .with(ReadCommand::Architecture, "x86_64\n")
            .with(ReadCommand::DpkgStatus, DPKG_STATUS);

        let inv = collect_inventory(&mut runner).unwrap();
        assert_eq!(inv.ecosystem.as_deref(), Some("Ubuntu:22.04:LTS"));
        assert_eq!(inv.kernel.as_deref(), Some("5.15.0-105-generic"));
        assert_eq!(inv.architecture.as_deref(), Some("x86_64"));
        assert!(inv.os_name.starts_with("Ubuntu 22.04.4 LTS"));
        // libssl3 carries source openssl; bash has no Source line, so its
        // source defaults to its own name.
        let libssl = inv.packages.iter().find(|p| p.name == "libssl3").unwrap();
        assert_eq!(libssl.source_name.as_deref(), Some("openssl"));
        assert!(inv.packages.iter().any(|p| p.name == "bash"));
        assert!(inv.collection_errors.is_empty());
    }

    #[test]
    fn unknown_distribution_yields_no_packages_and_no_guess() {
        let mut runner = MapRunner::new().with(
            ReadCommand::OsRelease,
            "ID=plan9\nNAME=\"Plan 9\"\nVERSION_ID=\"4\"\n",
        );
        let inv = collect_inventory(&mut runner).unwrap();
        assert_eq!(inv.ecosystem, None);
        assert!(inv.packages.is_empty());
    }
}
