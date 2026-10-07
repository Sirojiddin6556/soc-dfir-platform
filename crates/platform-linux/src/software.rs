#![forbid(unsafe_code)]

//! Installed packages from dpkg (`/var/lib/dpkg/status`) and rpm, with
//! package URLs and OSV ecosystem names for vulnerability matching.

use crate::os::OsRelease;
use host_snapshot::SoftwareObservation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpkgPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub maintainer: String,
    /// Source package name (defaults to the binary package name).
    pub source_name: String,
    /// Source package version (defaults to the binary version).
    pub source_version: String,
    pub status: String,
}

/// Parses dpkg's status database, keeping packages whose status (third word
/// of `Status:`) is `installed` -- this includes packages on hold.
pub fn parse_dpkg_status(content: &str) -> Vec<DpkgPackage> {
    let mut out = Vec::new();
    for paragraph in content.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut arch = String::new();
        let mut maintainer = String::new();
        let mut source: Option<String> = None;
        let mut status = String::new();
        for line in paragraph.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue; // continuation of a multi-line field
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Package" => name = Some(value.to_string()),
                "Version" => version = Some(value.to_string()),
                "Architecture" => arch = value.to_string(),
                "Maintainer" => maintainer = value.to_string(),
                "Source" => source = Some(value.to_string()),
                "Status" => status = value.to_string(),
                _ => {}
            }
        }
        let (Some(name), Some(version)) = (name, version) else {
            continue;
        };
        if status.split_whitespace().nth(2) != Some("installed") {
            continue;
        }
        // "Source: glibc (2.39-0ubuntu8.3)" carries an explicit source version.
        let (source_name, source_version) = match source {
            Some(src) => match src.split_once(" (") {
                Some((n, v)) => (
                    n.trim().to_string(),
                    v.trim_end_matches(')').trim().to_string(),
                ),
                None => (src.trim().to_string(), version.clone()),
            },
            None => (name.clone(), version.clone()),
        };
        out.push(DpkgPackage {
            name,
            version,
            architecture: arch,
            maintainer,
            source_name,
            source_version,
            status,
        });
    }
    out
}

/// The `rpm -qa --queryformat` used by the collector (static; never built
/// from input). Fields are tab separated.
pub const RPM_QUERY_FORMAT: &str =
    "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\t%{SOURCERPM}\\t%{INSTALLTIME}\\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmPackage {
    pub name: String,
    pub epoch: Option<String>,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub vendor: String,
    pub source_rpm: Option<String>,
    pub install_time: Option<i64>,
}

impl RpmPackage {
    /// `[epoch:]version-release`
    pub fn evr(&self) -> String {
        match &self.epoch {
            Some(e) => format!("{}:{}-{}", e, self.version, self.release),
            None => format!("{}-{}", self.version, self.release),
        }
    }

    /// Source package name from `openssl-3.0.7-25.el9_3.src.rpm`.
    pub fn source_name(&self) -> Option<String> {
        let srpm = self.source_rpm.as_deref()?;
        let base = srpm
            .strip_suffix(".src.rpm")
            .or_else(|| srpm.strip_suffix(".nosrc.rpm"))?;
        let (rest, _release) = base.rsplit_once('-')?;
        let (name, _version) = rest.rsplit_once('-')?;
        Some(name.to_string())
    }
}

fn none_if_unset(v: &str) -> Option<String> {
    let v = v.trim();
    (!v.is_empty() && v != "(none)").then(|| v.to_string())
}

pub fn parse_rpm_qa(output: &str) -> Vec<RpmPackage> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 8 || f[0].is_empty() || f[0] == "gpg-pubkey" {
                return None;
            }
            Some(RpmPackage {
                name: f[0].to_string(),
                epoch: none_if_unset(f[1]),
                version: f[2].to_string(),
                release: f[3].to_string(),
                arch: f[4].to_string(),
                vendor: none_if_unset(f[5]).unwrap_or_default(),
                source_rpm: none_if_unset(f[6]),
                install_time: f[7].trim().parse().ok(),
            })
        })
        .collect()
}

/// Percent-encodes a purl component: unreserved characters and ':' stay as
/// is, everything else (including '+', which a decoder would turn into a
/// space) is encoded.
pub fn purl_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn purl(
    kind: &str,
    namespace: &str,
    name: &str,
    version: &str,
    mut qualifiers: Vec<(&str, String)>,
) -> String {
    qualifiers.retain(|(_, v)| !v.is_empty());
    // purl spec: qualifiers sorted by key.
    qualifiers.sort_by(|a, b| a.0.cmp(b.0));
    let mut s = format!(
        "pkg:{}/{}/{}@{}",
        kind,
        purl_encode(namespace),
        purl_encode(name),
        purl_encode(version)
    );
    if !qualifiers.is_empty() {
        s.push('?');
        s.push_str(
            &qualifiers
                .iter()
                .map(|(k, v)| format!("{}={}", k, purl_encode(v)))
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    s
}

/// Package URL for a Debian-family package, in the form produced by Syft:
/// `pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl`.
pub fn deb_purl(pkg: &DpkgPackage, os: &OsRelease) -> String {
    let namespace = if os.id.is_empty() { "debian" } else { &os.id };
    let upstream = if pkg.source_name == pkg.name {
        String::new()
    } else if pkg.source_version != pkg.version {
        format!("{}@{}", pkg.source_name, pkg.source_version)
    } else {
        pkg.source_name.clone()
    };
    purl(
        "deb",
        namespace,
        &pkg.name,
        &pkg.version,
        vec![
            ("arch", pkg.architecture.clone()),
            ("distro", os.purl_distro().unwrap_or_default()),
            ("upstream", upstream),
        ],
    )
}

/// `pkg:rpm/rocky/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=openssl-3.0.7-25.el9_3.src.rpm`
pub fn rpm_purl(pkg: &RpmPackage, os: &OsRelease) -> String {
    let namespace = if os.id.is_empty() { "redhat" } else { &os.id };
    purl(
        "rpm",
        namespace,
        &pkg.name,
        &format!("{}-{}", pkg.version, pkg.release),
        vec![
            ("arch", pkg.arch.clone()),
            ("distro", os.purl_distro().unwrap_or_default()),
            ("epoch", pkg.epoch.clone().unwrap_or_default()),
            ("upstream", pkg.source_rpm.clone().unwrap_or_default()),
        ],
    )
}

pub fn dpkg_to_observation(
    pkg: &DpkgPackage,
    os: &OsRelease,
    install_date: String,
) -> SoftwareObservation {
    SoftwareObservation {
        product: pkg.name.clone(),
        version: pkg.version.clone(),
        publisher: pkg.maintainer.clone(),
        install_location: String::new(),
        install_date,
        architecture: pkg.architecture.clone(),
        source: "dpkg".to_string(),
        confidence: 1.0,
        purl: Some(deb_purl(pkg, os)),
        ecosystem: os.osv_ecosystem(),
        source_package: Some(pkg.source_name.clone()),
        source_version: Some(pkg.source_version.clone()),
    }
}

pub fn rpm_to_observation(pkg: &RpmPackage, os: &OsRelease) -> SoftwareObservation {
    let install_date = pkg
        .install_time
        .and_then(|t| chrono::DateTime::<chrono::Utc>::from_timestamp(t, 0))
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    SoftwareObservation {
        product: pkg.name.clone(),
        version: pkg.evr(),
        publisher: pkg.vendor.clone(),
        install_location: String::new(),
        install_date,
        architecture: pkg.arch.clone(),
        source: "rpm".to_string(),
        confidence: 1.0,
        purl: Some(rpm_purl(pkg, os)),
        ecosystem: os.osv_ecosystem(),
        source_package: pkg.source_name(),
        source_version: Some(format!("{}-{}", pkg.version, pkg.release)),
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::*;
    use crate::util::file_mtime_rfc3339;
    use std::path::Path;

    fn rpm_available(root: &Path) -> bool {
        let has_db = ["var/lib/rpm", "usr/lib/sysimage/rpm"]
            .iter()
            .any(|d| root.join(d).is_dir());
        has_db && root == Path::new("/")
    }

    pub fn collect(
        root: &Path,
        os: &OsRelease,
        errors: &mut Vec<String>,
    ) -> Vec<SoftwareObservation> {
        let mut out = Vec::new();
        let mut found_db = false;

        let status_path = root.join("var/lib/dpkg/status");
        if status_path.exists() {
            found_db = true;
            match std::fs::read_to_string(&status_path) {
                Ok(content) => {
                    for pkg in parse_dpkg_status(&content) {
                        // dpkg does not record install time; the file list's
                        // mtime is when the package was last unpacked.
                        let info = root.join("var/lib/dpkg/info");
                        let date = file_mtime_rfc3339(
                            &info.join(format!("{}:{}.list", pkg.name, pkg.architecture)),
                        )
                        .or_else(|| file_mtime_rfc3339(&info.join(format!("{}.list", pkg.name))))
                        .unwrap_or_default();
                        out.push(dpkg_to_observation(&pkg, os, date));
                    }
                }
                Err(e) => errors.push(format!("Не удалось прочитать /var/lib/dpkg/status: {}", e)),
            }
        }

        if rpm_available(root) {
            found_db = true;
            match std::process::Command::new("rpm")
                .args(["-qa", "--queryformat", RPM_QUERY_FORMAT])
                .output()
            {
                Ok(o) if o.status.success() => {
                    for pkg in parse_rpm_qa(&String::from_utf8_lossy(&o.stdout)) {
                        out.push(rpm_to_observation(&pkg, os));
                    }
                }
                Ok(o) => errors.push(format!(
                    "rpm -qa завершился с ошибкой: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => errors.push(format!("rpm недоступен: {}", e)),
            }
        }

        if !found_db {
            errors
                .push("Не найдена база пакетного менеджера (dpkg/rpm): список ПО пуст".to_string());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::parse_os_release;

    const DPKG_STATUS: &str = "Package: libssl3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 6188
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.11-1~deb12u2
Depends: libc6 (>= 2.34)
Description: Secure Sockets Layer toolkit - shared libraries
 This package is part of the OpenSSL project's implementation of the SSL
 and TLS cryptographic protocols for secure communication over the
 Internet.
Homepage: https://www.openssl.org/

Package: bsdutils
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Maintainer: util-linux packagers <util-linux@packages.debian.org>
Architecture: amd64
Source: util-linux (2.38.1-5)
Version: 1:2.38.1-5+b1
Description: basic utilities from 4.4BSD-Lite

Package: removed-but-configured
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1
Description: should not be listed

Package: held-package
Status: hold ok installed
Maintainer: Someone <a@b.c>
Architecture: all
Version: 2.0
Description: on hold, still installed

Package: half
Status: install reinstreq half-installed
Architecture: amd64
Version: 0.1
";

    const DEBIAN_OS: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\n";

    #[test]
    fn parses_installed_dpkg_packages_only() {
        let pkgs = parse_dpkg_status(DPKG_STATUS);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["libssl3", "bsdutils", "held-package"]);

        let ssl = &pkgs[0];
        assert_eq!(ssl.version, "3.0.11-1~deb12u2");
        assert_eq!(ssl.architecture, "amd64");
        assert_eq!(ssl.source_name, "openssl");
        assert_eq!(ssl.source_version, "3.0.11-1~deb12u2");

        let bsd = &pkgs[1];
        assert_eq!(bsd.version, "1:2.38.1-5+b1");
        assert_eq!(bsd.source_name, "util-linux");
        assert_eq!(bsd.source_version, "2.38.1-5");

        assert_eq!(pkgs[2].source_name, "held-package");
    }

    #[test]
    fn builds_deb_purls_and_osv_ecosystem() {
        let os = parse_os_release(DEBIAN_OS);
        let pkgs = parse_dpkg_status(DPKG_STATUS);
        assert_eq!(
            deb_purl(&pkgs[0], &os),
            "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"
        );
        assert_eq!(
            deb_purl(&pkgs[1], &os),
            "pkg:deb/debian/bsdutils@1:2.38.1-5%2Bb1?arch=amd64&distro=debian-12&upstream=util-linux%402.38.1-5"
        );
        assert_eq!(
            deb_purl(&pkgs[2], &os),
            "pkg:deb/debian/held-package@2.0?arch=all&distro=debian-12"
        );

        let obs = dpkg_to_observation(&pkgs[0], &os, String::new());
        assert_eq!(obs.source, "dpkg");
        assert_eq!(obs.ecosystem.as_deref(), Some("Debian:12"));
        assert_eq!(obs.source_package.as_deref(), Some("openssl"));
        assert_eq!(obs.product, "libssl3");
    }

    const RPM_QA: &str = "openssl-libs\t1\t3.0.7\t25.el9_3\tx86_64\tRocky Enterprise Software Foundation\topenssl-3.0.7-25.el9_3.src.rpm\t1704067200
bash\t(none)\t5.1.8\t6.el9_1\tx86_64\tRocky Enterprise Software Foundation\tbash-5.1.8-6.el9_1.src.rpm\t1704067100
gpg-pubkey\t(none)\t350d275d\t6279464b\t(none)\t(none)\t(none)\t1704067000
kernel-core\t(none)\t5.14.0\t362.13.1.el9_3\tx86_64\t(none)\t(none)\tnot-a-number
";

    #[test]
    fn parses_rpm_query_output() {
        let os = parse_os_release(
            "ID=\"rocky\"\nVERSION_ID=\"9.3\"\nPRETTY_NAME=\"Rocky Linux 9.3 (Blue Onyx)\"\n",
        );
        let pkgs = parse_rpm_qa(RPM_QA);
        assert_eq!(pkgs.len(), 3, "gpg-pubkey pseudo packages are skipped");
        assert_eq!(pkgs[0].evr(), "1:3.0.7-25.el9_3");
        assert_eq!(pkgs[0].source_name().as_deref(), Some("openssl"));
        assert_eq!(pkgs[1].epoch, None);
        assert_eq!(pkgs[1].evr(), "5.1.8-6.el9_1");
        assert_eq!(pkgs[2].vendor, "");
        assert_eq!(pkgs[2].install_time, None);
        assert_eq!(pkgs[2].source_name(), None);

        assert_eq!(
            rpm_purl(&pkgs[0], &os),
            "pkg:rpm/rocky/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=openssl-3.0.7-25.el9_3.src.rpm"
        );
        let obs = rpm_to_observation(&pkgs[0], &os);
        assert_eq!(obs.source, "rpm");
        assert_eq!(obs.version, "1:3.0.7-25.el9_3");
        assert_eq!(obs.ecosystem.as_deref(), Some("Rocky Linux:9"));
        assert_eq!(obs.install_date, "2024-01-01T00:00:00+00:00");
    }

    #[test]
    fn purl_encoding() {
        assert_eq!(purl_encode("1:2.38.1-5+b1"), "1:2.38.1-5%2Bb1");
        assert_eq!(purl_encode("a b/c@d"), "a%20b%2Fc%40d");
        assert_eq!(purl_encode("3.0.11-1~deb12u2"), "3.0.11-1~deb12u2");
    }
}
