#![forbid(unsafe_code)]

//! Operating system identification from `/etc/os-release` and the kernel.

/// Parsed `/etc/os-release` (or `/usr/lib/os-release`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub id_like: Vec<String>,
    pub name: String,
    pub pretty_name: String,
    pub version: String,
    pub version_id: String,
    pub version_codename: Option<String>,
}

/// Unquotes an os-release value (shell-like: single or double quotes, with
/// backslash escapes inside double quotes).
fn unquote(raw: &str) -> String {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else {
                out.push(c);
            }
        }
        out
    } else if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.to_string()
    }
}

pub fn parse_os_release(content: &str) -> OsRelease {
    let mut os = OsRelease::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(value);
        match key.trim() {
            "ID" => os.id = value.to_ascii_lowercase(),
            "ID_LIKE" => {
                os.id_like = value
                    .split_whitespace()
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            }
            "NAME" => os.name = value,
            "PRETTY_NAME" => os.pretty_name = value,
            "VERSION" => os.version = value,
            "VERSION_ID" => os.version_id = value,
            "VERSION_CODENAME" if !value.is_empty() => os.version_codename = Some(value),
            _ => {}
        }
    }
    os
}

impl OsRelease {
    /// Display name, e.g. "Ubuntu 24.04.5 LTS".
    pub fn display_name(&self) -> String {
        if !self.pretty_name.is_empty() {
            self.pretty_name.clone()
        } else if !self.name.is_empty() {
            format!("{} {}", self.name, self.version).trim().to_string()
        } else {
            "Linux".to_string()
        }
    }

    /// `distro` qualifier for package URLs, following the convention used by
    /// Syft/Grype: `<ID>-<VERSION_ID>` (e.g. "debian-12", "ubuntu-24.04").
    pub fn purl_distro(&self) -> Option<String> {
        if self.id.is_empty() || self.version_id.is_empty() {
            None
        } else {
            Some(format!("{}-{}", self.id, self.version_id))
        }
    }

    fn major_version(&self) -> &str {
        self.version_id
            .split('.')
            .next()
            .unwrap_or(&self.version_id)
    }

    /// The OSV ecosystem name for this distribution's packages, when OSV
    /// publishes one (https://ossf.github.io/osv-schema/#affectedpackage-field).
    pub fn osv_ecosystem(&self) -> Option<String> {
        if self.version_id.is_empty() {
            return None;
        }
        match self.id.as_str() {
            "debian" => Some(format!("Debian:{}", self.major_version())),
            "ubuntu" => {
                if self.version.contains("LTS") || self.pretty_name.contains("LTS") {
                    Some(format!("Ubuntu:{}:LTS", self.version_id))
                } else {
                    Some(format!("Ubuntu:{}", self.version_id))
                }
            }
            "almalinux" => Some(format!("AlmaLinux:{}", self.major_version())),
            "rocky" => Some(format!("Rocky Linux:{}", self.major_version())),
            "alpine" => {
                let mut parts = self.version_id.split('.');
                match (parts.next(), parts.next()) {
                    (Some(major), Some(minor)) => Some(format!("Alpine:v{}.{}", major, minor)),
                    _ => None,
                }
            }
            "opensuse-leap" => Some(format!("openSUSE:Leap {}", self.version_id)),
            "rhel" => Some("Red Hat".to_string()),
            _ => None,
        }
    }
}

/// Maps a `uname -m` style machine name to the dpkg architecture name used
/// in Debian package URLs.
pub fn dpkg_arch_for_machine(machine: &str) -> &str {
    match machine {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "i386" | "i486" | "i586" | "i686" => "i386",
        "armv7l" => "armhf",
        "ppc64le" => "ppc64el",
        other => other,
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::{parse_os_release, OsRelease};
    use std::path::Path;

    pub fn read_os_release(root: &Path) -> Option<OsRelease> {
        for candidate in ["etc/os-release", "usr/lib/os-release"] {
            if let Ok(content) = std::fs::read_to_string(root.join(candidate)) {
                return Some(parse_os_release(&content));
            }
        }
        None
    }

    pub fn kernel_release() -> Option<String> {
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let release = release.trim();
            if !release.is_empty() {
                return Some(release.to_string());
            }
        }
        let out = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()?;
        let release = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!release.is_empty()).then_some(release)
    }

    pub fn machine_arch() -> String {
        if let Ok(arch) = std::fs::read_to_string("/proc/sys/kernel/arch") {
            let arch = arch.trim();
            if !arch.is_empty() {
                return arch.to_string();
            }
        }
        if let Ok(out) = std::process::Command::new("uname").arg("-m").output() {
            let arch = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !arch.is_empty() {
                return arch;
            }
        }
        std::env::consts::ARCH.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: &str = r#"PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.5 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
"#;

    const DEBIAN: &str = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
"#;

    const ROCKY: &str = "NAME=\"Rocky Linux\"\nVERSION=\"9.3 (Blue Onyx)\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.3\"\nPRETTY_NAME=\"Rocky Linux 9.3 (Blue Onyx)\"\n";

    #[test]
    fn parses_ubuntu_os_release() {
        let os = parse_os_release(UBUNTU);
        assert_eq!(os.id, "ubuntu");
        assert_eq!(os.id_like, vec!["debian"]);
        assert_eq!(os.pretty_name, "Ubuntu 24.04.5 LTS");
        assert_eq!(os.version_id, "24.04");
        assert_eq!(os.version_codename.as_deref(), Some("noble"));
        assert_eq!(os.purl_distro().as_deref(), Some("ubuntu-24.04"));
        assert_eq!(os.osv_ecosystem().as_deref(), Some("Ubuntu:24.04:LTS"));
    }

    #[test]
    fn parses_debian_and_rocky() {
        let debian = parse_os_release(DEBIAN);
        assert_eq!(debian.display_name(), "Debian GNU/Linux 12 (bookworm)");
        assert_eq!(debian.osv_ecosystem().as_deref(), Some("Debian:12"));
        assert_eq!(debian.purl_distro().as_deref(), Some("debian-12"));

        let rocky = parse_os_release(ROCKY);
        assert_eq!(rocky.id, "rocky");
        assert_eq!(rocky.id_like, vec!["rhel", "centos", "fedora"]);
        assert_eq!(rocky.osv_ecosystem().as_deref(), Some("Rocky Linux:9"));
    }

    #[test]
    fn handles_escapes_and_comments() {
        let os = parse_os_release("# comment\nNAME=\"My \\\"Distro\\\"\"\nID='custom'\n");
        assert_eq!(os.name, "My \"Distro\"");
        assert_eq!(os.id, "custom");
        assert_eq!(os.osv_ecosystem(), None);
    }

    #[test]
    fn maps_dpkg_architectures() {
        assert_eq!(dpkg_arch_for_machine("x86_64"), "amd64");
        assert_eq!(dpkg_arch_for_machine("aarch64"), "arm64");
        assert_eq!(dpkg_arch_for_machine("riscv64"), "riscv64");
    }
}
