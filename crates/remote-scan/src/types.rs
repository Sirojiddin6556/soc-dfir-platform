//! Shared types for the remote scan: the target, credentials, host-key
//! handling, the collected inventory and the final report.

use serde::Serialize;
use vulnerability_engine::app_scan::AppScanReport;
use vulnerability_engine::msrc::WindowsScanReport;
use vulnerability_engine::package_scan::{InstalledPackage, PackageScanReport};

/// A host to scan. `host` is exactly what the operator typed (an address or
/// name they are authorised to scan); nothing is discovered or guessed.
#[derive(Debug, Clone)]
pub struct RemoteTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl RemoteTarget {
    pub fn new(host: impl Into<String>, port: u16, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
        }
    }
}

/// How the operator authenticates. The secret is held only for the scan and is
/// never written to a report, a log or the database.
#[derive(Clone)]
pub enum Credential {
    Password(String),
    /// A private key in OpenSSH/PEM form, with an optional passphrase.
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the secret, even by accident, in a debug line or trace.
        match self {
            Credential::Password(_) => f.write_str("Password(***)"),
            Credential::PrivateKey { .. } => f.write_str("PrivateKey(***)"),
        }
    }
}

/// A server host key the operator is shown so they can confirm the host is
/// theirs before any credential is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostKey {
    /// Key algorithm, e.g. "ssh-ed25519".
    pub algorithm: String,
    /// Base64 SHA-256 of the key, the modern OpenSSH fingerprint form
    /// (`SHA256:...`), without the prefix.
    pub sha256: String,
}

impl HostKey {
    /// The fingerprint as OpenSSH prints it, e.g. `SHA256:abc...`.
    pub fn fingerprint(&self) -> String {
        format!("SHA256:{}", self.sha256)
    }
}

/// Trust-on-first-use policy. The first connection *discovers* the key and
/// stops before authenticating; once the operator confirms the fingerprint, the
/// scan runs with [`HostKeyPolicy::Expect`], which refuses to authenticate
/// against any other key.
#[derive(Debug, Clone)]
pub enum HostKeyPolicy {
    /// Fetch the host key and disconnect without authenticating.
    Discover,
    /// Proceed only if the server presents this exact SHA-256 fingerprint.
    Expect(String),
}

/// What the collected host turned out to be, plus the packages to match.
#[derive(Debug, Clone, Default)]
pub struct RemoteInventory {
    /// Human-readable OS name, e.g. "Ubuntu 22.04.4 LTS".
    pub os_name: String,
    /// The OSV ecosystem of the distribution, when recognised
    /// ("Ubuntu:22.04", "Debian:12", "Alpine:v3.19", ...).
    pub ecosystem: Option<String>,
    pub kernel: Option<String>,
    pub architecture: Option<String>,
    /// Packages mapped into the shared matcher's shape.
    pub packages: Vec<InstalledPackage>,
    /// Non-fatal problems (a command returned nothing, a file was unreadable).
    pub collection_errors: Vec<String>,
}

/// The outcome category of a scan, mirroring the local package scan's statuses
/// so the UI can treat remote and local results the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoteScanStatus {
    /// Host key fetched; waiting for the operator to confirm the fingerprint.
    HostKeyUnconfirmed,
    /// The distribution is not one whose packages can be matched.
    UnsupportedPlatform,
    /// No installed packages could be read.
    NoPackageInventory,
    /// The advisory database has not been loaded for this ecosystem.
    VulndbEmpty,
    /// Packages checked, nothing known-vulnerable.
    NoKnownMatchedVulnerabilities,
    /// Known vulnerabilities found.
    VulnerabilitiesFound,
}

/// Which OS family the connected host turned out to be. The scan auto-detects
/// this after authenticating and branches to the matching collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RemotePlatform {
    Linux,
    Windows,
}

/// The outcome category of the Windows OS/KB (MSRC) match, mirroring the local
/// Windows scan so the UI treats remote and local the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsOsStatus {
    /// The host's Windows version/build could not be read.
    Unsupported,
    /// No MSRC bulletins are loaded.
    VulndbEmpty,
    /// The product is not present in the loaded bulletins.
    ProductNotInDatabase,
    /// Build matched against the bulletins, nothing missing.
    NoKnownMatchedVulnerabilities,
    /// The build is missing fixes for known CVEs.
    VulnerabilitiesFound,
}

/// The Windows half of a remote scan: the OS/KB (MSRC) result and the
/// installed-program (NVD) result, plus the host facts the UI shows.
#[derive(Debug, Clone)]
pub struct WindowsRemoteReport {
    pub caption: String,
    pub full_build: String,
    pub display_version: String,
    /// The MSRC product the host was matched to, when recognised.
    pub product: Option<String>,
    pub installed_updates: usize,
    pub os_status: WindowsOsStatus,
    /// The MSRC OS/KB scan, when the product was recognised and matched.
    pub os_cve: Option<WindowsScanReport>,
    /// The installed-program CVE scan (NVD), when there were programs to check.
    pub app_cve: Option<AppScanReport>,
}

/// The full result of a remote scan.
#[derive(Debug, Clone)]
pub struct RemoteScanReport {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key: Option<HostKey>,
    pub platform: RemotePlatform,
    pub status: RemoteScanStatus,
    pub os_name: String,
    pub ecosystem: Option<String>,
    pub kernel: Option<String>,
    pub architecture: Option<String>,
    /// The package CVE result, when the scan got far enough to produce one.
    pub package_report: Option<PackageScanReport>,
    /// The CIS configuration-audit result. Runs on any Linux or Windows host
    /// with the relevant settings, independent of whether CVEs could be
    /// matched, so it is present even when the CVE reports are not.
    pub cis_report: Option<crate::cis::CisReport>,
    /// The Windows CVE results, present only for a Windows target.
    pub windows: Option<WindowsRemoteReport>,
    pub collection_errors: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("ошибка соединения с {host}: {source}")]
    Connect {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("не удалось проверить ключ хоста: {0}")]
    HostKey(String),
    /// Internal signal: discovery fetched the key and refused to continue, as
    /// intended. The caller turns this into a confirmation prompt.
    #[error("ключ хоста получен и ожидает подтверждения оператором")]
    HostKeyDiscovered(HostKey),
    #[error(
        "отпечаток ключа хоста не совпал: ожидался {expected}, получен {actual}. \
         Подключение прервано, пароль не отправлен"
    )]
    HostKeyMismatch { expected: String, actual: String },
    #[error("аутентификация не удалась (проверьте логин, пароль или ключ)")]
    AuthFailed,
    #[error("удалённая команда не выполнена: {0}")]
    Command(String),
    #[error("ошибка SSH: {0}")]
    Ssh(String),
    #[error("ошибка SFTP: {0}")]
    Sftp(String),
    #[error("ошибка чтения базы уязвимостей: {0}")]
    Database(#[from] rusqlite::Error),
}
