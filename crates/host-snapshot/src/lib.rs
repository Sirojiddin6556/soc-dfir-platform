#![forbid(unsafe_code)]

//! Platform-neutral model of a live host snapshot.
//!
//! Both the Linux (`platform-linux`) and Windows (`platform-windows`)
//! collectors produce a [`HostSnapshot`]. The JSON shape is a strict superset
//! of the former `WindowsHostSnapshot`, so existing consumers (desktop UI,
//! investigation graph, CVE scanner) keep working; new fields are all
//! `#[serde(default)]` so older serialized snapshots still deserialize.
//!
//! Every value in a snapshot must come from the machine it describes. When a
//! collector cannot obtain something it leaves the field empty / `None` and
//! records why in [`HostSnapshot::collection_errors`] -- it never substitutes
//! placeholder data.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::net::{IpAddr, UdpSocket};
use std::path::Path;
use std::sync::Mutex;

/// Version stamped into every snapshot and observation produced by the
/// collectors in this workspace.
pub const COLLECTOR_VERSION: &str = "0.3.0";

/// Executables larger than this are not hashed (the hash is reported as
/// `None`, never as a hash of a truncated prefix).
pub const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub snapshot_id: String,
    /// Real hostname of the inspected machine.
    pub host: String,
    /// Primary (outbound-route) IP address; empty when it could not be
    /// determined. Never a hardcoded loopback placeholder.
    pub host_ip: String,
    /// Human readable OS name, e.g. "Ubuntu 24.04.5 LTS (x86_64)" or
    /// "Microsoft Windows 11 Pro (64-bit)".
    pub os: String,
    pub processes: Vec<ProcessObservation>,
    pub sockets: Vec<SocketObservation>,
    pub services: Vec<ServiceObservation>,
    /// Windows Task Scheduler tasks; on Linux cron entries and systemd timers.
    pub scheduled_tasks: Vec<ScheduledTaskObservation>,
    /// Windows Run/RunOnce keys; on Linux enabled systemd units, rc.local,
    /// XDG autostart entries and /etc/ld.so.preload.
    pub autoruns: Vec<AutorunObservation>,
    pub software: Vec<SoftwareObservation>,
    /// Account names (kept as plain strings for UI compatibility; see
    /// `user_accounts` for structured details).
    pub users: Vec<String>,
    pub firewall_rules: Vec<FirewallRule>,
    pub os_build: Option<u32>,
    pub os_ubr: Option<u32>,
    pub installed_kbs: Vec<String>,
    pub collected_at: String,
    pub collector_version: String,

    /// "linux", "windows" or another `std::env::consts::OS` value.
    #[serde(default)]
    pub platform: String,
    /// os-release `ID` on Linux ("ubuntu", "debian", "rhel", ...), "windows"
    /// on Windows.
    #[serde(default)]
    pub os_family: String,
    /// os-release `VERSION_ID` on Linux ("24.04"), Win32_OperatingSystem
    /// `Version` on Windows ("10.0.22631").
    #[serde(default)]
    pub os_version: String,
    /// os-release `VERSION_CODENAME` ("noble", "bookworm") when present.
    #[serde(default)]
    pub os_codename: Option<String>,
    /// Running kernel release (Linux) or NT kernel version (Windows).
    #[serde(default)]
    pub kernel: String,
    /// Machine architecture, e.g. "x86_64", "aarch64".
    #[serde(default)]
    pub architecture: String,
    /// All non-loopback local addresses that could be enumerated.
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub user_accounts: Vec<UserAccount>,
    /// Human readable reasons why parts of the snapshot are empty or
    /// incomplete (missing privileges, systemd not running, ...).
    #[serde(default)]
    pub collection_errors: Vec<String>,
}

impl HostSnapshot {
    /// An empty snapshot skeleton. Collectors fill it in; nothing here is
    /// invented.
    pub fn empty(snapshot_id: String, host: String, platform: &str, collected_at: String) -> Self {
        Self {
            snapshot_id,
            host,
            host_ip: String::new(),
            os: String::new(),
            processes: Vec::new(),
            sockets: Vec::new(),
            services: Vec::new(),
            scheduled_tasks: Vec::new(),
            autoruns: Vec::new(),
            software: Vec::new(),
            users: Vec::new(),
            firewall_rules: Vec::new(),
            os_build: None,
            os_ubr: None,
            installed_kbs: Vec::new(),
            collected_at,
            collector_version: COLLECTOR_VERSION.to_string(),
            platform: platform.to_string(),
            os_family: String::new(),
            os_version: String::new(),
            os_codename: None,
            kernel: String::new(),
            architecture: String::new(),
            ip_addresses: Vec::new(),
            user_accounts: Vec::new(),
            collection_errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessObservation {
    pub host_id: String,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
    pub username: Option<String>,
    pub session_id: u32,
    pub started_at: Option<String>,
    pub sha256: Option<String>,
    /// Authenticode signer. Only set when a signature was actually verified.
    pub signer: Option<String>,
    /// Architecture of the executable image ("x86_64", "aarch64", ...) or
    /// "unknown" when it could not be read.
    pub architecture: String,
    /// Windows integrity level when known; on Linux "root" for effective
    /// uid 0, otherwise "user". "unknown" when it could not be determined.
    pub integrity_level: String,
    pub collected_at: String,
    pub collector_version: String,
    pub source: String,
    /// Real uid (Linux).
    #[serde(default)]
    pub uid: Option<u32>,
    /// The process image was deleted from disk after start (Linux
    /// `/proc/<pid>/exe` ends in " (deleted)"), including memfd-backed
    /// ("fileless") executables.
    #[serde(default)]
    pub exe_deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketObservation {
    /// "TCP" or "UDP".
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    /// Normalized state: Listen, Established, SynSent, SynReceived,
    /// FinWait1, FinWait2, TimeWait, Closed, CloseWait, LastAck, Closing,
    /// NewSynRecv, Bound (unconnected UDP), DeleteTCB, Unknown.
    pub state: String,
    /// Owning process id; 0 when the owner could not be determined.
    pub pid: u32,
    pub process_name: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub collected_at: String,
    /// Kernel socket inode (Linux).
    #[serde(default)]
    pub inode: Option<u64>,
    /// Owning uid as reported by the kernel (Linux).
    #[serde(default)]
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub service_name: String,
    pub display_name: String,
    /// Windows: Running/Stopped. Linux: systemd "active/sub" (e.g.
    /// "active/running") or "unknown" when systemd is not running.
    pub state: String,
    /// Windows: Auto/Manual/Disabled. Linux: enabled/disabled/static/masked.
    pub start_type: String,
    pub binary_path: String,
    pub account: String,
    pub pid: Option<u32>,
    pub executable_hash: Option<String>,
    pub path_quoted: bool,
    pub unquoted_risk: bool,
    pub collected_at: String,
    /// "scm" (Windows Service Control Manager), "systemd" or "sysv".
    #[serde(default)]
    pub source: String,
    /// Unit file / init script path (Linux).
    #[serde(default)]
    pub unit_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorunObservation {
    /// Registry hive on Windows; on Linux the mechanism family
    /// ("systemd", "rc.local", "xdg-autostart", "ld.so.preload").
    pub hive: String,
    /// Registry key path or configuration file path.
    pub key: String,
    pub value_name: String,
    pub value_data: String,
    pub resolved_executable: String,
    pub hash: Option<String>,
    pub owner: Option<String>,
    pub timestamp: String,
    /// Normalized mechanism used by correlation rules: registry_run,
    /// systemd_service, systemd_user_service, rc_local, xdg_autostart,
    /// ld_preload.
    #[serde(default)]
    pub mechanism: String,
}

/// Backwards compatible name used by the Windows collector and older code.
pub type RegistryAutorunObservation = AutorunObservation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTaskObservation {
    pub task_name: String,
    pub task_path: String,
    pub state: String,
    pub action: Option<String>,
    pub arguments: Option<String>,
    pub run_level: String,
    pub collected_at: String,
    /// "task_scheduler", "cron", "cron_periodic" or "systemd_timer".
    #[serde(default)]
    pub mechanism: String,
    /// Cron expression / timer spec when applicable.
    #[serde(default)]
    pub schedule: Option<String>,
    /// Account the task runs as, when known.
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareObservation {
    pub product: String,
    pub version: String,
    pub publisher: String,
    pub install_location: String,
    pub install_date: String,
    pub architecture: String,
    /// "RegistryUninstall", "dpkg" or "rpm".
    pub source: String,
    pub confidence: f32,
    /// Package URL, e.g.
    /// `pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.5?arch=amd64&upstream=openssl&distro=ubuntu-24.04`.
    #[serde(default)]
    pub purl: Option<String>,
    /// OSV ecosystem string, e.g. "Debian:12", "Ubuntu:24.04:LTS",
    /// "AlmaLinux:9".
    #[serde(default)]
    pub ecosystem: Option<String>,
    /// Source package name (Debian `Source:`, RPM source rpm name). OSV
    /// Debian/Ubuntu advisories are keyed by source package.
    #[serde(default)]
    pub source_package: Option<String>,
    #[serde(default)]
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub direction: String,
    pub action: String,
    pub enabled: bool,
    /// Netfilter table (Linux).
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccount {
    pub name: String,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    /// Windows security identifier.
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub full_name: Option<String>,
    #[serde(default)]
    pub home: Option<String>,
    #[serde(default)]
    pub shell: Option<String>,
    /// `None` when the platform does not expose it without extra privileges.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Has a login shell (Linux) / is a regular enabled account (Windows).
    #[serde(default)]
    pub interactive: bool,
    /// Member of sudo/wheel/admin (Linux), uid 0, or of the local
    /// Administrators group (Windows).
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub last_logon: Option<String>,
    /// "passwd", "Get-LocalUser" or "Win32_UserAccount".
    #[serde(default)]
    pub source: String,
}

/// Outcome of hashing a file with a size cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileHash {
    Sha256(String),
    TooLarge(u64),
    Unreadable,
}

impl FileHash {
    pub fn into_option(self) -> Option<String> {
        match self {
            FileHash::Sha256(h) => Some(h),
            _ => None,
        }
    }
}

/// SHA-256 of a whole file, refusing files bigger than `max_bytes`. A hash of
/// a truncated prefix would look authoritative while being wrong, so large
/// files are reported as [`FileHash::TooLarge`] instead.
pub fn sha256_file_capped(path: &Path, max_bytes: u64) -> FileHash {
    use sha2::{Digest, Sha256};

    let Ok(mut file) = std::fs::File::open(path) else {
        return FileHash::Unreadable;
    };
    if let Ok(meta) = file.metadata() {
        if meta.len() > max_bytes {
            return FileHash::TooLarge(meta.len());
        }
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total > max_bytes {
                    // File grew while reading (or metadata lied): refuse.
                    return FileHash::TooLarge(total);
                }
                hasher.update(&buffer[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return FileHash::Unreadable,
        }
    }
    FileHash::Sha256(hex::encode(hasher.finalize()))
}

/// Process-wide memo of file hashes keyed by a caller supplied identity
/// (e.g. device+inode+size+mtime), so refreshing a snapshot does not re-hash
/// every unchanged executable.
pub struct FileHashCache {
    entries: Mutex<BTreeMap<String, Option<String>>>,
}

impl FileHashCache {
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns the cached hash for `key`, computing it from `path` on a miss.
    pub fn get_or_compute(&self, key: &str, path: &Path, max_bytes: u64) -> Option<String> {
        if let Ok(guard) = self.entries.lock() {
            if let Some(hit) = guard.get(key) {
                return hit.clone();
            }
        }
        let outcome = sha256_file_capped(path, max_bytes);
        // Do not cache transient read failures; do cache hashes and
        // "too large" verdicts.
        let cacheable = !matches!(outcome, FileHash::Unreadable);
        let value = outcome.into_option();
        if cacheable {
            if let Ok(mut guard) = self.entries.lock() {
                guard.insert(key.to_string(), value.clone());
            }
        }
        value
    }
}

impl Default for FileHashCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Real hostname of the machine this process runs on.
pub fn local_hostname() -> String {
    // Linux exposes the UTS hostname directly; prefer it over environment
    // variables, which are often stale or unset in services.
    if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let name = name.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(name) = std::env::var(var) {
            let name = name.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    if let Ok(output) = std::process::Command::new("hostname").output() {
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "unknown-host".to_string()
}

/// The local source address the kernel would use for outbound traffic.
///
/// `connect()` on a UDP socket sends no packets: it only performs a route
/// lookup and fixes the peer, after which `local_addr()` reports the source
/// address chosen for that route. The peer addresses below are therefore
/// never contacted. Returns `None` when there is no usable route.
pub fn primary_ip() -> Option<IpAddr> {
    let probes: [(&str, &str); 2] = [
        ("0.0.0.0:0", "8.8.8.8:53"),
        ("[::]:0", "[2001:4860:4860::8888]:53"),
    ];
    for (bind, peer) in probes {
        let Ok(socket) = UdpSocket::bind(bind) else {
            continue;
        };
        if socket.connect(peer).is_err() {
            continue;
        }
        if let Ok(local) = socket.local_addr() {
            let ip = local.ip();
            if !ip.is_unspecified() && !ip.is_loopback() {
                return Some(ip);
            }
        }
    }
    None
}

/// Accepts either a single JSON object or an array of objects (PowerShell's
/// `ConvertTo-Json` emits a bare object when a pipeline yields one item) and
/// always returns a list.
pub fn json_items(json: &str) -> Vec<serde_json::Value> {
    let trimmed = json.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Vec::new();
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Array(items)) => items,
        Ok(value @ serde_json::Value::Object(_)) => vec![value],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_small_file_is_exact() {
        let dir = std::env::temp_dir().join(format!("host-snapshot-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("abc.txt");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file_capped(&path, 1024),
            FileHash::Sha256(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string()
            )
        );
        // A file over the cap is refused rather than hashed partially.
        assert_eq!(sha256_file_capped(&path, 2), FileHash::TooLarge(3));
        assert_eq!(
            sha256_file_capped(&dir.join("missing"), 1024),
            FileHash::Unreadable
        );

        let cache = FileHashCache::new();
        let first = cache.get_or_compute("k", &path, 1024);
        std::fs::write(&path, b"changed").unwrap();
        // Same identity key -> served from cache.
        assert_eq!(cache.get_or_compute("k", &path, 1024), first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_items_accepts_object_or_array() {
        assert_eq!(json_items(r#"{"a":1}"#).len(), 1);
        assert_eq!(json_items(r#"[{"a":1},{"a":2}]"#).len(), 2);
        assert!(json_items("").is_empty());
        assert!(json_items("not json").is_empty());
        assert_eq!(json_items("\u{feff}[{\"a\":1}]").len(), 1);
    }

    #[test]
    fn primary_ip_is_never_loopback() {
        if let Some(ip) = primary_ip() {
            assert!(!ip.is_loopback());
            assert!(!ip.is_unspecified());
        }
    }

    #[test]
    fn hostname_is_real() {
        let name = local_hostname();
        assert!(!name.is_empty());
        if let Ok(kernel_name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            assert_eq!(name, kernel_name.trim());
        }
    }

    #[test]
    fn old_windows_snapshot_json_still_deserializes() {
        let old = r#"{"snapshot_id":"SNAP-1","host":"PC","host_ip":"10.0.0.5","os":"Windows",
            "processes":[],"sockets":[],"services":[],"scheduled_tasks":[],"autoruns":[],
            "software":[],"users":[],"firewall_rules":[],"os_build":22631,"os_ubr":4037,
            "installed_kbs":["KB5034441"],"collected_at":"2026-01-01T00:00:00Z","collector_version":"0.2.0"}"#;
        let snap: HostSnapshot = serde_json::from_str(old).unwrap();
        assert_eq!(snap.os_build, Some(22631));
        assert!(snap.platform.is_empty());
        assert!(snap.collection_errors.is_empty());
    }
}
