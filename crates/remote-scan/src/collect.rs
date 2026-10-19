//! What a forensic artifact collection over SSH gathers from a Linux host, and
//! the transport-free rules around it: which files and directories are worth
//! taking, how a remote path maps onto a safe local path, which account homes
//! to visit, and the manifest that records exactly what was (and was not)
//! collected.
//!
//! The collection is **read-only** on the target: it lists directories, reads
//! files and runs the fixed read-only commands in
//! [`crate::command::ReadCommand`]. Nothing is written, renamed or removed on
//! the server. [`crate::ssh_collect`] drives these rules against a live SFTP
//! session; everything here is unit-tested without a network.

use serde::Serialize;

/// Bounds on one collection, so a huge or hostile host cannot fill the disk or
/// run forever. Logs are the point of the exercise, so the per-file cap is far
/// larger than the project-fetch cap.
#[derive(Debug, Clone, Copy)]
pub struct CollectLimits {
    /// A single file larger than this is recorded as skipped, not copied.
    pub max_file_bytes: u64,
    /// Bytes copied in total, at most.
    pub max_total_bytes: u64,
    /// Files copied, at most.
    pub max_files: usize,
    /// Account home directories visited, at most.
    pub max_users: usize,
    /// Entries read from any one directory listing, at most.
    pub max_dir_entries: usize,
    /// Output kept from one read-only command, at most.
    pub max_command_bytes: u64,
    /// Output kept from the journald export, at most.
    pub max_journal_bytes: u64,
}

impl Default for CollectLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 512 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_files: 4_000,
            max_users: 200,
            max_dir_entries: 2_000,
            max_command_bytes: 16 * 1024 * 1024,
            max_journal_bytes: 128 * 1024 * 1024,
        }
    }
}

/// What a collected artifact is, so the analyst can filter the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A text log (auth, syslog, web server, audit, package manager).
    Log,
    /// Account database and password policy (passwd, group, shadow, login.defs).
    Account,
    /// sudo policy.
    Sudo,
    /// cron: system crontab, drop-ins, periodic scripts, user crontabs.
    Cron,
    /// systemd units and timers installed by an administrator (or an attacker).
    Systemd,
    /// SSH server configuration and per-account keys.
    Ssh,
    /// Shell start-up files and command history.
    Shell,
    /// Other system identity and persistence points (hosts, preload, rc.local).
    System,
    /// The captured output of a read-only command.
    Command,
}

/// System files taken by exact path.
pub const SYSTEM_FILES: &[(&str, ArtifactKind)] = &[
    ("/etc/hostname", ArtifactKind::System),
    ("/etc/os-release", ArtifactKind::System),
    ("/etc/timezone", ArtifactKind::System),
    ("/etc/hosts", ArtifactKind::System),
    ("/etc/resolv.conf", ArtifactKind::System),
    ("/etc/ld.so.preload", ArtifactKind::System),
    ("/etc/rc.local", ArtifactKind::System),
    ("/etc/passwd", ArtifactKind::Account),
    ("/etc/group", ArtifactKind::Account),
    ("/etc/shadow", ArtifactKind::Account),
    ("/etc/login.defs", ArtifactKind::Account),
    ("/etc/sudoers", ArtifactKind::Sudo),
    ("/etc/crontab", ArtifactKind::Cron),
    ("/etc/anacrontab", ArtifactKind::Cron),
    ("/etc/ssh/sshd_config", ArtifactKind::Ssh),
    ("/etc/profile", ArtifactKind::Shell),
    ("/etc/bash.bashrc", ArtifactKind::Shell),
    ("/etc/bashrc", ArtifactKind::Shell),
    ("/etc/environment", ArtifactKind::Shell),
];

/// Directories whose regular files are all taken (one level deep). For the
/// systemd directory, `*.wants`/`*.requires` subdirectories are listed too,
/// because the symlinks in them are what "enabled" means.
pub const SYSTEM_DIRS: &[(&str, ArtifactKind)] = &[
    ("/etc/sudoers.d", ArtifactKind::Sudo),
    ("/etc/cron.d", ArtifactKind::Cron),
    ("/etc/cron.hourly", ArtifactKind::Cron),
    ("/etc/cron.daily", ArtifactKind::Cron),
    ("/etc/cron.weekly", ArtifactKind::Cron),
    ("/etc/cron.monthly", ArtifactKind::Cron),
    ("/var/spool/cron/crontabs", ArtifactKind::Cron),
    ("/var/spool/cron", ArtifactKind::Cron),
    ("/etc/systemd/system", ArtifactKind::Systemd),
    ("/etc/ssh/sshd_config.d", ArtifactKind::Ssh),
    ("/etc/profile.d", ArtifactKind::Shell),
    ("/etc/update-motd.d", ArtifactKind::Shell),
];

/// The log root, and the subdirectories under it whose files are logs too.
pub const LOG_DIR: &str = "/var/log";
pub const LOG_SUBDIRS: &[&str] = &["nginx", "apache2", "httpd", "audit", "apt"];

/// The text logs any of which makes a journald export redundant: when none of
/// these came down, the host logs only to the binary journal and an export is
/// the only way to get its events.
pub const TEXT_SYSLOG_NAMES: &[&str] = &["auth.log", "secure", "syslog", "messages"];

/// Per-account files, relative to the account's home directory.
pub const USER_FILES: &[(&str, ArtifactKind)] = &[
    (".ssh/authorized_keys", ArtifactKind::Ssh),
    (".ssh/authorized_keys2", ArtifactKind::Ssh),
    (".ssh/known_hosts", ArtifactKind::Ssh),
    (".ssh/config", ArtifactKind::Ssh),
    (".bashrc", ArtifactKind::Shell),
    (".bash_profile", ArtifactKind::Shell),
    (".profile", ArtifactKind::Shell),
    (".bash_logout", ArtifactKind::Shell),
    (".zshrc", ArtifactKind::Shell),
    (".bash_history", ArtifactKind::Shell),
    (".zsh_history", ArtifactKind::Shell),
];

/// Per-account directories, relative to the home, whose files are all taken.
pub const USER_DIRS: &[(&str, ArtifactKind)] = &[(".config/systemd/user", ArtifactKind::Systemd)];

/// The folder under the host's case directory that holds command captures.
pub const COMMANDS_DIR: &str = "_commands";
/// The folder under the host's case directory that holds the journald export.
pub const JOURNAL_DIR: &str = "journal";
/// The journald export file name — recognised as a log by the analyser.
pub const JOURNAL_FILE: &str = "journal.log";
/// The manifest written into the host's case directory.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Whether a name under `/var/log` is a text log worth copying. Deliberately a
/// superset of what the analyser parses: unparsed logs are still evidence.
pub fn looks_like_log_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_binary_log_name(&lower) {
        return false;
    }
    let base = lower.strip_suffix(".gz").unwrap_or(&lower);
    // Databases, archives and offset/state files that sometimes sit in a log
    // directory are not text logs.
    const NOT_LOG_EXT: &[&str] = &[
        "db", "sqlite", "sqlite3", "gz", "xz", "bz2", "zst", "zip", "tar", "offset", "state",
        "pid", "lock", "socket",
    ];
    if let Some((_, ext)) = base.rsplit_once('.') {
        if NOT_LOG_EXT.contains(&ext) {
            return false;
        }
    }
    const NAMES: &[&str] = &[
        "auth", "secure", "syslog", "messages", "kern", "cron", "mail", "daemon", "user", "dpkg",
        "fail2ban", "ufw", "audit", "yum", "dnf", "dmesg", "boot", "history", "access", "error",
    ];
    // `auth.log`, `secure`, `syslog.1`, `messages-20261019` ...
    let stem = base.split(['.', '-']).next().unwrap_or(base);
    if NAMES.contains(&stem) {
        return true;
    }
    if base.ends_with(".log") {
        return true;
    }
    // `foo.log.1` (rotated).
    if let Some((stem, suffix)) = base.rsplit_once('.') {
        if !suffix.is_empty()
            && suffix.chars().all(|c| c.is_ascii_digit())
            && stem.ends_with(".log")
        {
            return true;
        }
    }
    false
}

/// Binary login records and the journal itself: not copied as text (the
/// read-only `last`/`lastb` commands render the login records instead).
pub fn is_binary_log_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let base = lower.strip_suffix(".gz").unwrap_or(&lower);
    let stem = base.split(['.', '-']).next().unwrap_or(base);
    matches!(stem, "wtmp" | "btmp" | "lastlog" | "faillog" | "tallylog")
        || base.ends_with(".journal")
        || base.ends_with(".journal~")
}

/// Windows reserved device names; a file so named cannot be created on an
/// engine running on Windows, so the local copy gets a suffix.
const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// One path component as it may be written under the case directory on any
/// OS. `None` for `.`/`..`/empty, which must never be mapped (a hostile server
/// could otherwise steer the copy outside the case folder).
pub fn sanitize_component(component: &str) -> Option<String> {
    if component.is_empty() || component == "." || component == ".." {
        return None;
    }
    let mut out: String = component
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let stem = out.split('.').next().unwrap_or("").to_ascii_lowercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        out.push('_');
    }
    // Trailing dots/spaces are dropped by Windows; make them visible instead.
    if out.ends_with('.') || out.ends_with(' ') {
        out.push('_');
    }
    Some(out)
}

/// Maps an absolute remote path onto a `/`-separated relative path under the
/// host's case directory (`/var/log/auth.log` → `var/log/auth.log`). `None`
/// when any component is unsafe.
pub fn local_rel_path(remote_path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for comp in remote_path.split('/') {
        if comp.is_empty() {
            continue; // leading `/` or a doubled slash
        }
        parts.push(sanitize_component(comp)?);
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

/// A directory name for the host under the case directory. The first path
/// segment of every collected file is this name, which is how the analyser
/// attributes events to the host. Only `[A-Za-z0-9._-]` survive; a name that
/// comes out empty falls back to the address the operator typed.
pub fn sanitize_host_dir(hostname: &str, fallback: &str) -> String {
    fn clean(s: &str) -> String {
        let cleaned: String = s
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(64)
            .collect();
        cleaned.trim_start_matches('.').to_string()
    }
    let name = clean(hostname);
    if !name.is_empty() && name != "localhost" && name != "localhost.localdomain" {
        return name;
    }
    let fb = clean(fallback);
    if fb.is_empty() {
        "host".to_string()
    } else {
        fb
    }
}

/// An account whose home directory is worth visiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserHome {
    pub name: String,
    pub uid: u32,
    pub home: String,
    pub shell: String,
}

/// Picks the interactive accounts out of `/etc/passwd`: root and every regular
/// user (UID ≥ 1000) with a real login shell and a real home. Service accounts
/// with `nologin`/`false` shells have no history or keys worth taking.
pub fn parse_passwd_homes(passwd: &str, max_users: usize) -> Vec<UserHome> {
    let mut out: Vec<UserHome> = Vec::new();
    for line in passwd.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        let home = f[5].trim();
        let shell = f[6].trim();
        if uid != 0 && (uid < 1000 || uid == 65534) {
            continue;
        }
        let shell_name = shell.rsplit('/').next().unwrap_or(shell);
        if matches!(
            shell_name,
            "nologin" | "false" | "sync" | "halt" | "shutdown" | ""
        ) {
            continue;
        }
        if !home.starts_with('/') || home == "/" || home == "/nonexistent" || home == "/dev/null" {
            continue;
        }
        if out.iter().any(|u| u.home == home) {
            continue;
        }
        out.push(UserHome {
            name: f[0].to_string(),
            uid,
            home: home.to_string(),
            shell: shell.to_string(),
        });
        if out.len() >= max_users {
            break;
        }
    }
    out
}

/// `PRETTY_NAME` from an `os-release` file, unquoted.
pub fn os_pretty_name(os_release: &str) -> Option<String> {
    os_release
        .lines()
        .find_map(|l| l.trim().strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// Why a path was not copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SkipReason {
    /// Exists, but the login account may not read it (needs root/adm).
    NoAccess,
    /// A device, socket, FIFO or directory where a file was expected.
    NotAFile,
    /// A binary login record or journal file; rendered by a command instead.
    Binary,
    /// Larger than the per-file cap.
    TooLarge,
    /// The total or file-count cap was reached.
    Limit,
    /// The name could not be mapped onto a safe local path.
    BadName,
    /// Any other transport or server error while reading it.
    Error,
}

/// A path that exists on the host but was not copied, and why.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedPath {
    pub remote_path: String,
    pub reason: SkipReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A symlink seen in a collected directory (never followed): its target is the
/// fact — for systemd `*.wants` entries it is the enabled unit.
#[derive(Debug, Clone, Serialize)]
pub struct SymlinkRecord {
    pub path: String,
    pub target: String,
}

/// One file copied from the host.
#[derive(Debug, Clone, Serialize)]
pub struct CollectedFile {
    pub remote_path: String,
    /// `/`-separated path under the host's case directory.
    pub local_path: String,
    pub kind: ArtifactKind,
    pub bytes: u64,
    /// SHA-256 of the bytes written locally, computed while copying.
    pub sha256: String,
    /// The file's modification time on the host (UTC, RFC 3339), preserved on
    /// the local copy so year-less syslog lines get the right year.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<String>,
    /// True when the copy stopped at the per-file cap (the file grew, or was
    /// larger than its reported size).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// The captured output of one read-only command.
#[derive(Debug, Clone, Serialize)]
pub struct CommandCapture {
    pub name: String,
    pub command: String,
    pub local_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<u32>,
}

/// Where the host's system events came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JournalMode {
    /// Text logs (`auth.log`, `syslog`, ...) were copied; no export needed.
    TextLogs,
    /// No text logs were readable, so the journald export was taken.
    JournalExport,
    /// Neither text logs nor a journal export could be read.
    #[default]
    Unavailable,
}

/// Everything the collection did, for the case record and the UI. Honest by
/// construction: every candidate path ends up in exactly one of `files`,
/// `absent`, `skipped` or `symlinks`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CollectionManifest {
    pub version: u32,
    /// The address the operator typed.
    pub host: String,
    pub port: u16,
    /// The login used on the host. Never the secret.
    pub username: String,
    /// `hostname -f` as the host reported it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The folder name under the case directory (sanitised hostname).
    pub host_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    pub platform: String,
    /// Engine clock (UTC, RFC 3339) when the collection started.
    pub collected_at: String,
    /// Host clock (UTC, RFC 3339) as `date -u` reported it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_time_utc: Option<String>,
    /// Host clock minus engine clock, in seconds. Positive: the host runs
    /// ahead. The analyst needs this to line up host times with other sources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_skew_seconds: Option<i64>,
    /// Accounts whose homes were visited.
    pub users: Vec<String>,
    pub files: Vec<CollectedFile>,
    /// Candidate paths that do not exist on this host.
    pub absent: Vec<String>,
    pub skipped: Vec<SkippedPath>,
    pub symlinks: Vec<SymlinkRecord>,
    pub commands: Vec<CommandCapture>,
    pub journal_mode: JournalMode,
    pub total_bytes: u64,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_hit: Option<String>,
    /// Plain-language notes for the analyst (what was not possible and why).
    pub notes: Vec<String>,
}

impl CollectionManifest {
    pub const VERSION: u32 = 1;

    /// Paths that exist but the login could not read: what a root/adm login
    /// would add.
    pub fn needs_privilege(&self) -> Vec<&str> {
        self.skipped
            .iter()
            .filter(|s| s.reason == SkipReason::NoAccess)
            .map(|s| s.remote_path.as_str())
            .collect()
    }

    /// Whether any text system log came down (see [`TEXT_SYSLOG_NAMES`]).
    pub fn has_text_syslog(&self) -> bool {
        self.files.iter().any(|f| {
            f.kind == ArtifactKind::Log && {
                let name = f.remote_path.rsplit('/').next().unwrap_or("");
                let stem = name.split(['.', '-']).next().unwrap_or(name);
                TEXT_SYSLOG_NAMES
                    .iter()
                    .any(|t| name == *t || stem == t.split('.').next().unwrap_or(t))
            }
        })
    }

    /// Files by kind, for a one-line summary.
    pub fn count_by_kind(&self) -> Vec<(ArtifactKind, usize)> {
        let kinds = [
            ArtifactKind::Log,
            ArtifactKind::Account,
            ArtifactKind::Sudo,
            ArtifactKind::Cron,
            ArtifactKind::Systemd,
            ArtifactKind::Ssh,
            ArtifactKind::Shell,
            ArtifactKind::System,
        ];
        kinds
            .iter()
            .map(|k| (*k, self.files.iter().filter(|f| f.kind == *k).count()))
            .filter(|(_, n)| *n > 0)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_names_are_recognised_and_binaries_are_not() {
        for ok in [
            "auth.log",
            "auth.log.1",
            "auth.log.2.gz",
            "secure",
            "secure-20261019",
            "syslog",
            "syslog.7.gz",
            "messages",
            "kern.log",
            "cron",
            "dpkg.log",
            "history.log.3.gz",
            "fail2ban.log",
            "ufw.log",
            "audit.log",
            "access.log",
            "error.log.1",
            "my-app.log",
        ] {
            assert!(looks_like_log_name(ok), "{ok} should be a log");
        }
        for no in [
            "wtmp",
            "btmp",
            "btmp.1",
            "lastlog",
            "faillog",
            "system@0005.journal",
            "user-1000.journal~",
            "README",
            "alternatives",
            "dmesg.db",
        ] {
            assert!(
                !looks_like_log_name(no),
                "{no} should not be copied as a log"
            );
        }
        assert!(is_binary_log_name("wtmp.1"));
        assert!(!is_binary_log_name("auth.log"));
    }

    #[test]
    fn remote_paths_map_under_the_host_dir_and_never_escape() {
        assert_eq!(
            local_rel_path("/var/log/auth.log").as_deref(),
            Some("var/log/auth.log")
        );
        assert_eq!(
            local_rel_path("//etc//cron.d/job").as_deref(),
            Some("etc/cron.d/job")
        );
        assert_eq!(local_rel_path("/home/x/../../etc/shadow"), None);
        assert_eq!(local_rel_path("/"), None);
        assert_eq!(local_rel_path("/etc/./passwd"), None);
        // Characters a Windows engine cannot store are replaced, never dropped.
        assert_eq!(
            local_rel_path("/var/log/odd:name|x").as_deref(),
            Some("var/log/odd_name_x")
        );
        assert_eq!(sanitize_component("aux").as_deref(), Some("aux_"));
        assert_eq!(sanitize_component("nul.txt").as_deref(), Some("nul.txt_"));
        assert_eq!(sanitize_component("trail.").as_deref(), Some("trail._"));
        assert_eq!(sanitize_component("evil\u{7}"), Some("evil_".to_string()));
        assert_eq!(sanitize_component(".."), None);
        assert_eq!(sanitize_component(""), None);
    }

    #[test]
    fn host_dir_is_a_safe_folder_name() {
        assert_eq!(
            sanitize_host_dir("web01.example.com\n", "1.2.3.4"),
            "web01.example.com"
        );
        assert_eq!(sanitize_host_dir("<img src=x>", "192.168.1.10"), "imgsrcx");
        assert_eq!(sanitize_host_dir("../../x", "10.0.0.1"), "x");
        assert_eq!(sanitize_host_dir("", "10.0.0.1"), "10.0.0.1");
        assert_eq!(sanitize_host_dir("localhost", "db01.local"), "db01.local");
        assert_eq!(sanitize_host_dir("", "   "), "host");
        let long = "a".repeat(100);
        assert_eq!(sanitize_host_dir(&long, "h").len(), 64);
    }

    #[test]
    fn passwd_yields_root_and_interactive_users_only() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
                      ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n\
                      deploy:x:1001:1001::/home/deploy:/bin/zsh\n\
                      svc:x:1002:1002::/home/svc:/usr/sbin/nologin\n\
                      broken:x:notanumber:1:/home/b:/bin/sh\n\
                      dup:x:1003:1003::/home/deploy:/bin/sh\n";
        let users = parse_passwd_homes(passwd, 10);
        let names: Vec<&str> = users.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["root", "ubuntu", "deploy"]);
        assert_eq!(users[0].home, "/root");
        assert_eq!(users[2].shell, "/bin/zsh");
        assert_eq!(parse_passwd_homes(passwd, 2).len(), 2);
    }

    #[test]
    fn os_pretty_name_is_unquoted() {
        assert_eq!(
            os_pretty_name("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nID=ubuntu\n")
                .as_deref(),
            Some("Ubuntu 22.04.4 LTS")
        );
        assert_eq!(os_pretty_name("ID=alpine\n"), None);
    }

    #[test]
    fn manifest_reports_privilege_gaps_and_text_syslog_presence() {
        let mut m = CollectionManifest {
            version: CollectionManifest::VERSION,
            ..Default::default()
        };
        assert!(!m.has_text_syslog());
        m.skipped.push(SkippedPath {
            remote_path: "/etc/shadow".into(),
            reason: SkipReason::NoAccess,
            detail: None,
        });
        m.skipped.push(SkippedPath {
            remote_path: "/var/log/wtmp".into(),
            reason: SkipReason::Binary,
            detail: None,
        });
        assert_eq!(m.needs_privilege(), vec!["/etc/shadow"]);
        m.files.push(CollectedFile {
            remote_path: "/var/log/nginx/access.log".into(),
            local_path: "var/log/nginx/access.log".into(),
            kind: ArtifactKind::Log,
            bytes: 10,
            sha256: "00".into(),
            mtime: None,
            truncated: false,
        });
        assert!(!m.has_text_syslog(), "a web log is not a system log");
        m.files.push(CollectedFile {
            remote_path: "/var/log/auth.log.1".into(),
            local_path: "var/log/auth.log.1".into(),
            kind: ArtifactKind::Log,
            bytes: 10,
            sha256: "00".into(),
            mtime: None,
            truncated: false,
        });
        assert!(m.has_text_syslog());
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["skipped"][0]["reason"], "NO_ACCESS");
        assert_eq!(json["files"][0]["kind"], "log");
        assert_eq!(json["journal_mode"], "unavailable");
        assert_eq!(m.count_by_kind(), vec![(ArtifactKind::Log, 2)]);
    }
}
