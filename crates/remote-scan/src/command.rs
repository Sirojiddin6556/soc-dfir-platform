//! The read-only command surface.
//!
//! The scanner can issue only the fixed commands in [`ReadCommand`]. There is
//! no variant that takes a caller-supplied string, so the scanner cannot run
//! anything that writes to, installs on, or otherwise changes the target: it
//! can only read. Every command is spelled out here and reviewed once.

use std::collections::HashMap;
use vulnerability_engine::package_scan::InstalledPackage;

use crate::types::RemoteError;

/// A single read-only command the collector may run on the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadCommand {
    /// Distribution identity.
    OsRelease,
    /// Kernel release (`uname -r`).
    KernelRelease,
    /// Machine architecture (`uname -m`).
    Architecture,
    /// Debian/Ubuntu installed-package database.
    DpkgStatus,
    /// rpm installed packages, one tab-separated line each.
    RpmQuery,
    /// apk installed-package database.
    ApkInstalled,
    /// The effective sshd configuration (main file plus any drop-ins).
    SshdConfig,
    /// `sshd -T` — the *effective* sshd configuration as the daemon itself
    /// resolves it (every directive, precedence already applied). Read-only;
    /// usually only available to root, so it is best-effort and the file-based
    /// [`ReadCommand::SshdConfig`] is the fallback.
    SshdEffective,
    /// System-wide password-ageing and hashing defaults.
    LoginDefs,
    /// The local account database (names, UIDs, shells — no hashes).
    Passwd,
    /// Mode, owner and group of the sensitive system files, from `stat`
    /// metadata only (never their contents).
    FileModes,
    /// Currently mounted filesystems and their options (`/proc/mounts`), to
    /// audit hardening options such as nodev/nosuid/noexec on `/tmp`.
    Mounts,
    /// A fixed set of kernel hardening parameters, read straight from
    /// `/proc/sys` (never via the `sysctl` binary), each as `path:value`.
    Sysctl,
    /// The PAM password-quality policy (`pwquality.conf` and its drop-ins).
    PwQuality,
    /// The PAM account-lockout policy (`faillock.conf`).
    Faillock,
    /// Whether Debian/Ubuntu unattended security upgrades are enabled.
    AutoUpgrades,
    /// Whether AppArmor is enabled in the kernel (`/sys`).
    Apparmor,
}

impl ReadCommand {
    /// The exact shell command sent to the host. Each is a read — `cat`,
    /// `uname`, or an `rpm -qa` query — and contains no interpolated input, so
    /// it cannot be turned into a mutating command. `2>/dev/null` keeps a
    /// missing file from polluting stdout; a `|| true`-free form means a real
    /// failure still surfaces as a non-zero exit we can report.
    pub fn remote_command(&self) -> String {
        match self {
            ReadCommand::OsRelease => {
                "cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null".to_string()
            }
            ReadCommand::KernelRelease => "uname -r".to_string(),
            ReadCommand::Architecture => "uname -m".to_string(),
            ReadCommand::DpkgStatus => "cat /var/lib/dpkg/status 2>/dev/null".to_string(),
            // The query format is the same static string the local collector
            // feeds rpm; single-quoted so the shell passes the `\t`/`\n`
            // through to rpm unchanged.
            ReadCommand::RpmQuery => format!(
                "rpm -qa --queryformat '{}'",
                platform_linux::software::RPM_QUERY_FORMAT
            ),
            ReadCommand::ApkInstalled => "cat /lib/apk/db/installed 2>/dev/null".to_string(),
            // The sshd config plus any drop-in files it includes. Every value
            // seen is collected; when a keyword is set only once we can judge it
            // safely, and a conflict across files is reported for review rather
            // than guessed. The loop runs only `cat`, so it stays read-only.
            ReadCommand::SshdConfig => "for f in /etc/ssh/sshd_config \
                 /etc/ssh/sshd_config.d/*.conf; \
                 do cat \"$f\" 2>/dev/null; done"
                .to_string(),
            // `sshd -T` prints the effective configuration the daemon would
            // actually use (precedence across the main file and every drop-in
            // already applied). It only validates and dumps config — it starts
            // no listener and changes nothing — so it is read-only. It usually
            // needs root (to read host keys); when it cannot run, stdout is
            // empty and the audit falls back to the file-based config. The
            // common absolute path is tried first for non-login shells.
            ReadCommand::SshdEffective => {
                "/usr/sbin/sshd -T 2>/dev/null || sshd -T 2>/dev/null".to_string()
            }
            ReadCommand::LoginDefs => "cat /etc/login.defs 2>/dev/null".to_string(),
            // Account names, UIDs, shells and the password *field* (the `x`
            // placeholder) — never a hash; hashes live in shadow, which a
            // read-only unprivileged session cannot and must not read.
            ReadCommand::Passwd => "cat /etc/passwd 2>/dev/null".to_string(),
            // Metadata only: name, octal mode, owner and group. `stat` on a file
            // you cannot open still reports its mode, so this audits shadow's
            // permissions without reading shadow.
            ReadCommand::FileModes => "stat -c '%n %a %U %G' \
                 /etc/passwd /etc/shadow /etc/group /etc/gshadow \
                 /etc/ssh/sshd_config 2>/dev/null"
                .to_string(),
            // The live mount table. Only read.
            ReadCommand::Mounts => "cat /proc/mounts 2>/dev/null".to_string(),
            // Kernel hardening parameters read directly as files under
            // /proc/sys — never through the `sysctl` binary — so this stays a
            // pure read. `grep -H ''` prints each file as `path:value`.
            ReadCommand::Sysctl => "grep -H '' \
                 /proc/sys/net/ipv4/ip_forward \
                 /proc/sys/net/ipv4/conf/all/rp_filter \
                 /proc/sys/net/ipv4/tcp_syncookies \
                 /proc/sys/kernel/randomize_va_space \
                 /proc/sys/net/ipv4/conf/all/accept_redirects \
                 /proc/sys/net/ipv4/conf/all/send_redirects \
                 /proc/sys/net/ipv4/conf/all/accept_source_route \
                 2>/dev/null"
                .to_string(),
            ReadCommand::PwQuality => "cat /etc/security/pwquality.conf \
                 /etc/security/pwquality.conf.d/*.conf 2>/dev/null"
                .to_string(),
            ReadCommand::Faillock => "cat /etc/security/faillock.conf 2>/dev/null".to_string(),
            ReadCommand::AutoUpgrades => {
                "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null".to_string()
            }
            ReadCommand::Apparmor => {
                "cat /sys/module/apparmor/parameters/enabled 2>/dev/null".to_string()
            }
        }
    }
}

/// The captured result of one command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    /// Process exit status, when the transport reports one.
    pub exit_status: Option<u32>,
}

impl CommandOutput {
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            exit_status: Some(0),
        }
    }
}

/// Runs read-only commands on the target. The SSH transport implements this;
/// tests implement it with captured output so the whole matching path runs
/// with no network.
pub trait CommandRunner {
    fn run(&mut self, command: ReadCommand) -> Result<CommandOutput, RemoteError>;
}

/// A [`CommandRunner`] backed by a fixed map of outputs — used by the SSH
/// transport (which gathers every command's output up front, then replays it
/// through the sync pipeline) and by tests.
#[derive(Debug, Default, Clone)]
pub struct MapRunner {
    outputs: HashMap<ReadCommand, CommandOutput>,
}

impl MapRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, command: ReadCommand, stdout: impl Into<String>) -> Self {
        self.outputs.insert(command, CommandOutput::ok(stdout));
        self
    }

    pub fn insert(&mut self, command: ReadCommand, output: CommandOutput) {
        self.outputs.insert(command, output);
    }
}

impl CommandRunner for MapRunner {
    fn run(&mut self, command: ReadCommand) -> Result<CommandOutput, RemoteError> {
        self.outputs
            .get(&command)
            .cloned()
            .ok_or_else(|| RemoteError::Command(format!("нет вывода для команды {command:?}")))
    }
}

/// Converts a [`host_snapshot::SoftwareObservation`] (what the shared Linux
/// parsers emit) into the matcher's [`InstalledPackage`], keeping only the
/// package sources the matcher understands. This is the exact mapping the
/// local scan uses, so remote and local feed the matcher identically.
pub(crate) fn observation_to_package(
    obs: &host_snapshot::SoftwareObservation,
) -> Option<InstalledPackage> {
    if !matches!(obs.source.as_str(), "dpkg" | "rpm" | "apk") {
        return None;
    }
    Some(InstalledPackage {
        name: obs.product.clone(),
        version: obs.version.clone(),
        source_name: obs.source_package.clone(),
        source_version: obs.source_version.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command the scanner can issue, for the read-only guards to sweep.
    const ALL_COMMANDS: [ReadCommand; 17] = [
        ReadCommand::OsRelease,
        ReadCommand::KernelRelease,
        ReadCommand::Architecture,
        ReadCommand::DpkgStatus,
        ReadCommand::RpmQuery,
        ReadCommand::ApkInstalled,
        ReadCommand::SshdConfig,
        ReadCommand::SshdEffective,
        ReadCommand::LoginDefs,
        ReadCommand::Passwd,
        ReadCommand::FileModes,
        ReadCommand::Mounts,
        ReadCommand::Sysctl,
        ReadCommand::PwQuality,
        ReadCommand::Faillock,
        ReadCommand::AutoUpgrades,
        ReadCommand::Apparmor,
    ];

    #[test]
    fn no_command_contains_a_mutating_subcommand() {
        // Defence in depth: no command may contain a package-manager or
        // redirection form that changes the target. These are matched as
        // substrings because they are unambiguous phrases that never occur in a
        // read path (`rpm -qa`, a query, is deliberately allowed).
        let mutating_phrases = [
            "apt install",
            "apt-get install",
            "yum install",
            "dnf install",
            "apk add",
            "apk del",
            "dpkg -i",
            "dpkg --install",
            "rpm -i",
            "rpm -U",
            "rpm -e",
            "pip install",
            ">>",
            "| tee",
        ];
        for cmd in ALL_COMMANDS {
            let text = cmd.remote_command();
            for bad in mutating_phrases {
                assert!(
                    !text.contains(bad),
                    "command {cmd:?} = {text:?} contains mutating phrase {bad:?}"
                );
            }
        }
    }

    #[test]
    fn no_command_invokes_a_mutating_binary() {
        // A word-level guard for pure-mutator binaries: the read path
        // `/etc/passwd` must never be mistaken for the `passwd` *command*, so we
        // split each command into shell words and require that no word *equals*
        // a mutating binary name. `/etc/passwd` is the word "/etc/passwd", which
        // is not "passwd".
        let mutating_binaries = [
            "rm",
            "rmdir",
            "mv",
            "cp",
            "dd",
            "chmod",
            "chown",
            "chgrp",
            "tee",
            "truncate",
            "ln",
            "mkfs",
            "kill",
            "pkill",
            "reboot",
            "shutdown",
            "poweroff",
            "halt",
            "init",
            "sed",
            "useradd",
            "userdel",
            "usermod",
            "groupadd",
            "groupdel",
            "gpasswd",
            "passwd",
            "chpasswd",
            "systemctl",
            "service",
            "mount",
            "umount",
            "iptables",
            "sysctl",
        ];
        for cmd in ALL_COMMANDS {
            let text = cmd.remote_command();
            // Treat shell metacharacters as word separators so `a;rm` splits.
            let normalized: String = text
                .chars()
                .map(|c| {
                    if matches!(c, ';' | '|' | '&' | '(' | ')' | '`') {
                        ' '
                    } else {
                        c
                    }
                })
                .collect();
            for word in normalized.split_whitespace() {
                // Strip surrounding quotes so `"rm"` would still be caught.
                let word = word.trim_matches(|c| c == '"' || c == '\'');
                assert!(
                    !mutating_binaries.contains(&word),
                    "command {cmd:?} = {text:?} invokes mutating binary {word:?}"
                );
            }
        }
    }

    #[test]
    fn rpm_query_uses_the_shared_format() {
        let text = ReadCommand::RpmQuery.remote_command();
        assert!(text.starts_with("rpm -qa --queryformat '"));
        assert!(text.contains("%{NAME}"));
        assert!(text.contains("%{SOURCERPM}"));
    }
}
