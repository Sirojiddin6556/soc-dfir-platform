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

    #[test]
    fn every_command_is_read_only() {
        // A defence-in-depth check: no command issued by the scanner may
        // contain a verb that changes the target. If someone adds a mutating
        // command later, this fails loudly.
        // Mutating *commands*, matched as command-shaped tokens (not bare
        // substrings — "/lib/apk/db/installed" is a read path, not an install).
        let mutating = [
            "rm ",
            "rm -",
            "mv ",
            "cp ",
            "apt install",
            "apt-get install",
            "yum install",
            "dnf install",
            "apk add",
            "apk del",
            "dpkg -i",
            "rpm -i",
            "rpm -U",
            "rpm -e",
            "pip install",
            "chmod ",
            "chown ",
            ">>",
            "| tee",
            "tee ",
            "systemctl ",
            "service ",
            "kill ",
            "reboot",
            "shutdown",
            "useradd",
            "passwd ",
            "truncate",
        ];
        for cmd in [
            ReadCommand::OsRelease,
            ReadCommand::KernelRelease,
            ReadCommand::Architecture,
            ReadCommand::DpkgStatus,
            ReadCommand::RpmQuery,
            ReadCommand::ApkInstalled,
        ] {
            let text = cmd.remote_command();
            for bad in mutating {
                assert!(
                    !text.contains(bad),
                    "command {cmd:?} = {text:?} contains mutating token {bad:?}"
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
