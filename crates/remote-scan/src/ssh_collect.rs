//! Forensic artifact collection over SSH (feature `ssh`): the live-session
//! driver for the rules in [`crate::collect`].
//!
//! One confirmed, credentialed session does everything: a few fixed read-only
//! commands ([`ReadCommand`]) for the host's identity, clock and volatile state,
//! then an SFTP channel that copies the persistence points, account files and
//! logs the rules name. Every byte is hashed (SHA-256) as it is written, the
//! host's modification times are preserved on the copies, and the manifest
//! records every candidate path as copied, absent, skipped (with the reason)
//! or a symlink that was not followed.
//!
//! **Read-only on the target.** The session only runs the fixed commands,
//! lists directories and reads files; it never writes, renames or removes
//! anything on the server, never follows a symlink in a listing, and never
//! escalates (what the login cannot read is reported as needing privilege, not
//! worked around). The credential lives only for the session and is never
//! written to the manifest, a log or the case.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use russh::client::Handle;
use russh::{ChannelMsg, Disconnect};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::StatusCode;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::collect::{
    is_binary_log_name, local_rel_path, looks_like_log_name, os_pretty_name, parse_passwd_homes,
    sanitize_host_dir, ArtifactKind, CollectLimits, CollectedFile, CollectionManifest,
    CommandCapture, JournalMode, SkipReason, SkippedPath, SymlinkRecord, COMMANDS_DIR, JOURNAL_DIR,
    JOURNAL_FILE, LOG_DIR, LOG_SUBDIRS, MANIFEST_FILE, SYSTEM_DIRS, SYSTEM_FILES, USER_DIRS,
    USER_FILES,
};
use crate::command::ReadCommand;
use crate::ssh::{authenticate, open_session, ClientHandler, SshTimeouts};
use crate::types::{Credential, HostKey, HostKeyPolicy, RemoteError, RemoteTarget};

/// The outcome of a collection: the manifest, the host key the server
/// presented, and where the host's files landed.
pub struct CollectResult {
    pub manifest: CollectionManifest,
    pub host_key: HostKey,
    /// `case_dir/<host_dir>`.
    pub host_dir: PathBuf,
}

/// Raw output of one command, bounded.
struct CommandBytes {
    data: Vec<u8>,
    truncated: bool,
    exit_status: Option<u32>,
    /// Set when the command could not be run at all (not merely non-zero).
    error: Option<String>,
}

impl CommandBytes {
    fn empty(error: Option<String>) -> Self {
        Self {
            data: Vec::new(),
            truncated: false,
            exit_status: None,
            error,
        }
    }

    fn first_line(&self) -> String {
        String::from_utf8_lossy(&self.data)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }
}

/// Runs one fixed read-only command, keeping at most `max_bytes` of stdout.
/// When the cap is reached the channel is closed so a runaway command (a huge
/// journal) does not stream for ever.
async fn run_capped(
    handle: &mut Handle<ClientHandler>,
    command: &str,
    timeout: Duration,
    max_bytes: u64,
) -> Result<CommandBytes, RemoteError> {
    let fut = async {
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| RemoteError::Ssh(e.to_string()))?;
        channel
            .exec(true, command.as_bytes())
            .await
            .map_err(|e| RemoteError::Ssh(e.to_string()))?;

        let mut data: Vec<u8> = Vec::new();
        let mut truncated = false;
        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data: ref chunk } => {
                    if truncated {
                        continue;
                    }
                    let room = (max_bytes as usize).saturating_sub(data.len());
                    if chunk.len() <= room {
                        data.extend_from_slice(chunk);
                    } else {
                        data.extend_from_slice(&chunk[..room]);
                        truncated = true;
                        let _ = channel.close().await;
                    }
                }
                // stderr (ExtendedData) is deliberately ignored: a missing
                // file or a permission notice writes there.
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Close if truncated => break,
                _ => {}
            }
        }
        Ok::<_, RemoteError>(CommandBytes {
            data,
            truncated,
            exit_status,
            error: None,
        })
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(RemoteError::Command(format!(
            "истекло время ожидания команды: {command}"
        ))),
    }
}

/// [`run_capped`] that never fails: a command the host lacks must not abort the
/// collection. The failure is kept so the manifest can say so.
async fn soft(
    handle: &mut Handle<ClientHandler>,
    command: ReadCommand,
    timeout: Duration,
    max_bytes: u64,
) -> CommandBytes {
    match run_capped(handle, &command.remote_command(), timeout, max_bytes).await {
        Ok(out) => out,
        Err(e) => CommandBytes::empty(Some(e.to_string())),
    }
}

/// What an SFTP error means for a candidate path.
enum PathProblem {
    Absent,
    NoAccess,
    Other(String),
}

fn classify(e: &SftpError) -> PathProblem {
    match e {
        SftpError::Status(st) => match st.status_code {
            StatusCode::NoSuchFile => PathProblem::Absent,
            StatusCode::PermissionDenied => PathProblem::NoAccess,
            _ => PathProblem::Other(e.to_string()),
        },
        other => PathProblem::Other(other.to_string()),
    }
}

/// Collects the artifacts from `target` into `case_dir/<host>/`, confirming the
/// host key first (`expected_fingerprint` is the base64 SHA-256 the operator
/// confirmed). Fails before touching the disk if the host already has a folder
/// in this case, so one folder is always one collection.
pub async fn collect_artifacts_over_ssh(
    target: &RemoteTarget,
    credential: &Credential,
    expected_fingerprint: &str,
    case_dir: &Path,
    limits: CollectLimits,
    timeouts: SshTimeouts,
) -> Result<CollectResult, RemoteError> {
    let (mut handle, host_key) = open_session(
        target,
        HostKeyPolicy::Expect(expected_fingerprint.to_string()),
        timeouts,
    )
    .await?;
    authenticate(&mut handle, target, credential).await?;

    let small = 64 * 1024;
    // Identity first: a host that does not answer `uname -r` is not Linux.
    let uname = soft(
        &mut handle,
        ReadCommand::KernelRelease,
        timeouts.command,
        small,
    )
    .await;
    let kernel = uname.first_line();
    if kernel.is_empty() {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        return Err(RemoteError::Collect(
            "хост не ответил на uname -r: сбор артефактов пока поддерживается только для Linux"
                .to_string(),
        ));
    }
    let hostname_out = soft(&mut handle, ReadCommand::Hostname, timeouts.command, small).await;
    let hostname = hostname_out.first_line();
    let engine_now = Utc::now();
    let date_out = soft(&mut handle, ReadCommand::DateUtc, timeouts.command, small).await;
    let remote_time = DateTime::parse_from_rfc3339(&date_out.first_line())
        .ok()
        .map(|t| t.with_timezone(&Utc));
    let os_out = soft(&mut handle, ReadCommand::OsRelease, timeouts.command, small).await;
    let os_name = os_pretty_name(&String::from_utf8_lossy(&os_out.data));

    let host_dir_name = sanitize_host_dir(&hostname, &target.host);
    let host_dir = case_dir.join(&host_dir_name);
    if host_dir.exists() {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        return Err(RemoteError::Collect(format!(
            "хост «{host_dir_name}» уже есть в этом деле; создайте новое дело или удалите его папку"
        )));
    }
    std::fs::create_dir_all(&host_dir)
        .map_err(|e| RemoteError::Collect(format!("не удалось создать папку дела: {e}")))?;

    let manifest = CollectionManifest {
        version: CollectionManifest::VERSION,
        host: target.host.clone(),
        port: target.port,
        username: target.username.clone(),
        hostname: (!hostname.is_empty()).then(|| hostname.clone()),
        host_dir: host_dir_name,
        os_name,
        kernel: Some(kernel),
        platform: "linux".to_string(),
        collected_at: engine_now.to_rfc3339_opts(SecondsFormat::Secs, true),
        remote_time_utc: remote_time.map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true)),
        clock_skew_seconds: remote_time.map(|t| (t - engine_now).num_seconds()),
        ..Default::default()
    };

    // The SFTP subsystem rides its own channel; the exec channels stay usable.
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| RemoteError::Ssh(e.to_string()))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| RemoteError::Sftp(format!("подсистема SFTP недоступна на сервере: {e}")))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| RemoteError::Sftp(e.to_string()))?;
    sftp.set_timeout(timeouts.command.as_secs().max(5));

    let mut c = Collector {
        sftp,
        host_dir: host_dir.clone(),
        host_rel: manifest.host_dir.clone(),
        limits,
        manifest,
    };

    // 1. Persistence and account artifacts by exact path and by directory.
    for (path, kind) in SYSTEM_FILES {
        c.fetch_file(path, *kind).await?;
    }
    for (dir, kind) in SYSTEM_DIRS {
        c.fetch_dir(dir, *kind, DirMode::All).await?;
    }

    // 2. Logs.
    c.fetch_dir(LOG_DIR, ArtifactKind::Log, DirMode::Logs)
        .await?;
    for sub in LOG_SUBDIRS {
        c.fetch_dir(
            &format!("{LOG_DIR}/{sub}"),
            ArtifactKind::Log,
            DirMode::Logs,
        )
        .await?;
    }

    // 3. Per-account files, for the accounts /etc/passwd says are interactive.
    let passwd_local = host_dir.join("etc").join("passwd");
    match std::fs::read_to_string(&passwd_local) {
        Ok(text) => {
            let users = parse_passwd_homes(&text, limits.max_users);
            for u in users {
                c.manifest.users.push(u.name.clone());
                let home = u.home.trim_end_matches('/');
                for (rel, kind) in USER_FILES {
                    c.fetch_file(&format!("{home}/{rel}"), *kind).await?;
                }
                for (rel, kind) in USER_DIRS {
                    c.fetch_dir(&format!("{home}/{rel}"), *kind, DirMode::All)
                        .await?;
                }
            }
        }
        Err(_) => c.manifest.notes.push(
            "/etc/passwd не получен — домашние папки пользователей не просматривались".to_string(),
        ),
    }

    // 4. Volatile state and rendered binary records, as command captures.
    c.write_capture("hostname", ReadCommand::Hostname, &hostname_out)?;
    c.write_capture("date-utc", ReadCommand::DateUtc, &date_out)?;
    c.write_capture("uname-r", ReadCommand::KernelRelease, &uname)?;
    c.write_capture("os-release", ReadCommand::OsRelease, &os_out)?;
    let long = timeouts.command * 4;
    for (name, command) in [
        ("last", ReadCommand::LastLogins),
        ("lastb", ReadCommand::BadLogins),
        ("ps", ReadCommand::Processes),
        ("ss", ReadCommand::ListeningSockets),
        ("crontab-l", ReadCommand::UserCrontab),
        ("modules", ReadCommand::KernelModules),
        ("mounts", ReadCommand::Mounts),
        ("sshd-T", ReadCommand::SshdEffective),
    ] {
        let out = soft(&mut handle, command, long, limits.max_command_bytes).await;
        c.write_capture(name, command, &out)?;
    }

    // 5. System events: text logs when the host keeps them, otherwise the
    //    journald export (never both, so no event is counted twice).
    if c.manifest.has_text_syslog() {
        c.manifest.journal_mode = JournalMode::TextLogs;
        c.manifest.notes.push(
            "Текстовые системные журналы получены; экспорт journald не делался, чтобы события не дублировались"
                .to_string(),
        );
    } else {
        let out = soft(
            &mut handle,
            ReadCommand::JournalExport,
            Duration::from_secs(600),
            limits.max_journal_bytes,
        )
        .await;
        if out.data.iter().all(u8::is_ascii_whitespace) {
            c.manifest.journal_mode = JournalMode::Unavailable;
            c.manifest.notes.push(format!(
                "Системные журналы недоступны этому пользователю: ни /var/log/auth.log|syslog, ни journalctl не читаются{}. Нужен root или пользователь группы adm/systemd-journal",
                out.error.as_deref().map(|e| format!(" ({e})")).unwrap_or_default()
            ));
        } else {
            c.write_journal(&out)?;
            c.manifest.journal_mode = JournalMode::JournalExport;
            c.manifest.notes.push(format!(
                "Текстовых системных журналов нет — взят экспорт journald за 30 дней (UTC){}",
                if out.truncated {
                    ", обрезан по размеру"
                } else {
                    ""
                }
            ));
        }
    }

    let _ = c.sftp.close().await;
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;

    let mut manifest = c.manifest;
    manifest.total_bytes = manifest.files.iter().map(|f| f.bytes).sum::<u64>()
        + manifest.commands.iter().map(|f| f.bytes).sum::<u64>();
    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| RemoteError::Collect(format!("манифест не сериализуется: {e}")))?;
    std::fs::write(host_dir.join(MANIFEST_FILE), json)
        .map_err(|e| RemoteError::Collect(format!("не удалось записать манифест: {e}")))?;

    Ok(CollectResult {
        manifest,
        host_key,
        host_dir,
    })
}

/// How a directory listing is filtered.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DirMode {
    /// Every regular file.
    All,
    /// Only names that look like text logs; binary records are noted.
    Logs,
}

struct Collector {
    sftp: SftpSession,
    /// `case_dir/<host>` — where this host's files are written.
    host_dir: PathBuf,
    /// The host folder's name, used to prefix every manifest path so the
    /// recorded path is relative to the case directory (and the analyser
    /// attributes events to this host).
    host_rel: String,
    limits: CollectLimits,
    manifest: CollectionManifest,
}

impl Collector {
    fn skip(&mut self, remote: &str, reason: SkipReason, detail: Option<String>) {
        if self.manifest.skipped.len() < 2_000 {
            self.manifest.skipped.push(SkippedPath {
                remote_path: remote.to_string(),
                reason,
                detail,
            });
        }
    }

    fn absent(&mut self, remote: &str) {
        if self.manifest.absent.len() < 2_000 {
            self.manifest.absent.push(remote.to_string());
        }
    }

    fn local_path(&self, rel: &str) -> PathBuf {
        rel.split('/')
            .filter(|c| !c.is_empty())
            .fold(self.host_dir.clone(), |p, c| p.join(c))
    }

    /// The path recorded in the manifest: relative to the case directory, so
    /// its first segment is the host folder.
    fn manifest_rel(&self, rel: &str) -> String {
        format!("{}/{}", self.host_rel, rel)
    }

    /// Copies one file by exact path (a named file's symlink is followed, since
    /// the list is fixed and bounded). Errors returned are local disk failures;
    /// anything about the remote path is recorded in the manifest instead.
    async fn fetch_file(&mut self, remote: &str, kind: ArtifactKind) -> Result<(), RemoteError> {
        let Some(rel) = local_rel_path(remote) else {
            self.skip(remote, SkipReason::BadName, None);
            return Ok(());
        };
        let meta = match self.sftp.metadata(remote).await {
            Ok(m) => m,
            Err(e) => {
                match classify(&e) {
                    PathProblem::Absent => self.absent(remote),
                    PathProblem::NoAccess => self.skip(remote, SkipReason::NoAccess, None),
                    PathProblem::Other(d) => self.skip(remote, SkipReason::Error, Some(d)),
                }
                return Ok(());
            }
        };
        let ft = meta.file_type();
        if ft.is_dir() || ft.is_other() {
            self.skip(remote, SkipReason::NotAFile, None);
            return Ok(());
        }
        let size = meta.len();
        if size > self.limits.max_file_bytes {
            self.skip(
                remote,
                SkipReason::TooLarge,
                Some(format!("{} МБ", size / (1024 * 1024))),
            );
            return Ok(());
        }
        let total: u64 = self.manifest.files.iter().map(|f| f.bytes).sum();
        if self.manifest.files.len() + 1 > self.limits.max_files
            || total + size > self.limits.max_total_bytes
        {
            if !self.manifest.truncated {
                self.manifest.truncated = true;
                self.manifest.limit_hit = Some(format!(
                    "Достигнут предел сбора ({} файлов или {} МБ): часть файлов не скопирована",
                    self.limits.max_files,
                    self.limits.max_total_bytes / (1024 * 1024)
                ));
            }
            self.skip(remote, SkipReason::Limit, None);
            return Ok(());
        }

        let mut file = match self.sftp.open(remote).await {
            Ok(f) => f,
            Err(e) => {
                match classify(&e) {
                    PathProblem::Absent => self.absent(remote),
                    PathProblem::NoAccess => self.skip(remote, SkipReason::NoAccess, None),
                    PathProblem::Other(d) => self.skip(remote, SkipReason::Error, Some(d)),
                }
                return Ok(());
            }
        };

        let local = self.local_path(&rel);
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RemoteError::Collect(format!("не удалось создать папку: {e}")))?;
        }
        let mut out = tokio::fs::File::create(&local)
            .await
            .map_err(|e| RemoteError::Collect(format!("не удалось создать файл копии: {e}")))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut written: u64 = 0;
        let mut truncated = false;
        loop {
            match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let room = self.limits.max_file_bytes.saturating_sub(written) as usize;
                    let take = n.min(room);
                    hasher.update(&buf[..take]);
                    out.write_all(&buf[..take]).await.map_err(|e| {
                        RemoteError::Collect(format!("не удалось записать копию: {e}"))
                    })?;
                    written += take as u64;
                    if take < n {
                        truncated = true;
                        break;
                    }
                }
                Err(e) => {
                    // A read that fails midway (the file vanished, a permission
                    // boundary inside it): drop the partial copy, record it.
                    drop(out);
                    let _ = std::fs::remove_file(&local);
                    let _ = file.close().await;
                    self.skip(remote, SkipReason::Error, Some(e.to_string()));
                    return Ok(());
                }
            }
        }
        out.flush()
            .await
            .map_err(|e| RemoteError::Collect(format!("не удалось записать копию: {e}")))?;
        drop(out);
        let _ = file.close().await;

        // Preserve the host's modification time on the copy: the analyser
        // takes the year of year-less syslog lines from it.
        let mtime = meta.modified().ok();
        if let Some(t) = mtime {
            if let Ok(fh) = std::fs::OpenOptions::new().write(true).open(&local) {
                let _ = fh.set_modified(t);
            }
        }
        let manifest_local = self.manifest_rel(&rel);
        self.manifest.files.push(CollectedFile {
            remote_path: remote.to_string(),
            local_path: manifest_local,
            kind,
            bytes: written,
            sha256: hex::encode(hasher.finalize()),
            mtime: mtime
                .map(|t| DateTime::<Utc>::from(t).to_rfc3339_opts(SecondsFormat::Secs, true)),
            truncated,
        });
        Ok(())
    }

    /// Copies the regular files of one directory (one level). Symlinks are
    /// recorded with their targets and never followed; subdirectories are
    /// ignored except for systemd's `*.wants`/`*.requires`/`*.d`, which hold
    /// the "enabled" links and drop-in overrides.
    async fn fetch_dir(
        &mut self,
        dir: &str,
        kind: ArtifactKind,
        mode: DirMode,
    ) -> Result<(), RemoteError> {
        let rd = match self.sftp.read_dir(dir).await {
            Ok(rd) => rd,
            Err(e) => {
                match classify(&e) {
                    PathProblem::Absent => self.absent(dir),
                    PathProblem::NoAccess => self.skip(dir, SkipReason::NoAccess, None),
                    PathProblem::Other(d) => self.skip(dir, SkipReason::Error, Some(d)),
                }
                return Ok(());
            }
        };
        let mut entries: Vec<russh_sftp::client::fs::DirEntry> = rd.collect();
        entries.sort_by_key(|e| e.file_name());
        if entries.len() > self.limits.max_dir_entries {
            self.manifest.notes.push(format!(
                "{dir}: {} записей, просмотрены первые {}",
                entries.len(),
                self.limits.max_dir_entries
            ));
            entries.truncate(self.limits.max_dir_entries);
        }
        let base = dir.trim_end_matches('/');
        let mut nested: Vec<String> = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." || name.contains('/') {
                continue;
            }
            let remote = format!("{base}/{name}");
            let ft = entry.file_type();
            if ft.is_symlink() {
                let target = self.sftp.read_link(&remote).await.unwrap_or_default();
                if self.manifest.symlinks.len() < 2_000 {
                    self.manifest.symlinks.push(SymlinkRecord {
                        path: remote,
                        target,
                    });
                }
                continue;
            }
            if ft.is_dir() {
                if kind == ArtifactKind::Systemd
                    && (name.ends_with(".wants")
                        || name.ends_with(".requires")
                        || name.ends_with(".d"))
                {
                    nested.push(remote);
                } else if mode == DirMode::Logs && name == "journal" {
                    self.manifest.notes.push(
                        "/var/log/journal (двоичный журнал systemd) не копируется; события берутся из текстовых журналов или экспорта journalctl"
                            .to_string(),
                    );
                }
                continue;
            }
            if ft.is_other() {
                continue; // devices, sockets, FIFOs
            }
            if mode == DirMode::Logs {
                if is_binary_log_name(&name) {
                    self.skip(
                        &remote,
                        SkipReason::Binary,
                        Some(
                            "двоичные записи входов: см. _commands/last.txt и lastb.txt"
                                .to_string(),
                        ),
                    );
                    continue;
                }
                if !looks_like_log_name(&name) {
                    continue;
                }
            }
            self.fetch_file(&remote, kind).await?;
        }
        for sub in nested {
            self.fetch_shallow(&sub, kind).await?;
        }
        Ok(())
    }

    /// One level of a systemd `*.wants`/`*.d` directory: files are copied,
    /// symlinks recorded, nothing deeper.
    async fn fetch_shallow(&mut self, dir: &str, kind: ArtifactKind) -> Result<(), RemoteError> {
        let rd = match self.sftp.read_dir(dir).await {
            Ok(rd) => rd,
            Err(e) => {
                if let PathProblem::NoAccess = classify(&e) {
                    self.skip(dir, SkipReason::NoAccess, None);
                }
                return Ok(());
            }
        };
        let base = dir.trim_end_matches('/');
        for entry in rd.take(self.limits.max_dir_entries) {
            let name = entry.file_name();
            if name == "." || name == ".." || name.contains('/') {
                continue;
            }
            let remote = format!("{base}/{name}");
            let ft = entry.file_type();
            if ft.is_symlink() {
                let target = self.sftp.read_link(&remote).await.unwrap_or_default();
                if self.manifest.symlinks.len() < 2_000 {
                    self.manifest.symlinks.push(SymlinkRecord {
                        path: remote,
                        target,
                    });
                }
            } else if ft.is_file() {
                self.fetch_file(&remote, kind).await?;
            }
        }
        Ok(())
    }

    /// Writes a command's output under `_commands/<name>.txt` and records it.
    fn write_capture(
        &mut self,
        name: &str,
        command: ReadCommand,
        out: &CommandBytes,
    ) -> Result<(), RemoteError> {
        let rel = format!("{COMMANDS_DIR}/{name}.txt");
        let sha = self.write_bytes(&rel, &out.data)?;
        let manifest_local = self.manifest_rel(&rel);
        self.manifest.commands.push(CommandCapture {
            name: name.to_string(),
            command: command.remote_command(),
            local_path: manifest_local,
            bytes: out.data.len() as u64,
            sha256: sha,
            truncated: out.truncated,
            exit_status: out.exit_status,
        });
        if let Some(e) = &out.error {
            self.manifest
                .notes
                .push(format!("Команда {name} не выполнена: {e}"));
        }
        Ok(())
    }

    /// Writes the journald export where the analyser reads it as a log.
    fn write_journal(&mut self, out: &CommandBytes) -> Result<(), RemoteError> {
        let rel = format!("{JOURNAL_DIR}/{JOURNAL_FILE}");
        let sha = self.write_bytes(&rel, &out.data)?;
        let manifest_local = self.manifest_rel(&rel);
        self.manifest.commands.push(CommandCapture {
            name: "journalctl".to_string(),
            command: ReadCommand::JournalExport.remote_command(),
            local_path: manifest_local,
            bytes: out.data.len() as u64,
            sha256: sha,
            truncated: out.truncated,
            exit_status: out.exit_status,
        });
        Ok(())
    }

    fn write_bytes(&self, rel: &str, data: &[u8]) -> Result<String, RemoteError> {
        let local = self.local_path(rel);
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RemoteError::Collect(format!("не удалось создать папку: {e}")))?;
        }
        std::fs::write(&local, data)
            .map_err(|e| RemoteError::Collect(format!("не удалось записать {rel}: {e}")))?;
        Ok(hex::encode(Sha256::digest(data)))
    }
}
