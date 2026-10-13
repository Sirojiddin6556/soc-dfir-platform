//! The SSH transport (feature `ssh`).
//!
//! Trust on first use is enforced structurally: in [`HostKeyPolicy::Discover`]
//! the client fetches the server's host key and refuses to continue, so **no
//! credential is ever offered to an unconfirmed host**. Only once the operator
//! has confirmed the fingerprint does a scan run with
//! [`HostKeyPolicy::Expect`], which authenticates only if the server presents
//! that exact key. Every command run is a [`ReadCommand`], so the session can
//! only read.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::path::Path;

use async_trait::async_trait;
use russh::client::{self, Handle, Handler};
use russh::keys::key::{self, KeyPair};
use russh::{ChannelMsg, Disconnect};
use russh_sftp::client::SftpSession;

use crate::command::{CommandOutput, MapRunner, ReadCommand};
use crate::fetch::{is_binary_path, is_excluded_dir, FetchLimits, FetchSummary};
use crate::scan::scan_remote;
use crate::types::{
    Credential, HostKey, HostKeyPolicy, RemoteError, RemoteScanReport, RemoteScanStatus,
    RemoteTarget,
};
use vulnerability_engine::VulnDbRepository;

/// Network timeouts. Kept short so a dead host or a stalled command cannot hang
/// the scan.
#[derive(Debug, Clone, Copy)]
pub struct SshTimeouts {
    pub connect: Duration,
    pub command: Duration,
}

impl Default for SshTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(15),
            command: Duration::from_secs(30),
        }
    }
}

#[derive(Default)]
struct HandshakeState {
    seen_key: Option<HostKey>,
    mismatch: Option<(String, String)>,
}

struct ClientHandler {
    policy: HostKeyPolicy,
    state: Arc<Mutex<HandshakeState>>,
}

#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let hk = HostKey {
            algorithm: server_public_key.name().to_string(),
            sha256: server_public_key.fingerprint(),
        };
        let mut st = self.state.lock().unwrap();
        st.seen_key = Some(hk.clone());
        match &self.policy {
            // Discovery: we only wanted the key. Refusing it aborts the
            // handshake before authentication, so no secret is sent.
            HostKeyPolicy::Discover => Ok(false),
            HostKeyPolicy::Expect(expected) => {
                if &hk.sha256 == expected {
                    Ok(true)
                } else {
                    st.mismatch = Some((expected.clone(), hk.sha256));
                    Ok(false)
                }
            }
        }
    }
}

async fn open_session(
    target: &RemoteTarget,
    policy: HostKeyPolicy,
    timeouts: SshTimeouts,
) -> Result<(Handle<ClientHandler>, HostKey), RemoteError> {
    let state = Arc::new(Mutex::new(HandshakeState::default()));
    let handler = ClientHandler {
        policy,
        state: state.clone(),
    };
    let config = Arc::new(client::Config::default());

    let connect = client::connect(config, (target.host.as_str(), target.port), handler);
    let result = match tokio::time::timeout(timeouts.connect, connect).await {
        Ok(r) => r,
        Err(_) => {
            return Err(RemoteError::Connect {
                host: target.host.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "истекло время ожидания соединения",
                ),
            })
        }
    };

    // Whatever happened, a captured key or a mismatch is the authoritative
    // reason — read it before mapping the raw error.
    let captured = {
        let st = state.lock().unwrap();
        (st.seen_key.clone(), st.mismatch.clone())
    };
    if let (_, Some((expected, actual))) = &captured {
        return Err(RemoteError::HostKeyMismatch {
            expected: format!("SHA256:{expected}"),
            actual: format!("SHA256:{actual}"),
        });
    }

    match result {
        Ok(handle) => {
            let key = captured
                .0
                .ok_or_else(|| RemoteError::HostKey("сервер не предъявил ключ".to_string()))?;
            Ok((handle, key))
        }
        Err(e) => {
            // In discovery mode a refused key is the expected outcome and we
            // still captured it; surface it rather than the transport error.
            if let Some(key) = captured.0 {
                Err(RemoteError::HostKeyDiscovered(key))
            } else {
                Err(RemoteError::Ssh(e.to_string()))
            }
        }
    }
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    target: &RemoteTarget,
    credential: &Credential,
) -> Result<(), RemoteError> {
    let ok = match credential {
        Credential::Password(password) => handle
            .authenticate_password(&target.username, password)
            .await
            .map_err(|e| RemoteError::Ssh(e.to_string()))?,
        Credential::PrivateKey { pem, passphrase } => {
            let key = russh::keys::decode_secret_key(pem, passphrase.as_deref())
                .map_err(|e| RemoteError::HostKey(format!("закрытый ключ не читается: {e}")))?;
            let _: &KeyPair = &key;
            handle
                .authenticate_publickey(&target.username, Arc::new(key))
                .await
                .map_err(|e| RemoteError::Ssh(e.to_string()))?
        }
    };
    if ok {
        Ok(())
    } else {
        Err(RemoteError::AuthFailed)
    }
}

async fn run_command(
    handle: &mut Handle<ClientHandler>,
    command: &str,
    timeout: Duration,
) -> Result<CommandOutput, RemoteError> {
    let fut = async {
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| RemoteError::Ssh(e.to_string()))?;
        channel
            .exec(true, command.as_bytes())
            .await
            .map_err(|e| RemoteError::Ssh(e.to_string()))?;

        let mut stdout: Vec<u8> = Vec::new();
        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                // stderr (ExtendedData) is deliberately ignored: a missing file
                // writes there, and we never want diagnostics in the inventory.
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Eof | ChannelMsg::Close => {}
                _ => {}
            }
        }
        Ok::<_, RemoteError>(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            exit_status,
        })
    };

    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(RemoteError::Command(format!(
            "истекло время ожидания команды: {command}"
        ))),
    }
}

/// Connects to `target`, confirms the host key per `policy`, authenticates, and
/// returns the host key plus a [`MapRunner`] holding every read command's
/// output — which the sync scan pipeline then consumes.
async fn collect_over_ssh(
    target: &RemoteTarget,
    credential: &Credential,
    policy: HostKeyPolicy,
    timeouts: SshTimeouts,
) -> Result<(HostKey, MapRunner), RemoteError> {
    let (mut handle, host_key) = open_session(target, policy, timeouts).await?;
    authenticate(&mut handle, target, credential).await?;

    let mut runner = MapRunner::new();
    for command in [
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
    ] {
        // A per-command failure (e.g. rpm absent on a dpkg host) is not fatal;
        // record an empty output so the pipeline reports it as unavailable.
        let output = run_command(&mut handle, &command.remote_command(), timeouts.command)
            .await
            .unwrap_or_else(|_| CommandOutput {
                stdout: String::new(),
                exit_status: None,
            });
        runner.insert(command, output);
    }

    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    Ok((host_key, runner))
}

/// Fetches the server's host key without authenticating, for the operator to
/// confirm. No credential is sent.
pub async fn discover_host_key(
    target: &RemoteTarget,
    timeouts: SshTimeouts,
) -> Result<HostKey, RemoteError> {
    match open_session(target, HostKeyPolicy::Discover, timeouts).await {
        Ok((handle, key)) => {
            // Shouldn't normally reach here (Discover refuses the key), but if a
            // server somehow accepted, close cleanly and return the key.
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
            Ok(key)
        }
        Err(RemoteError::HostKeyDiscovered(key)) => Ok(key),
        Err(e) => Err(e),
    }
}

/// Runs a full credentialed scan over SSH against a host whose key the operator
/// has already confirmed (`expected_fingerprint` is the base64 SHA-256). The
/// package matching reuses the shared OSV matcher via [`scan_remote`].
pub async fn scan_over_ssh(
    repo: &VulnDbRepository,
    target: &RemoteTarget,
    credential: &Credential,
    expected_fingerprint: &str,
    timeouts: SshTimeouts,
) -> Result<RemoteScanReport, RemoteError> {
    let (host_key, mut runner) = collect_over_ssh(
        target,
        credential,
        HostKeyPolicy::Expect(expected_fingerprint.to_string()),
        timeouts,
    )
    .await?;
    scan_remote(repo, target, Some(host_key), &mut runner)
}

/// The outcome of fetching a remote project tree over SFTP into a local
/// directory, ready for the code analyser to read.
pub struct FetchResult {
    pub summary: FetchSummary,
    pub host_key: HostKey,
    /// The base path as the server resolved it (a relative path or `~` is
    /// interpreted against the login home), for the report.
    pub resolved_path: String,
}

/// Downloads the project at `remote_path` into the local directory `dest` over
/// SFTP, confirming the host key first. **Read-only on the target**: it only
/// lists directories and reads files — never writes, renames or removes
/// anything on the server. Dependency, build and version-control directories
/// and binary/media files are skipped, and the [`FetchLimits`] bound the copy
/// so a huge or hostile tree cannot fill the disk or loop through symlinks.
pub async fn fetch_project_over_ssh(
    target: &RemoteTarget,
    credential: &Credential,
    expected_fingerprint: &str,
    remote_path: &str,
    dest: &Path,
    limits: FetchLimits,
    timeouts: SshTimeouts,
) -> Result<FetchResult, RemoteError> {
    let (mut handle, host_key) = open_session(
        target,
        HostKeyPolicy::Expect(expected_fingerprint.to_string()),
        timeouts,
    )
    .await?;
    authenticate(&mut handle, target, credential).await?;

    // The SFTP subsystem rides a dedicated channel.
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

    // Resolve `~`/relative against the login home; fall back to the raw input.
    let base = sftp
        .canonicalize(remote_path)
        .await
        .unwrap_or_else(|_| remote_path.to_string());

    let summary = download_tree(&sftp, &base, dest, limits).await?;
    let _ = sftp.close().await;
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    Ok(FetchResult {
        summary,
        host_key,
        resolved_path: base,
    })
}

/// Joins a POSIX base, a `/`-separated relative path and a name into a remote
/// path. SFTP always speaks POSIX paths on the wire regardless of the engine
/// host's own separator.
fn remote_join(base: &str, rel: &str, name: &str) -> String {
    let base = base.trim_end_matches('/');
    if rel.is_empty() {
        format!("{base}/{name}")
    } else {
        format!("{base}/{rel}/{name}")
    }
}

/// Maps a `/`-separated relative path and a name onto a local path under
/// `dest`, pushing one component at a time so it is correct on any OS.
fn local_path(dest: &Path, rel: &str, name: &str) -> std::path::PathBuf {
    let mut p = dest.to_path_buf();
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        p.push(comp);
    }
    p.push(name);
    p
}

/// Walks the remote tree breadth-first, applying the exclusions and limits,
/// and writes each kept file under `dest` preserving its relative path.
async fn download_tree(
    sftp: &SftpSession,
    base: &str,
    dest: &Path,
    limits: FetchLimits,
) -> Result<FetchSummary, RemoteError> {
    let mut summary = FetchSummary::default();
    // Confirm the base is a directory we can list before anything else.
    let root_entries = sftp.read_dir(base.to_string()).await.map_err(|e| {
        RemoteError::Sftp(format!(
            "папка {base} недоступна (проверьте путь и права): {e}"
        ))
    })?;

    // Queue of (relative dir path, its already-read entries, depth).
    let mut queue: std::collections::VecDeque<(String, usize)> = std::collections::VecDeque::new();
    // Process the root's entries, then descend.
    let mut pending: Vec<(String, Vec<russh_sftp::client::fs::DirEntry>)> =
        vec![(String::new(), root_entries.collect())];

    'walk: loop {
        // Drain any directory whose entries are already in hand, then pull the
        // next queued directory and read it.
        while let Some((rel, entries)) = pending.pop() {
            for entry in entries {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let child_rel = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                let ft = entry.file_type();
                if ft.is_symlink() {
                    // Never followed: a symlink could escape the tree or loop.
                    push_capped(&mut summary.skipped_symlinks, child_rel);
                    continue;
                }
                if ft.is_dir() {
                    if is_excluded_dir(&name) {
                        push_capped(&mut summary.skipped_dirs, child_rel);
                    } else {
                        let depth = child_rel.matches('/').count();
                        if depth <= limits.max_depth {
                            queue.push_back((child_rel, depth));
                        } else {
                            push_capped(
                                &mut summary.skipped_dirs,
                                format!("{child_rel} (слишком глубоко)"),
                            );
                        }
                    }
                    continue;
                }
                if !ft.is_file() {
                    // Devices, FIFOs and sockets are not source.
                    continue;
                }
                if is_binary_path(&name) {
                    push_capped(&mut summary.skipped_binary, child_rel);
                    continue;
                }
                let size = entry.metadata().len();
                if size > limits.max_file_bytes {
                    push_capped(&mut summary.skipped_large, child_rel);
                    continue;
                }
                if summary.files + 1 > limits.max_files
                    || summary.bytes + size > limits.max_total_bytes
                {
                    summary.truncated = true;
                    summary.limit_hit = Some(format!(
                        "Достигнут предел загрузки ({} файлов или {} МБ). Проект скопирован частично.",
                        limits.max_files,
                        limits.max_total_bytes / (1024 * 1024)
                    ));
                    break 'walk;
                }
                let remote = remote_join(base, &rel, &name);
                let data = match sftp.read(remote).await {
                    Ok(d) => d,
                    Err(_) => continue, // unreadable file: skip, never fail the scan
                };
                let local = local_path(dest, &rel, &name);
                if let Some(parent) = local.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        RemoteError::Sftp(format!("не удалось создать временную папку: {e}"))
                    })?;
                }
                std::fs::write(&local, &data).map_err(|e| {
                    RemoteError::Sftp(format!("не удалось записать временный файл: {e}"))
                })?;
                summary.files += 1;
                summary.bytes += data.len() as u64;
            }
        }
        let Some((rel, _depth)) = queue.pop_front() else {
            break;
        };
        let full = if rel.is_empty() {
            base.to_string()
        } else {
            format!("{}/{rel}", base.trim_end_matches('/'))
        };
        match sftp.read_dir(full).await {
            Ok(rd) => pending.push((rel, rd.collect())),
            // An unreadable subdirectory is noted, not fatal.
            Err(_) => push_capped(&mut summary.skipped_dirs, format!("{rel} (нет доступа)")),
        }
    }

    if summary.files == 0 && !summary.truncated {
        return Err(RemoteError::Sftp(format!(
            "в {base} не найдено файлов исходного кода для анализа"
        )));
    }
    Ok(summary)
}

/// Appends to a skip list, capped so a pathological tree cannot grow the
/// report without bound.
fn push_capped(list: &mut Vec<String>, item: String) {
    const CAP: usize = 500;
    if list.len() < CAP {
        list.push(item);
    }
}

/// Produces the "waiting for the operator to confirm the host key" report from
/// a discovered key, so the caller can hand it straight to the UI.
pub fn unconfirmed_report(target: &RemoteTarget, host_key: HostKey) -> RemoteScanReport {
    RemoteScanReport {
        host: target.host.clone(),
        port: target.port,
        username: target.username.clone(),
        host_key: Some(host_key),
        status: RemoteScanStatus::HostKeyUnconfirmed,
        os_name: String::new(),
        ecosystem: None,
        kernel: None,
        architecture: None,
        package_report: None,
        cis_report: None,
        collection_errors: Vec::new(),
    }
}
