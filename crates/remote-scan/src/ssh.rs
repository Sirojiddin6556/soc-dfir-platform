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

use async_trait::async_trait;
use russh::client::{self, Handle, Handler};
use russh::keys::key::{self, KeyPair};
use russh::{ChannelMsg, Disconnect};

use crate::command::{CommandOutput, MapRunner, ReadCommand};
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
        collection_errors: Vec::new(),
    }
}
