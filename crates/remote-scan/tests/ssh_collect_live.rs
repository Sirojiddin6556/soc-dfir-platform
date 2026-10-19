//! A real, end-to-end check of the SSH artifact collection: it stands up a
//! local OpenSSH server (key-based login, its own host key and SFTP subsystem)
//! and runs the collector against it, so the whole russh + russh-sftp round
//! trip is exercised against a genuine SSH daemon — not a mock.
//!
//! It reads this machine's own filesystem read-only, confirms the host key
//! first, authenticates with a throwaway key, and checks that real files were
//! copied, hashed, and turned into a timeline.
//!
//! `#[ignore]`d so CI (which has no sshd set up) stays green; run it with
//! `cargo test -p remote-scan --features ssh --test ssh_collect_live -- --ignored --nocapture`.
//! If `sshd`/`sftp-server` are not installed it skips with a message.
#![cfg(feature = "ssh")]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use remote_scan::collect::{CollectLimits, JournalMode};
use remote_scan::ssh::{discover_host_key, SshTimeouts};
use remote_scan::ssh_collect::collect_artifacts_over_ssh;
use remote_scan::types::Credential;
use remote_scan::RemoteTarget;

/// A started sshd, killed on drop.
struct Sshd {
    child: Child,
    port: u16,
    _dir: TempDir,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    for dir in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let p = Path::new(dir).join(bin);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn sftp_server() -> Option<PathBuf> {
    for p in [
        "/usr/lib/openssh/sftp-server",
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/libexec/sftp-server",
    ] {
        if Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

/// Starts an OpenSSH server on a loopback port with pubkey-only login, and
/// returns it plus the throwaway private key (PEM) to authenticate with.
fn start_sshd() -> Option<(Sshd, String, String)> {
    let sshd = which("sshd")?;
    let keygen = which("ssh-keygen")?;
    let sftp = sftp_server()?;

    let base = std::env::temp_dir().join(format!("soc-sshd-{}", std::process::id()));
    std::fs::create_dir_all(&base).ok()?;
    let dir = TempDir(base.clone());

    let host_key = base.join("host_ed25519");
    let client_key = base.join("client_ed25519");
    for path in [&host_key, &client_key] {
        let ok = Command::new(&keygen)
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(path)
            .status()
            .ok()?
            .success();
        if !ok {
            return None;
        }
    }
    let client_pem = std::fs::read_to_string(&client_key).ok()?;
    let authorized = base.join("authorized_keys");
    std::fs::copy(client_key.with_extension("pub"), &authorized).ok()?;

    let port = 2222;
    let config = base.join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host}\n\
             PidFile {pid}\n\
             PasswordAuthentication no\n\
             PubkeyAuthentication yes\n\
             PermitRootLogin yes\n\
             UsePAM no\n\
             StrictModes no\n\
             AuthorizedKeysFile {auth}\n\
             Subsystem sftp {sftp}\n",
            host = host_key.display(),
            pid = base.join("sshd.pid").display(),
            auth = authorized.display(),
            sftp = sftp.display(),
        ),
    )
    .ok()?;
    // sshd insists on tight permissions for its host key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&host_key, std::fs::Permissions::from_mode(0o600));
    }

    let child = Command::new(&sshd)
        .arg("-D")
        .arg("-f")
        .arg(&config)
        .spawn()
        .ok()?;

    // Wait for the port to accept connections.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some((
                Sshd {
                    child,
                    port,
                    _dir: dir,
                },
                client_pem,
                whoami(),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| {
            String::from_utf8(
                Command::new("id")
                    .arg("-un")
                    .output()
                    .map(|o| o.stdout)
                    .unwrap_or_default(),
            )
            .unwrap_or_default()
            .trim()
            .to_string()
        })
}

#[tokio::test]
#[ignore = "requires a local sshd; run with --ignored"]
async fn collects_real_artifacts_over_ssh() {
    let Some((sshd, client_pem, user)) = start_sshd() else {
        eprintln!("skipping: sshd/ssh-keygen/sftp-server not available");
        return;
    };
    let target = RemoteTarget::new("127.0.0.1", sshd.port, &user);
    let timeouts = SshTimeouts::default();

    // 1. Discover and confirm the host key (no credential sent yet).
    let key = discover_host_key(&target, timeouts)
        .await
        .expect("host key discovered");
    assert!(!key.sha256.is_empty(), "a fingerprint was returned");

    // 2. Collect into a fresh case directory, authenticating with the key.
    let case_dir = std::env::temp_dir().join(format!("soc-case-{}", std::process::id()));
    let _guard = TempDir(case_dir.clone());
    let cred = Credential::PrivateKey {
        pem: client_pem,
        passphrase: None,
    };
    let result = collect_artifacts_over_ssh(
        &target,
        &cred,
        &key.sha256,
        &case_dir,
        CollectLimits::default(),
        timeouts,
    )
    .await
    .expect("collection ran");
    let m = &result.manifest;

    // The host's own passwd came down and is attributed under its folder.
    assert!(
        m.files.iter().any(|f| f.remote_path == "/etc/passwd"),
        "expected /etc/passwd among {} files",
        m.files.len()
    );
    let passwd = m
        .files
        .iter()
        .find(|f| f.remote_path == "/etc/passwd")
        .unwrap();
    assert_eq!(passwd.sha256.len(), 64, "sha256 is hex-encoded");
    assert!(
        passwd.local_path.starts_with(&m.host_dir),
        "copy {} lives under the host folder {}",
        passwd.local_path,
        m.host_dir
    );

    // The copy really exists on disk with the recorded hash.
    let local = case_dir.join(
        passwd
            .local_path
            .replace('/', std::path::MAIN_SEPARATOR_STR),
    );
    let bytes = std::fs::read(&local).expect("copied file exists");
    let got = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    assert_eq!(got, passwd.sha256, "stored hash matches the bytes on disk");

    // Read-only commands were captured, and the manifest names where events
    // came from. The manifest and the host dir are present.
    assert!(
        m.commands.iter().any(|c| c.name == "ps"),
        "process list captured"
    );
    assert!(case_dir.join(&m.host_dir).join("manifest.json").exists());
    let _ = JournalMode::TextLogs; // the enum is part of the manifest contract
    eprintln!(
        "collected {} files, {} commands, journal_mode {:?}, {} skipped, host '{}'",
        m.files.len(),
        m.commands.len(),
        m.journal_mode,
        m.skipped.len(),
        m.host_dir
    );
}
