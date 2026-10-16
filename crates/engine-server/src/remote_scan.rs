//! Credentialed remote-host vulnerability scan over SSH, driven from the
//! engine.
//!
//! `remote.discover` connects to a host the operator entered, fetches its SSH
//! host key and returns the fingerprint for the operator to confirm — no
//! credential is sent at this step. `remote.scan` then runs a full scan in the
//! background against the confirmed key: it collects the host's OS, kernel and
//! installed packages over read-only SSH commands and matches them with the
//! same OSV database the local Linux scan uses. `remote.status` reports
//! progress and, once done, the findings.
//!
//! The operator's password or key is held only for the duration of the scan
//! and is never written into the status, the report or a log.

use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::{json, Value};

use remote_scan::ssh::{discover_host_key, scan_over_ssh, SshTimeouts};
use remote_scan::types::{
    Credential, RemotePlatform, RemoteScanReport, RemoteScanStatus, WindowsOsStatus,
};
use remote_scan::RemoteTarget;

use crate::vulndb::VulnDbService;

const DEFAULT_PORT: u16 = 22;

#[derive(Default)]
struct ScanJob {
    running: bool,
    generation: u64,
    target: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
    report: Option<Value>,
    error: Option<String>,
}

pub struct RemoteScanService {
    vulndb: Arc<VulnDbService>,
    job: Mutex<ScanJob>,
}

impl RemoteScanService {
    pub fn new(vulndb: Arc<VulnDbService>) -> Self {
        Self {
            vulndb,
            job: Mutex::new(ScanJob::default()),
        }
    }

    /// Fetches the host key so the operator can confirm it. Sends no
    /// credential. Runs on the caller's async runtime.
    pub async fn discover(&self, params: &Value) -> Result<Value, String> {
        let target = parse_target(params)?;
        let key = discover_host_key(&target, SshTimeouts::default())
            .await
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "host": target.host,
            "port": target.port,
            "host_key": {
                "algorithm": key.algorithm,
                "sha256": key.sha256,
                "fingerprint": key.fingerprint(),
            },
        }))
    }

    /// Starts a background scan against a host whose key was already confirmed.
    pub fn start(self: &Arc<Self>, params: &Value) -> Result<Value, String> {
        let target = parse_target(params)?;
        let credential = parse_credential(params)?;
        let expected = params
            .get("expected_fingerprint")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "Сначала подтвердите отпечаток ключа хоста (remote.discover)".to_string()
            })?;
        // Accept the fingerprint with or without the OpenSSH `SHA256:` prefix.
        let expected = expected
            .strip_prefix("SHA256:")
            .unwrap_or(expected)
            .to_string();

        let repo = self.vulndb.open_repo()?;

        let generation = {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Проверка удалённого хоста уже выполняется".to_string());
            }
            let generation = job.generation + 1;
            *job = ScanJob {
                running: true,
                generation,
                target: Some(format!(
                    "{}@{}:{}",
                    target.username, target.host, target.port
                )),
                started_at: Some(Utc::now().to_rfc3339()),
                ..ScanJob::default()
            };
            generation
        };

        let service = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("remote-scan".into())
            .spawn(move || {
                let outcome = run_blocking(&repo, &target, &credential, &expected);
                service.finish(generation, outcome);
            });
        if let Err(e) = spawned {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            job.running = false;
            job.error = Some(format!("Не удалось запустить проверку: {e}"));
        }
        Ok(self.status())
    }

    fn finish(&self, generation: u64, outcome: Result<RemoteScanReport, String>) {
        let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        if job.generation != generation {
            return;
        }
        job.running = false;
        job.finished_at = Some(Utc::now().to_rfc3339());
        match outcome {
            Ok(report) => job.report = Some(report_to_json(&report)),
            Err(e) => job.error = Some(e),
        }
    }

    pub fn status(&self) -> Value {
        let job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "running": job.running,
            "target": job.target,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error": job.error,
            "report": job.report,
        })
    }
}

/// Runs the async SSH scan to completion on a private runtime (we are on a
/// dedicated thread, so a current-thread runtime is enough).
fn run_blocking(
    repo: &vulnerability_engine::VulnDbRepository,
    target: &RemoteTarget,
    credential: &Credential,
    expected_fingerprint: &str,
) -> Result<RemoteScanReport, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Не удалось создать среду выполнения: {e}"))?;
    runtime
        .block_on(scan_over_ssh(
            repo,
            target,
            credential,
            expected_fingerprint,
            SshTimeouts::default(),
        ))
        .map_err(|e| e.to_string())
}

pub(crate) fn parse_target(params: &Value) -> Result<RemoteTarget, String> {
    let host = params
        .get("host")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Укажите адрес хоста".to_string())?
        .to_string();
    let port = params
        .get("port")
        .and_then(|v| v.as_u64())
        .filter(|p| *p >= 1 && *p <= 65535)
        .map(|p| p as u16)
        .unwrap_or(DEFAULT_PORT);
    let username = params
        .get("username")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Укажите логин".to_string())?
        .to_string();
    Ok(RemoteTarget::new(host, port, username))
}

pub(crate) fn parse_credential(params: &Value) -> Result<Credential, String> {
    let private_key = params
        .get("private_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(pem) = private_key {
        let passphrase = params
            .get("passphrase")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        return Ok(Credential::PrivateKey {
            pem: pem.to_string(),
            passphrase,
        });
    }
    let password = params
        .get("password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    if let Some(pw) = password {
        return Ok(Credential::Password(pw.to_string()));
    }
    Err("Укажите пароль или приватный ключ".to_string())
}

fn status_label(status: RemoteScanStatus) -> &'static str {
    match status {
        RemoteScanStatus::HostKeyUnconfirmed => "HOST_KEY_UNCONFIRMED",
        RemoteScanStatus::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
        RemoteScanStatus::NoPackageInventory => "NO_PACKAGE_INVENTORY",
        RemoteScanStatus::VulndbEmpty => "VULNDB_EMPTY",
        RemoteScanStatus::NoKnownMatchedVulnerabilities => "NO_KNOWN_MATCHED_VULNERABILITIES",
        RemoteScanStatus::VulnerabilitiesFound => "VULNERABILITIES_FOUND",
    }
}

fn win_status_label(status: WindowsOsStatus) -> &'static str {
    match status {
        WindowsOsStatus::Unsupported => "UNSUPPORTED_PLATFORM",
        WindowsOsStatus::VulndbEmpty => "VULNDB_EMPTY",
        WindowsOsStatus::ProductNotInDatabase => "PRODUCT_NOT_IN_DATABASE",
        WindowsOsStatus::NoKnownMatchedVulnerabilities => "NO_KNOWN_MATCHED_VULNERABILITIES",
        WindowsOsStatus::VulnerabilitiesFound => "VULNERABILITIES_FOUND",
    }
}

fn report_to_json(r: &RemoteScanReport) -> Value {
    let platform = match r.platform {
        RemotePlatform::Linux => "linux",
        RemotePlatform::Windows => "windows",
    };
    let windows = r.windows.as_ref().map(|w| {
        json!({
            "caption": w.caption,
            "build": w.full_build,
            "display_version": w.display_version,
            "product": w.product,
            "installed_updates": w.installed_updates,
            "os_status": win_status_label(w.os_status),
            "os_cve": w.os_cve.as_ref().and_then(|v| serde_json::to_value(v).ok()),
            "app_cve": w.app_cve.as_ref().and_then(|v| serde_json::to_value(v).ok()),
        })
    });
    json!({
        "host": r.host,
        "port": r.port,
        "username": r.username,
        "platform": platform,
        "status": status_label(r.status),
        "os": r.os_name,
        "ecosystem": r.ecosystem,
        "kernel": r.kernel,
        "architecture": r.architecture,
        "host_key": r.host_key.as_ref().map(|k| json!({
            "algorithm": k.algorithm,
            "sha256": k.sha256,
            "fingerprint": k.fingerprint(),
        })),
        "package_report": r
            .package_report
            .as_ref()
            .and_then(|p| serde_json::to_value(p).ok()),
        "cis_report": r
            .cis_report
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "windows": windows,
        "collection_errors": r.collection_errors,
    })
}
