//! Source-code analysis of a project that lives on a remote host, fetched over
//! SFTP.
//!
//! `remote.code_scan` connects to a host whose SSH host key the operator has
//! already confirmed (via `remote.discover`), copies the project directory down
//! over SFTP into a temporary folder on the engine machine, runs the same
//! `code_analysis` taint analysis and dependency check the local `code.scan`
//! uses, and then **deletes the temporary copy**. `remote.code_status` reports
//! progress and, once done, the findings.
//!
//! Safety mirrors the remote OS scan:
//! - The fetch is read-only on the target — it only lists directories and reads
//!   files; nothing is written, renamed or removed on the server.
//! - Dependency, build and version-control directories and binary/media files
//!   are skipped, and the copy is size- and count-bounded, so a huge or hostile
//!   tree cannot fill the disk or loop through symlinks.
//! - The operator's password or key is held only for the duration of the fetch
//!   and is never written into the status, the report or a log.
//! - The downloaded source is removed from disk as soon as the report is built.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::{json, Value};

use remote_scan::fetch::FetchLimits;
use remote_scan::ssh::{fetch_project_over_ssh, FetchResult, SshTimeouts};
use remote_scan::types::Credential;
use remote_scan::RemoteTarget;

use crate::code_scan::{analyze, compose_report};
use crate::remote_scan::{parse_credential, parse_target};
use crate::vulndb::VulnDbService;

#[derive(Default)]
struct ScanJob {
    running: bool,
    generation: u64,
    target: Option<String>,
    path: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
    report: Option<Value>,
    error: Option<String>,
}

pub struct RemoteCodeScanService {
    vulndb: Arc<VulnDbService>,
    job: Mutex<ScanJob>,
}

impl RemoteCodeScanService {
    pub fn new(vulndb: Arc<VulnDbService>) -> Self {
        Self {
            vulndb,
            job: Mutex::new(ScanJob::default()),
        }
    }

    /// Starts a background fetch-and-analyse against a host whose key was
    /// already confirmed.
    pub fn start(self: &Arc<Self>, params: &Value) -> Result<Value, String> {
        let target = parse_target(params)?;
        let credential = parse_credential(params)?;
        let expected = expected_fingerprint(params)?;
        let remote_path = params
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Укажите путь к проекту на удалённом хосте".to_string())?
            .to_string();
        let options = code_analysis::Options {
            external_sources: params
                .get("external_sources")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            include_tests: params
                .get("include_tests")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };

        let generation = {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Проверка кода удалённого проекта уже выполняется".to_string());
            }
            let generation = job.generation + 1;
            *job = ScanJob {
                running: true,
                generation,
                target: Some(format!(
                    "{}@{}:{}",
                    target.username, target.host, target.port
                )),
                path: Some(remote_path.clone()),
                started_at: Some(Utc::now().to_rfc3339()),
                ..ScanJob::default()
            };
            generation
        };

        let service = Arc::clone(self);
        let vulndb = Arc::clone(&self.vulndb);
        let spawned = std::thread::Builder::new()
            .name("remote-code-scan".into())
            .spawn(move || {
                let outcome = run_blocking(
                    &vulndb,
                    &target,
                    &credential,
                    &expected,
                    &remote_path,
                    options,
                );
                service.finish(generation, outcome);
            });
        if let Err(e) = spawned {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            job.running = false;
            job.error = Some(format!("Не удалось запустить проверку: {e}"));
        }
        Ok(self.status())
    }

    fn finish(&self, generation: u64, outcome: Result<(Value, String), String>) {
        let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        if job.generation != generation {
            return;
        }
        job.running = false;
        job.finished_at = Some(Utc::now().to_rfc3339());
        match outcome {
            Ok((report, resolved_path)) => {
                job.path = Some(resolved_path);
                job.report = Some(report);
            }
            Err(e) => job.error = Some(e),
        }
    }

    pub fn status(&self) -> Value {
        let job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "languages": ["python", "java", "php", "c", "cpp", "javascript", "typescript"],
            "running": job.running,
            "target": job.target,
            "path": job.path,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error": job.error,
            "report": job.report,
        })
    }
}

/// Accepts the confirmed host-key fingerprint, with or without the OpenSSH
/// `SHA256:` prefix.
pub(crate) fn expected_fingerprint(params: &Value) -> Result<String, String> {
    let raw = params
        .get("expected_fingerprint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Сначала подтвердите отпечаток ключа хоста (remote.discover)".to_string())?;
    Ok(raw.strip_prefix("SHA256:").unwrap_or(raw).to_string())
}

/// Fetches the project over SFTP into a temporary folder, analyses it, and
/// deletes the folder. Returns the composed report (with a `fetch` summary) and
/// the path as the server resolved it. Runs on a dedicated thread, so a
/// current-thread runtime is enough for the async fetch.
fn run_blocking(
    vulndb: &VulnDbService,
    target: &RemoteTarget,
    credential: &Credential,
    expected_fingerprint: &str,
    remote_path: &str,
    options: code_analysis::Options,
) -> Result<(Value, String), String> {
    let temp = std::env::temp_dir().join(format!("soc_remote_code_{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&temp)
        .map_err(|e| format!("Не удалось создать временную папку: {e}"))?;
    // Whatever happens below, remove the downloaded source before returning.
    let result = fetch_analyze(
        vulndb,
        target,
        credential,
        expected_fingerprint,
        remote_path,
        &temp,
        options,
    );
    cleanup(&temp);
    result
}

fn fetch_analyze(
    vulndb: &VulnDbService,
    target: &RemoteTarget,
    credential: &Credential,
    expected_fingerprint: &str,
    remote_path: &str,
    temp: &Path,
    options: code_analysis::Options,
) -> Result<(Value, String), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Не удалось создать среду выполнения: {e}"))?;
    let FetchResult {
        summary,
        resolved_path,
        ..
    } = runtime
        .block_on(fetch_project_over_ssh(
            target,
            credential,
            expected_fingerprint,
            remote_path,
            temp,
            FetchLimits::default(),
            SshTimeouts::default(),
        ))
        .map_err(|e| e.to_string())?;

    let analyzed = analyze(temp, options).map_err(|e| format!("Анализ не выполнен: {e}"))?;
    // A remote project's packages must come only from its own fetched source,
    // never from the engine machine's installed Python — so no host probe.
    let mut report = compose_report(
        vulndb,
        false,
        temp,
        &analyzed.base,
        &analyzed.dependencies,
        &analyzed.imports,
        options.include_tests,
    );
    if let Some(map) = report.as_object_mut() {
        map.insert(
            "fetch".into(),
            serde_json::to_value(&summary).unwrap_or(Value::Null),
        );
    }
    Ok((report, resolved_path))
}

/// Removes the temporary project copy; a failure is logged, not surfaced, since
/// the report has already been built.
fn cleanup(temp: &Path) {
    if let Err(e) = std::fs::remove_dir_all(temp) {
        if temp.exists() {
            tracing::warn!(
                "could not remove temporary remote-code copy {:?}: {e}",
                temp
            );
        }
    }
}
