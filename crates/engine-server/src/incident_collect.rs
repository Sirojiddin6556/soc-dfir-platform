//! DFIR: gather a Linux host's investigation artifacts over SSH into a case.
//!
//! `incident.collect` connects to a host whose SSH host key the operator has
//! already confirmed (via `remote.discover`), copies the host's logs, account
//! files, cron/systemd units and SSH configuration into
//! `data/cases/<case>/<host>/`, records each copied file as a case artifact
//! (with its SHA-256 and a chain-of-custody event), and then builds the same
//! UTC timeline, findings and cross-host links `incident.scan` builds for a
//! folder. `incident.collect_status` reports progress and the result.
//!
//! The work is read-only on the target (see `remote_scan::ssh_collect`), and
//! the operator's password or key is held only for the run — never written to
//! the status, the case or a log.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};

use core_domain::artifact::{Artifact, CustodyEvent, CustodyEventType};
use core_domain::id::EntityId;
use incident_analysis::{analyze_path, Options};
use remote_scan::collect::{CollectLimits, CollectionManifest};
use remote_scan::ssh::SshTimeouts;
use remote_scan::ssh_collect::collect_artifacts_over_ssh;
use remote_scan::types::Credential;
use remote_scan::RemoteTarget;
use storage_sqlite::SqliteStorage;

use crate::incident_scan::timeline_to_json;
use crate::remote_code_scan::expected_fingerprint;
use crate::remote_scan::{parse_credential, parse_target};

/// The case a run lands in.
#[derive(Clone)]
struct CaseRef {
    id: EntityId,
    title: String,
}

#[derive(Default)]
struct Job {
    running: bool,
    generation: u64,
    target: Option<String>,
    case_id: Option<String>,
    case_title: Option<String>,
    case_dir: Option<String>,
    host_dir: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
    error: Option<String>,
    collection: Option<Value>,
    report: Option<Value>,
    /// Set when the files came down but no timeline could be built from them
    /// (for example, the login could read no logs). The run itself succeeded,
    /// so this is not `error`.
    report_error: Option<String>,
}

/// What a finished run produced.
struct Outcome {
    case: CaseRef,
    case_dir: PathBuf,
    host_dir: String,
    manifest: CollectionManifest,
    report: Result<Value, String>,
}

pub struct IncidentCollectService {
    storage: SqliteStorage,
    cases_dir: PathBuf,
    job: Mutex<Job>,
}

impl IncidentCollectService {
    pub fn new(storage: SqliteStorage, cases_dir: PathBuf) -> Self {
        Self {
            storage,
            cases_dir,
            job: Mutex::new(Job::default()),
        }
    }

    /// Where a case's files live.
    pub fn case_dir(&self, case_id: &EntityId) -> PathBuf {
        self.cases_dir.join(case_id.to_string())
    }

    /// Starts a background run against a host whose key was already confirmed.
    /// `case_id` adds the host to an existing case; otherwise a new case is
    /// created, titled `case_title` or a default naming the host.
    pub fn start(self: &Arc<Self>, params: &Value) -> Result<Value, String> {
        let target = parse_target(params)?;
        let credential = parse_credential(params)?;
        let expected = expected_fingerprint(params)?;
        let (case, is_new) = self.resolve_case(params, &target)?;

        // Create a new case up front, so it exists even if the run then fails.
        if is_new {
            self.storage
                .insert_case(case.id, &case.title, None)
                .map_err(|e| format!("Не удалось создать дело: {e}"))?;
        }

        let generation = {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Сбор артефактов уже выполняется".to_string());
            }
            let generation = job.generation + 1;
            *job = Job {
                running: true,
                generation,
                target: Some(format!(
                    "{}@{}:{}",
                    target.username, target.host, target.port
                )),
                case_id: Some(case.id.to_string()),
                case_title: Some(case.title.clone()),
                case_dir: Some(self.case_dir(&case.id).display().to_string()),
                started_at: Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
                ..Job::default()
            };
            generation
        };

        let service = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("incident-collect".into())
            .spawn(move || {
                let outcome = service.run_blocking(&target, &credential, &expected, case);
                service.finish(generation, outcome);
            });
        if let Err(e) = spawned {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            job.running = false;
            job.error = Some(format!("Не удалось запустить сбор: {e}"));
        }
        Ok(self.status())
    }

    fn resolve_case(
        &self,
        params: &Value,
        target: &RemoteTarget,
    ) -> Result<(CaseRef, bool), String> {
        if let Some(raw) = params
            .get("case_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let id = EntityId::parse(raw).map_err(|_| "Неверный идентификатор дела".to_string())?;
            let case = self
                .storage
                .get_case(id)
                .map_err(|e| format!("Не удалось прочитать дело: {e}"))?
                .ok_or_else(|| "Такого дела нет".to_string())?;
            return Ok((
                CaseRef {
                    id,
                    title: case.title,
                },
                false,
            ));
        }
        let title = params
            .get("case_title")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(200).collect::<String>())
            .unwrap_or_else(|| {
                format!(
                    "Инцидент: {} ({})",
                    target.host,
                    Utc::now().format("%Y-%m-%d")
                )
            });
        Ok((
            CaseRef {
                id: EntityId::new_v7(),
                title,
            },
            true,
        ))
    }

    fn finish(&self, generation: u64, outcome: Result<Outcome, String>) {
        let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        if job.generation != generation {
            return;
        }
        job.running = false;
        job.finished_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        match outcome {
            Ok(o) => {
                job.case_id = Some(o.case.id.to_string());
                job.case_title = Some(o.case.title);
                job.case_dir = Some(o.case_dir.display().to_string());
                job.host_dir = Some(o.host_dir);
                job.collection = Some(serde_json::to_value(&o.manifest).unwrap_or(Value::Null));
                match o.report {
                    Ok(r) => job.report = Some(r),
                    Err(e) => job.report_error = Some(e),
                }
            }
            Err(e) => job.error = Some(e),
        }
    }

    pub fn status(&self) -> Value {
        let job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "running": job.running,
            "target": job.target,
            "case": job.case_id.as_ref().map(|id| json!({
                "id": id,
                "title": job.case_title,
                "dir": job.case_dir,
            })),
            "host_dir": job.host_dir,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error": job.error,
            "collection": job.collection,
            "report": job.report,
            "report_error": job.report_error,
        })
    }

    /// Collects into the case folder, records the artifacts, and builds the
    /// timeline. Runs on a dedicated thread, so a current-thread runtime is
    /// enough to drive the async SSH part.
    fn run_blocking(
        &self,
        target: &RemoteTarget,
        credential: &Credential,
        expected_fingerprint: &str,
        case: CaseRef,
    ) -> Result<Outcome, String> {
        let case_dir = self.case_dir(&case.id);
        std::fs::create_dir_all(&case_dir)
            .map_err(|e| format!("Не удалось создать папку дела: {e}"))?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Не удалось создать среду выполнения: {e}"))?;
        let result = runtime
            .block_on(collect_artifacts_over_ssh(
                target,
                credential,
                expected_fingerprint,
                &case_dir,
                CollectLimits::default(),
                SshTimeouts::default(),
            ))
            .map_err(|e| e.to_string())?;

        // Record every collected file as a case artifact with a custody event.
        self.record_artifacts(&case.id, &case_dir, &result.manifest);

        // Build the timeline across every host folder now in the case, so a
        // second host's collection re-derives the cross-host links.
        let report = build_report(&case_dir);

        Ok(Outcome {
            case,
            case_dir,
            host_dir: result.manifest.host_dir.clone(),
            manifest: result.manifest,
            report,
        })
    }

    /// Writes one artifact row and one chain-of-custody event per collected
    /// file. The BLAKE3 (the content-addressed locator) is computed from the
    /// local copy; the SHA-256 came from the collector as it wrote the bytes.
    fn record_artifacts(&self, case_id: &EntityId, case_dir: &Path, manifest: &CollectionManifest) {
        let now = Utc::now();
        let mut prev_hash = String::from("GENESIS");
        for f in &manifest.files {
            let mut local = case_dir.to_path_buf();
            for comp in f.local_path.split('/').filter(|c| !c.is_empty()) {
                local.push(comp);
            }
            let hash_blake3 = match std::fs::read(&local) {
                Ok(bytes) => blake3::hash(&bytes).to_hex().to_string(),
                Err(_) => continue, // copy missing; skip quietly
            };
            let artifact = Artifact {
                id: EntityId::new_v7(),
                case_id: *case_id,
                hash_blake3,
                hash_sha256: f.sha256.clone(),
                original_name: f.remote_path.clone(),
                file_size: f.bytes,
                mime_type: "text/plain".to_string(),
                acquisition_method: format!("ssh-collection:{}", manifest.host_dir),
                acquired_at: now,
                ingested_at: now,
            };
            if self.storage.insert_artifact(&artifact).is_err() {
                continue;
            }
            let details = json!({
                "remote_path": f.remote_path,
                "local_path": f.local_path,
                "host": manifest.host_dir,
                "kind": f.kind,
                "sha256": f.sha256,
            });
            let event = CustodyEvent {
                id: EntityId::new_v7(),
                case_id: *case_id,
                actor_id: "ssh-collector".to_string(),
                event_type: CustodyEventType::ArtifactAcquired,
                artifact_hash: Some(f.sha256.clone()),
                details_json: details.to_string(),
                previous_state_hash: prev_hash.clone(),
                timestamp: now,
            };
            let _ = self.storage.append_custody_event(&event);
            prev_hash = f.sha256.clone();
        }
    }
}

/// Builds the unified timeline from every host folder under the case.
fn build_report(case_dir: &Path) -> Result<Value, String> {
    let opts = Options {
        max_files: 20_000,
        ..Options::default()
    };
    analyze_path(case_dir, &opts)
        .map(|t| timeline_to_json(&t))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_scan::collect::{ArtifactKind, CollectedFile};

    fn sha256_hex(b: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(b))
    }

    /// The post-collection engine path with no network: a staged case folder is
    /// recorded as artifacts with custody, and the timeline is built from it
    /// with the host attributed from its folder name.
    #[test]
    fn records_artifacts_and_builds_timeline_from_a_case_dir() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cases = std::env::temp_dir().join(format!(
            "soc-ic-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let svc = IncidentCollectService::new(storage.clone(), cases.clone());
        let case_id = EntityId::new_v7();
        storage.insert_case(case_id, "t", None).unwrap();
        let case_dir = svc.case_dir(&case_id);

        // Stage a host folder with one auth log carrying a brute-force run.
        let logdir = case_dir.join("web01").join("var").join("log");
        std::fs::create_dir_all(&logdir).unwrap();
        let body = "Oct 10 13:55:38 web01 sshd[1]: Failed password for invalid user admin from 45.1.2.3 port 1 ssh2\n".repeat(6);
        std::fs::write(logdir.join("auth.log"), &body).unwrap();

        let manifest = CollectionManifest {
            version: CollectionManifest::VERSION,
            host: "45.1.2.3".into(),
            port: 22,
            username: "root".into(),
            host_dir: "web01".into(),
            platform: "linux".into(),
            collected_at: "2026-10-19T00:00:00Z".into(),
            files: vec![CollectedFile {
                remote_path: "/var/log/auth.log".into(),
                local_path: "web01/var/log/auth.log".into(),
                kind: ArtifactKind::Log,
                bytes: body.len() as u64,
                sha256: sha256_hex(body.as_bytes()),
                mtime: None,
                truncated: false,
            }],
            ..Default::default()
        };
        svc.record_artifacts(&case_id, &case_dir, &manifest);

        // One artifact, with the forensic SHA-256 and a content-addressed BLAKE3.
        let arts = storage.list_artifacts_for_case(case_id).unwrap();
        assert_eq!(arts.len(), 1);
        assert_eq!(
            arts[0].get("hash_sha256").and_then(|v| v.as_str()),
            Some(manifest.files[0].sha256.as_str())
        );
        assert_eq!(
            arts[0].get("name").and_then(|v| v.as_str()),
            Some("/var/log/auth.log")
        );
        assert_eq!(
            arts[0]
                .get("hash_blake3")
                .and_then(|v| v.as_str())
                .map(str::len),
            Some(64)
        );
        // A chain-of-custody event was recorded for it.
        let chain = storage
            .list_custody_chain(&manifest.files[0].sha256)
            .unwrap();
        assert_eq!(chain.len(), 1);

        // The timeline builds, and the brute-force finding is attributed to the
        // host folder.
        let report = build_report(&case_dir).expect("timeline built");
        let events = report.get("events").and_then(|v| v.as_array()).unwrap();
        assert!(!events.is_empty(), "events parsed from the collected log");
        let findings = report.get("findings").and_then(|v| v.as_array()).unwrap();
        assert!(
            findings.iter().any(|f| f
                .get("hosts")
                .and_then(|h| h.as_array())
                .map(|a| a.iter().any(|x| x.as_str() == Some("web01")))
                .unwrap_or(false)),
            "a finding is attributed to web01: {findings:#?}"
        );

        let _ = std::fs::remove_dir_all(&cases);
    }
}
