//! Incident investigation (DFIR) — stage 1: build a unified UTC timeline from
//! a folder (or a single file) of host and web logs.
//!
//! `incident.scan` starts the analysis in the background against a path on the
//! engine's machine; `incident.status` reports progress and, once done, the
//! timeline. Nothing on disk is modified — the logs are only read.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::{json, Value};

use incident_analysis::{analyze_path, Options, Timeline};

#[derive(Default)]
struct ScanJob {
    running: bool,
    generation: u64,
    path: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
    report: Option<Value>,
    error: Option<String>,
}

pub struct IncidentScanService {
    job: Mutex<ScanJob>,
}

impl Default for IncidentScanService {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentScanService {
    pub fn new() -> Self {
        Self {
            job: Mutex::new(ScanJob::default()),
        }
    }

    /// Starts an investigation of the logs under `path`. One runs at a time.
    pub fn start(self: &Arc<Self>, params: &Value) -> Result<Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Укажите папку или файл с логами".to_string())?
            .to_string();

        let root =
            std::fs::canonicalize(&path).map_err(|e| format!("Путь {path} недоступен: {e}"))?;

        let mut opts = Options::default();
        if let Some(y) = params.get("assume_year").and_then(|v| v.as_i64()) {
            if (1970..=9999).contains(&y) {
                opts.assume_year = Some(y as i32);
            }
        }

        let generation = {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Расследование уже выполняется".to_string());
            }
            let generation = job.generation + 1;
            *job = ScanJob {
                running: true,
                generation,
                path: Some(path.clone()),
                started_at: Some(Utc::now().to_rfc3339()),
                ..ScanJob::default()
            };
            generation
        };

        let service = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("incident-scan".into())
            .spawn(move || {
                let outcome = run_blocking(&root, &opts);
                service.finish(generation, outcome);
            });
        if let Err(e) = spawned {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            job.running = false;
            job.error = Some(format!("Не удалось запустить расследование: {e}"));
        }
        Ok(self.status())
    }

    fn finish(&self, generation: u64, outcome: Result<Timeline, String>) {
        let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        if job.generation != generation {
            return; // a newer run started; drop this stale result
        }
        job.running = false;
        job.finished_at = Some(Utc::now().to_rfc3339());
        match outcome {
            Ok(timeline) => {
                job.report = Some(timeline_to_json(&timeline));
            }
            Err(e) => job.error = Some(e),
        }
    }

    pub fn status(&self) -> Value {
        let job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "running": job.running,
            "path": job.path,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error": job.error,
            "report": job.report,
        })
    }
}

fn run_blocking(root: &Path, opts: &Options) -> Result<Timeline, String> {
    analyze_path(root, opts).map_err(|e| e.to_string())
}

pub(crate) fn timeline_to_json(t: &Timeline) -> Value {
    // The timeline derives Serialize; add a small summary the UI shows above
    // the table without recomputing it client-side.
    let mut by_source: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for e in &t.events {
        *by_source.entry(e.source.as_str()).or_default() += 1;
    }
    json!({
        "events": t.events,
        "files": t.files,
        "findings": t.findings,
        "links": t.links,
        "first_event": t.first_event,
        "last_event": t.last_event,
        "warnings": t.warnings,
        "summary": {
            "total_events": t.events.len(),
            "files": t.files.len(),
            "findings": t.findings.len(),
            "links": t.links.len(),
            "by_source": by_source,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn start_then_status_yields_a_timeline() {
        let dir = std::env::temp_dir().join(format!("inc-svc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("access.log")).unwrap();
        writeln!(
            f,
            "192.0.2.9 - - [10/Oct/2026:13:55:36 +0000] \"GET /a HTTP/1.1\" 200 5 \"-\" \"-\""
        )
        .unwrap();
        drop(f);

        let svc = Arc::new(IncidentScanService::new());
        let started = svc
            .start(&json!({ "path": dir.to_str().unwrap(), "assume_year": 2026 }))
            .unwrap();
        assert_eq!(started.get("running").and_then(|v| v.as_bool()), Some(true));

        // Wait for the background thread to finish.
        let mut status = svc.status();
        for _ in 0..200 {
            if status.get("running").and_then(|v| v.as_bool()) == Some(false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            status = svc.status();
        }
        assert_eq!(status.get("error"), Some(&Value::Null));
        let report = status.get("report").unwrap();
        assert_eq!(
            report
                .get("summary")
                .and_then(|s| s.get("total_events"))
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        let ev = &report.get("events").unwrap().as_array().unwrap()[0];
        assert_eq!(
            ev.get("timestamp").and_then(|v| v.as_str()),
            Some("2026-10-10T13:55:36Z")
        );
        // The concrete log line is carried as evidence.
        assert!(ev
            .get("raw")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("GET /a HTTP/1.1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_path_is_rejected() {
        let svc = Arc::new(IncidentScanService::new());
        assert!(svc.start(&json!({ "path": "" })).is_err());
    }
}
