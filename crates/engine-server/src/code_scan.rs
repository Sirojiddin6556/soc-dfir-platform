//! Source code analysis of a project directory on the engine's machine.
//!
//! `code.scan` starts `code_analysis` on a directory in the background: it
//! looks for flaws in Python, Java, PHP, C and C++ where user input reaches
//! a dangerous call (SQL, command, path, template, LDAP ...). `code.status`
//! reports whether it is running and, once done, the findings with the path
//! the data took from its source to the sink.

use chrono::Utc;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct ScanJob {
    running: bool,
    path: Option<String>,
    external_sources: bool,
    include_tests: bool,
    started_at: Option<String>,
    finished_at: Option<String>,
    report: Option<Value>,
    error: Option<String>,
}

#[derive(Default)]
pub struct CodeScanService {
    job: Mutex<ScanJob>,
}

impl CodeScanService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts analyzing the directory `path`; one analysis runs at a time.
    pub fn start(
        self: &Arc<Self>,
        path: &str,
        external_sources: bool,
        include_tests: bool,
    ) -> Result<Value, String> {
        let path = path.trim();
        if path.is_empty() {
            return Err("Укажите папку с исходным кодом".to_string());
        }
        let root =
            std::fs::canonicalize(path).map_err(|e| format!("Папка {path} недоступна: {e}"))?;
        if !root.is_dir() {
            return Err(format!("{path} не папка"));
        }
        {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Анализ кода уже выполняется".to_string());
            }
            *job = ScanJob {
                running: true,
                path: Some(shown_path(&root)),
                external_sources,
                include_tests,
                started_at: Some(Utc::now().to_rfc3339()),
                ..ScanJob::default()
            };
        }
        let service = Arc::clone(self);
        let options = code_analysis::Options {
            external_sources,
            include_tests,
        };
        let spawned = std::thread::Builder::new()
            .name("code-scan".into())
            .spawn(move || service.run(root, options));
        if let Err(e) = spawned {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            job.running = false;
            job.error = Some(format!("Не удалось запустить анализ: {e}"));
        }
        Ok(self.status())
    }

    fn run(&self, root: PathBuf, options: code_analysis::Options) {
        let outcome = code_analysis::analyze_dir_with(&root, options)
            .map_err(|e| e.to_string())
            .and_then(|report| serde_json::to_value(report).map_err(|e| e.to_string()));
        let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        job.running = false;
        job.finished_at = Some(Utc::now().to_rfc3339());
        match outcome {
            Ok(report) => job.report = Some(report),
            Err(e) => {
                tracing::warn!("code analysis of {} failed: {e}", root.display());
                job.error = Some(format!("Анализ не выполнен: {e}"));
            }
        }
    }

    /// The current or last analysis; the report once it finished.
    pub fn status(&self) -> Value {
        let job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "languages": ["python", "java", "php", "c", "cpp"],
            "running": job.running,
            "path": job.path,
            "external_sources": job.external_sources,
            "include_tests": job.include_tests,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error": job.error,
            "report": job.report,
        })
    }
}

/// The folder as the user would write it: canonical paths on Windows carry
/// the `\\?\` prefix, which is noise for a drive path.
fn shown_path(root: &std::path::Path) -> String {
    let path = root.display().to_string();
    match path.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_string(),
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(service: &CodeScanService) -> Value {
        for _ in 0..600 {
            let s = service.status();
            if s["running"] == false {
                return s;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("analysis did not finish");
    }

    fn project(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("code_scan_{name}_{}", uuid::Uuid::now_v7()));
        for (path, text) in files {
            let p = dir.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    #[test]
    fn reports_flaws_of_a_project_with_their_path() {
        let dir = project(
            "flask",
            &[(
                "app/views.py",
                "from flask import request\nimport os\n\n\ndef run():\n    os.system('ping ' + request.args['host'])\n",
            )],
        );
        let service = Arc::new(CodeScanService::new());
        let started = service.start(dir.to_str().unwrap(), false, false).unwrap();
        assert_eq!(started["running"], true);
        let s = wait(&service);
        assert_eq!(s["error"], Value::Null, "{s}");
        let findings = s["report"]["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{s}");
        assert_eq!(findings[0]["rule"], "command-injection");
        assert_eq!(findings[0]["file"], "app/views.py");
        assert_eq!(findings[0]["line"], 6);
        assert!(!findings[0]["trace"].as_array().unwrap().is_empty());
        assert_eq!(s["report"]["files"], 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn shows_windows_drive_paths_without_the_verbatim_prefix() {
        assert_eq!(
            shown_path(std::path::Path::new(r"\\?\C:\src\shop")),
            r"C:\src\shop"
        );
        assert_eq!(
            shown_path(std::path::Path::new(r"\\?\UNC\server\share")),
            r"\\?\UNC\server\share"
        );
        assert_eq!(shown_path(std::path::Path::new("/srv/shop")), "/srv/shop");
    }

    #[test]
    fn refuses_missing_folders_and_a_second_run() {
        let service = Arc::new(CodeScanService::new());
        assert!(service.start("  ", false, false).is_err());
        let missing = std::env::temp_dir().join(format!("code_scan_none_{}", uuid::Uuid::now_v7()));
        let err = service
            .start(missing.to_str().unwrap(), false, false)
            .unwrap_err();
        assert!(err.contains("недоступна"), "{err}");

        let dir = project("busy", &[("a.py", "x = 1\n")]);
        // Hold the job as running to see the second start refused.
        service.job.lock().unwrap().running = true;
        let err = service
            .start(dir.to_str().unwrap(), false, false)
            .unwrap_err();
        assert!(err.contains("уже выполняется"), "{err}");
        service.job.lock().unwrap().running = false;
        service.start(dir.to_str().unwrap(), false, false).unwrap();
        let s = wait(&service);
        assert_eq!(s["report"]["findings"].as_array().unwrap().len(), 0, "{s}");
        std::fs::remove_dir_all(dir).ok();
    }
}
