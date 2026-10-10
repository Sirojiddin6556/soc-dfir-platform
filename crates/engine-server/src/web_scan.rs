//! Dynamic scan of a running web application, driven from the engine.
//!
//! `web.scan` starts a [`web_scan`] run against a URL in the background: it
//! crawls the site's pages and forms, optionally signs in first, and tests
//! the inputs it finds for reflected XSS, SQL injection, path traversal and
//! open redirects, plus passive weaknesses of the responses. `web.status`
//! reports whether it is running and, once done, the findings with the
//! request that produced each one.
//!
//! The scan is pointed at a system the operator is authorized to test; it
//! stays on that origin and caps how many requests it makes.

use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::Duration;
use web_scan::{Login, Options};

/// Hard ceilings so a value from the request cannot make the scan unbounded.
const MAX_PAGES_CAP: usize = 2000;
const MAX_REQUESTS_CAP: u32 = 50_000;

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

pub struct WebScanService {
    job: Mutex<ScanJob>,
}

impl Default for WebScanService {
    fn default() -> Self {
        Self::new()
    }
}

impl WebScanService {
    pub fn new() -> Self {
        Self {
            job: Mutex::new(ScanJob::default()),
        }
    }

    /// Starts a scan from JSON params; one scan runs at a time.
    pub fn start(self: &std::sync::Arc<Self>, params: &Value) -> Result<Value, String> {
        let target = params
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Укажите адрес сайта (http:// или https://)".to_string())?
            .to_string();
        let options = parse_options(params);

        let generation = {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Проверка сайта уже выполняется".to_string());
            }
            let generation = job.generation + 1;
            *job = ScanJob {
                running: true,
                generation,
                target: Some(target.clone()),
                started_at: Some(Utc::now().to_rfc3339()),
                ..ScanJob::default()
            };
            generation
        };

        let service = std::sync::Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("web-scan".into())
            .spawn(move || service.run(target, options, generation));
        if let Err(e) = spawned {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            job.running = false;
            job.error = Some(format!("Не удалось запустить проверку: {e}"));
        }
        Ok(self.status())
    }

    fn run(&self, target: String, options: Options, generation: u64) {
        let outcome = web_scan::scan(&target, &options);
        let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        if job.generation != generation {
            return;
        }
        job.running = false;
        job.finished_at = Some(Utc::now().to_rfc3339());
        match outcome {
            Ok(report) => match serde_json::to_value(&report) {
                Ok(v) => job.report = Some(v),
                Err(e) => job.error = Some(format!("Отчёт не сформирован: {e}")),
            },
            Err(e) => job.error = Some(format!("Проверка не выполнена: {e}")),
        }
    }

    /// The current or last scan; the report once it finished.
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

/// Builds scan options from the request, clamping every bound.
fn parse_options(params: &Value) -> Options {
    let mut options = Options {
        active: params
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        submit_forms: params
            .get("submit_forms")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        discover_paths: params
            .get("discover_paths")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        use_openapi: params
            .get("use_openapi")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        ..Options::default()
    };
    if let Some(n) = params.get("max_pages").and_then(|v| v.as_u64()) {
        options.max_pages = (n as usize).clamp(1, MAX_PAGES_CAP);
    }
    if let Some(n) = params.get("max_requests").and_then(|v| v.as_u64()) {
        options.max_requests = (n as u32).clamp(1, MAX_REQUESTS_CAP);
    }
    if let Some(secs) = params.get("timeout_secs").and_then(|v| v.as_u64()) {
        options.timeout = Duration::from_secs(secs.clamp(1, 120));
    }
    options.login = parse_login(params.get("login"));
    options
}

/// Accepts either a `fields` object/array or the common
/// username/password shorthand, plus an optional success marker.
fn parse_login(value: Option<&Value>) -> Option<Login> {
    let login = value?;
    let url = login
        .get("url")
        .and_then(|v| v.as_str())?
        .trim()
        .to_string();
    if url.is_empty() {
        return None;
    }
    let mut fields: Vec<(String, String)> = Vec::new();
    match login.get("fields") {
        Some(Value::Object(map)) => {
            for (k, v) in map {
                if let Some(v) = v.as_str() {
                    fields.push((k.clone(), v.to_string()));
                }
            }
        }
        Some(Value::Array(list)) => {
            for item in list {
                if let (Some(n), Some(v)) = (
                    item.get("name").and_then(|v| v.as_str()),
                    item.get("value").and_then(|v| v.as_str()),
                ) {
                    fields.push((n.to_string(), v.to_string()));
                }
            }
        }
        _ => {}
    }
    // Shorthand: username/password with optional field names.
    let field_name = |key: &str, default: &str| {
        login
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    };
    if let Some(user) = login.get("username").and_then(|v| v.as_str()) {
        fields.push((field_name("user_field", "username"), user.to_string()));
    }
    if let Some(pass) = login.get("password").and_then(|v| v.as_str()) {
        fields.push((field_name("pass_field", "password"), pass.to_string()));
    }
    if fields.is_empty() {
        return None;
    }
    Some(Login {
        url,
        fields,
        success_text: login
            .get("success_text")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty()),
        json: login.get("json").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_clamped_and_login_parsed() {
        let params = json!({
            "url": "http://x/",
            "active": false,
            "max_pages": 100000,
            "max_requests": 0,
            "login": {"url": "/login", "username": "admin", "password": "pw", "success_text": "Hi"}
        });
        let o = parse_options(&params);
        assert!(!o.active);
        assert_eq!(o.max_pages, MAX_PAGES_CAP);
        assert_eq!(o.max_requests, 1);
        let login = o.login.unwrap();
        assert_eq!(login.url, "/login");
        assert_eq!(
            login.fields,
            vec![
                ("username".to_string(), "admin".to_string()),
                ("password".to_string(), "pw".to_string()),
            ]
        );
        assert_eq!(login.success_text.as_deref(), Some("Hi"));
    }

    #[test]
    fn missing_url_is_rejected() {
        let service = std::sync::Arc::new(WebScanService::new());
        assert!(service.start(&json!({})).is_err());
        assert!(service.start(&json!({"url": "  "})).is_err());
    }
}
