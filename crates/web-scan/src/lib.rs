#![forbid(unsafe_code)]
//! Dynamic scan of a running web application the operator controls.
//!
//! Given a base URL, [`scan`] crawls same-origin pages and forms, optionally
//! signs in through a login form, and then tests the inputs it found for
//! common web flaws by sending requests and reading the responses:
//! reflected cross-site scripting, SQL injection surfaced by a database
//! error, path traversal and open redirects. It also reports passive
//! weaknesses of the responses themselves — missing security headers, cookies
//! without protective flags, and software versions disclosed in headers.
//!
//! Every finding carries the exact request that produced it so the operator
//! can repeat it by hand. The scanner stays on the target's own origin, caps
//! the number of requests it makes, and identifies itself with a dedicated
//! `User-Agent`. It is meant to be pointed at a system the operator is
//! authorized to test.

pub mod checks;
pub mod crawl;
pub mod html;
pub mod http;

use http::{Client, RequestRecord};
use serde::Serialize;
use std::time::{Duration, Instant};
use url::Url;

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// One weakness the scan found.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable machine key, e.g. `reflected-xss`.
    pub rule: String,
    pub cwe: u32,
    pub severity: Severity,
    /// Short Russian title shown in the table.
    pub title: String,
    /// One or two sentences: what it is and what to do.
    pub message: String,
    /// The affected address.
    pub url: String,
    pub method: String,
    /// The parameter the payload went into, when the finding is about one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    /// What in the response proved it (a reflected marker, an error string).
    pub evidence: String,
    /// The request that triggered it, as a `curl` command to repeat.
    pub request: String,
    /// The raw request record, for programmatic use.
    pub request_detail: RequestRecord,
}

/// Signing in before the scan, through an HTML form.
#[derive(Debug, Clone)]
pub struct Login {
    /// The page whose form takes the credentials (same origin).
    pub url: String,
    /// Field name/value pairs to submit (e.g. username and password).
    pub fields: Vec<(String, String)>,
    /// Optional text that appears only once signed in; when set, the scan
    /// verifies the login worked by looking for it on a page afterwards.
    pub success_text: Option<String>,
}

/// What the scan does and how far it goes.
#[derive(Debug, Clone)]
pub struct Options {
    /// Same-origin pages to crawl, at most.
    pub max_pages: usize,
    /// Total requests across crawl and checks, at most.
    pub max_requests: u32,
    /// Per-request connect/read timeout.
    pub timeout: Duration,
    /// Submit forms while crawling and fuzz their inputs. Submitting a form
    /// can change the application's data, so it is a deliberate choice.
    pub submit_forms: bool,
    /// Run the active payload checks; off leaves only crawling and the
    /// passive response checks.
    pub active: bool,
    /// Optional form login run before crawling.
    pub login: Option<Login>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_pages: 200,
            max_requests: 4000,
            timeout: Duration::from_secs(15),
            submit_forms: true,
            active: true,
            login: None,
        }
    }
}

/// The result of a scan.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: String,
    pub pages_crawled: usize,
    pub forms_found: usize,
    pub requests_made: u32,
    pub authenticated: bool,
    pub findings: Vec<Finding>,
    /// Non-fatal problems (unreachable pages, the login failing, the budget
    /// running out), shown so a thin result is not mistaken for a clean one.
    pub notes: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("неверный адрес: {0}")]
    BadUrl(String),
    #[error("адрес должен начинаться с http:// или https://")]
    NotHttp,
    #[error("сайт недоступен: {0}")]
    Unreachable(String),
}

/// A place the scanner can put a payload: a request with named parameters,
/// each of which is a candidate to mutate.
#[derive(Debug, Clone)]
pub struct InjectionPoint {
    /// For GET, the URL without its query; for POST, the form action URL.
    pub url: Url,
    pub method: Method,
    /// Baseline parameters (name, value) sent unchanged except the one tested.
    pub params: Vec<(String, String)>,
    /// The page the point came from, for reporting.
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

impl InjectionPoint {
    /// Builds the request for this point with parameter `index` set to
    /// `payload` (all others at their baseline), and sends it. Returns the
    /// response and the record of what was sent.
    pub fn send(
        &self,
        client: &Client,
        index: Option<usize>,
        payload: &str,
    ) -> Result<(http::Response, RequestRecord), http::HttpError> {
        let params: Vec<(String, String)> = self
            .params
            .iter()
            .enumerate()
            .map(|(i, (k, v))| {
                if Some(i) == index {
                    (k.clone(), payload.to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        match self.method {
            Method::Get => {
                let mut url = self.url.clone();
                url.set_query(Some(&http::encode_form(&params)));
                let record = RequestRecord {
                    method: "GET".into(),
                    url: url.to_string(),
                    body: String::new(),
                };
                let resp = client.get(&url)?;
                Ok((resp, record))
            }
            Method::Post => {
                let record = RequestRecord {
                    method: "POST".into(),
                    url: self.url.to_string(),
                    body: http::encode_form(&params),
                };
                let resp = client.post_form(&self.url, &params)?;
                Ok((resp, record))
            }
        }
    }
}

/// Runs the scan described by `options` against `target`.
pub fn scan(target: &str, options: &Options) -> Result<Report, ScanError> {
    let started = Instant::now();
    let base = Url::parse(target.trim()).map_err(|e| ScanError::BadUrl(e.to_string()))?;
    if base.scheme() != "http" && base.scheme() != "https" {
        return Err(ScanError::NotHttp);
    }
    if base.host().is_none() {
        return Err(ScanError::BadUrl("нет имени хоста".into()));
    }
    let client = Client::new(&base, options.max_requests, options.timeout);
    let mut notes = Vec::new();

    let authenticated = match &options.login {
        Some(login) => match do_login(&client, &base, login) {
            Ok(ok) => {
                if !ok {
                    notes.push(
                        "Вход по форме не удался: проверка выполнена без аутентификации".into(),
                    );
                }
                ok
            }
            Err(e) => {
                notes.push(format!("Вход по форме не выполнен: {e}"));
                false
            }
        },
        None => false,
    };

    // Confirm the site answers before crawling, for a clear error.
    if let Err(e) = client.get(&base) {
        return Err(ScanError::Unreachable(e.to_string()));
    }

    let crawl = crawl::crawl(&client, &base, options, &mut notes);
    let mut findings = Vec::new();

    // Passive checks on the landing page and the cookies collected so far.
    if let Ok(resp) = client.get(&base) {
        checks::passive::check(&base, &resp, &client, &mut findings);
    }

    if options.active {
        for point in &crawl.points {
            checks::run_active(&client, point, &mut findings);
            if client.remaining() == 0 {
                notes.push("Достигнут предел числа запросов: проверены не все места".into());
                break;
            }
        }
    }

    dedupe(&mut findings);
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.url.cmp(&b.url))
    });

    Ok(Report {
        target: base.to_string(),
        pages_crawled: crawl.pages,
        forms_found: crawl.forms,
        requests_made: options.max_requests - client.remaining(),
        authenticated,
        findings,
        notes,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Submits the login form's fields to its URL and, when `success_text` is
/// set, checks a later page for it. Cookies set by the response are kept by
/// the client for the rest of the scan.
fn do_login(client: &Client, base: &Url, login: &Login) -> Result<bool, String> {
    let url = base
        .join(&login.url)
        .map_err(|e| format!("адрес формы входа неверен: {e}"))?;
    if !client.same_origin(&url) {
        return Err("форма входа на другом сайте".into());
    }
    // Read the form first so hidden fields (CSRF tokens) ride along.
    let mut fields: Vec<(String, String)> = Vec::new();
    if let Ok(page) = client.get(&url) {
        if let Some(form) = html::forms(&page.body).into_iter().find(|f| {
            f.fields
                .iter()
                .any(|x| login.fields.iter().any(|(n, _)| *n == x.name))
        }) {
            for field in &form.fields {
                let given = login.fields.iter().find(|(n, _)| *n == field.name);
                match given {
                    Some((_, v)) => fields.push((field.name.clone(), v.clone())),
                    None if field.is_fuzzable() => {
                        fields.push((field.name.clone(), field.value.clone()))
                    }
                    None => {}
                }
            }
        }
    }
    if fields.is_empty() {
        fields = login.fields.clone();
    }
    let response = client.post_form(&url, &fields).map_err(|e| e.to_string())?;
    match &login.success_text {
        Some(text) => {
            // The text may be in the login response itself, or on a page
            // reached once signed in.
            if response.body.contains(text) {
                return Ok(true);
            }
            let page = client.get(base).map_err(|e| e.to_string())?;
            Ok(page.body.contains(text))
        }
        // No signal given: assume it worked if a session cookie was set.
        None => Ok(!client.cookies().is_empty()),
    }
}

/// Drops findings that repeat the same rule, URL and parameter, keeping the
/// first (highest severity after the sort is applied later).
fn dedupe(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        seen.insert((
            f.rule.clone(),
            f.url.clone(),
            f.param.clone(),
            f.method.clone(),
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_targets() {
        assert!(matches!(
            scan("ftp://x/", &Options::default()),
            Err(ScanError::NotHttp)
        ));
        assert!(matches!(
            scan("not a url", &Options::default()),
            Err(ScanError::BadUrl(_))
        ));
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}
