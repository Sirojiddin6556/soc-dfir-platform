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
pub mod discovery;
pub mod html;
pub mod http;
pub mod openapi;

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

/// Signing in before the scan, through an HTML form or a JSON API.
#[derive(Debug, Clone)]
pub struct Login {
    /// The URL that takes the credentials (same origin): a form page, or a
    /// JSON login endpoint when `json` is set.
    pub url: String,
    /// Field name/value pairs to submit (e.g. username and password).
    pub fields: Vec<(String, String)>,
    /// Optional text that appears only once signed in; when set, the scan
    /// verifies the login worked by looking for it on a page afterwards.
    pub success_text: Option<String>,
    /// Post the credentials as an `application/json` body (an API login)
    /// instead of an HTML form, and capture a returned bearer token.
    pub json: bool,
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
    /// Brute-force a built-in list of common paths to find endpoints that no
    /// page links to (as a content-discovery tool like ffuf does), and feed
    /// what answers into the crawl. Essential for single-page apps whose HTML
    /// carries no links.
    pub discover_paths: bool,
    /// Fetch an OpenAPI / Swagger description if the site exposes one, and
    /// turn its documented endpoints and parameters into checks.
    pub use_openapi: bool,
    /// Optional login run before crawling (HTML form or JSON API).
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
            discover_paths: true,
            use_openapi: true,
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
    /// Paths found by brute-forcing the built-in word list.
    pub paths_discovered: usize,
    /// Endpoints learned from an OpenAPI / Swagger description.
    pub api_endpoints: usize,
    /// Distinct places (query, form or JSON body) the active checks probed.
    pub points_tested: usize,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// Parameters go in the query string, fetched with GET.
    Get,
    /// Parameters go in an `application/x-www-form-urlencoded` POST body.
    Post,
    /// Parameters go in an `application/json` body, sent with the given HTTP
    /// verb (POST, PUT or PATCH) — used for API endpoints.
    Json(String),
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Json(verb) => verb.as_str(),
        }
    }
}

impl InjectionPoint {
    /// A key identifying this point by verb, path and parameter names, so
    /// duplicates found by different means (crawl, discovery, OpenAPI) drop.
    pub fn key(&self) -> String {
        let mut names: Vec<&str> = self.params.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        format!(
            "{} {}://{}{} [{}]",
            self.method.as_str(),
            self.url.scheme(),
            self.url.authority(),
            self.url.path(),
            names.join(",")
        )
    }

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
        match &self.method {
            Method::Get => {
                let mut url = self.url.clone();
                url.set_query(Some(&http::encode_form(&params)));
                let record = RequestRecord {
                    method: "GET".into(),
                    url: url.to_string(),
                    body: String::new(),
                    content_type: None,
                };
                let resp = client.get(&url)?;
                Ok((resp, record))
            }
            Method::Post => {
                let record = RequestRecord {
                    method: "POST".into(),
                    url: self.url.to_string(),
                    body: http::encode_form(&params),
                    content_type: Some("application/x-www-form-urlencoded".into()),
                };
                let resp = client.post_form(&self.url, &params)?;
                Ok((resp, record))
            }
            Method::Json(verb) => {
                let body = json_body(&params, index);
                let record = RequestRecord {
                    method: verb.clone(),
                    url: self.url.to_string(),
                    body: body.clone(),
                    content_type: Some("application/json".into()),
                };
                let resp = client.send_json(verb, &self.url, &body)?;
                Ok((resp, record))
            }
        }
    }
}

/// Builds a JSON object body from name/value pairs. The parameter at
/// `injected` is always sent as a string (it carries the payload); the rest
/// keep their natural JSON type when the baseline looks like a number, bool
/// or null, so a typed API still accepts the request and reaches its handler.
fn json_body(params: &[(String, String)], injected: Option<usize>) -> String {
    let mut map = serde_json::Map::new();
    for (i, (k, v)) in params.iter().enumerate() {
        let value = if Some(i) == injected {
            serde_json::Value::String(v.clone())
        } else {
            json_scalar(v)
        };
        map.insert(k.clone(), value);
    }
    serde_json::Value::Object(map).to_string()
}

/// A benign baseline value as its natural JSON type.
fn json_scalar(v: &str) -> serde_json::Value {
    if let Ok(n) = v.parse::<i64>() {
        return n.into();
    }
    if let Ok(f) = v.parse::<f64>() {
        return f.into();
    }
    match v {
        "true" => true.into(),
        "false" => false.into(),
        "null" => serde_json::Value::Null,
        _ => serde_json::Value::String(v.to_string()),
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
                    notes.push("Вход не удался: проверка выполнена без аутентификации".into());
                }
                ok
            }
            Err(e) => {
                notes.push(format!("Вход не выполнен: {e}"));
                false
            }
        },
        None => false,
    };

    // Confirm the site answers before crawling, for a clear error.
    if let Err(e) = client.get(&base) {
        return Err(ScanError::Unreachable(e.to_string()));
    }

    // Content discovery: brute-force common paths the HTML links to nowhere,
    // and crawl from whatever answers. This is what makes a single-page app
    // with no links yield something to check.
    let mut seeds: Vec<Url> = Vec::new();
    let mut paths_discovered = 0usize;
    if options.discover_paths {
        let found = discovery::discover(&client, &base, options, &mut notes);
        paths_discovered = found.len();
        seeds.extend(found);
    }

    let crawl = crawl::crawl(&client, &base, &seeds, options, &mut notes);
    let mut points = crawl.points;
    let page_urls = crawl.page_urls;
    let mut keys: std::collections::HashSet<String> = points.iter().map(|p| p.key()).collect();

    // OpenAPI / Swagger: documented endpoints and their parameters, including
    // JSON bodies the crawler can never see.
    let mut api_endpoints = 0usize;
    if options.use_openapi {
        let api = openapi::discover(&client, &base, &mut notes);
        for point in api {
            if keys.insert(point.key()) {
                api_endpoints += 1;
                points.push(point);
            }
        }
    }

    let mut findings = Vec::new();

    // Passive checks on the landing page and the cookies collected so far.
    if let Ok(resp) = client.get(&base) {
        checks::passive::check(&base, &resp, &client, &mut findings);
    }

    let points_tested = points.len();
    if options.active {
        for point in &points {
            checks::run_active(&client, point, &mut findings);
            if client.remaining() == 0 {
                notes.push("Достигнут предел числа запросов: проверены не все места".into());
                break;
            }
        }
        // Stored XSS plants marked payloads through every input, then re-reads
        // the crawled GET pages to see whether any was saved and served back.
        if client.remaining() > 0 {
            checks::stored::check(&client, &points, &page_urls, &mut findings);
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
        paths_discovered,
        api_endpoints,
        points_tested,
        requests_made: options.max_requests - client.remaining(),
        authenticated,
        findings,
        notes,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Signs in before the scan. For a JSON API login it posts the credentials as
/// a JSON object and captures a returned bearer token; for a form login it
/// reads the form (to carry hidden CSRF fields) and submits it. Either way the
/// cookies the response sets are kept by the client for the rest of the scan.
fn do_login(client: &Client, base: &Url, login: &Login) -> Result<bool, String> {
    let url = base
        .join(&login.url)
        .map_err(|e| format!("адрес входа неверен: {e}"))?;
    if !client.same_origin(&url) {
        return Err("адрес входа на другом сайте".into());
    }
    if login.json {
        return do_login_json(client, base, &url, login);
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

/// A JSON API login: posts `{field: value, …}` to the endpoint, keeps any
/// session cookie, and if the response carries a bearer token, sends it as
/// `Authorization: Bearer …` for the rest of the scan.
fn do_login_json(client: &Client, base: &Url, url: &Url, login: &Login) -> Result<bool, String> {
    let mut map = serde_json::Map::new();
    for (k, v) in &login.fields {
        map.insert(k.clone(), json_scalar(v));
    }
    let body = serde_json::Value::Object(map).to_string();
    let response = client
        .send_json("POST", url, &body)
        .map_err(|e| e.to_string())?;
    let parsed: Option<serde_json::Value> = serde_json::from_str(&response.body).ok();

    // A token in the response means authenticated API access from here on.
    let mut got_token = false;
    if let Some(value) = &parsed {
        if let Some(token) = find_token(value) {
            client.set_auth(format!("Bearer {token}"));
            got_token = true;
        }
    }

    if let Some(text) = &login.success_text {
        if response.body.contains(text) {
            return Ok(true);
        }
        // Try a page fetch with whatever cookie or token we now hold.
        if let Ok(page) = client.get(base) {
            if page.body.contains(text) {
                return Ok(true);
            }
        }
        return Ok(got_token);
    }
    // No explicit signal: a 2xx with a token or a session cookie is success.
    Ok((got_token || !client.cookies().is_empty()) && (200..300).contains(&response.status))
}

/// Searches a JSON value for a login token under the names APIs commonly use,
/// at any depth. Returns the first non-empty string found.
fn find_token(value: &serde_json::Value) -> Option<String> {
    const KEYS: &[&str] = &[
        "access_token",
        "accesstoken",
        "token",
        "jwt",
        "id_token",
        "idtoken",
        "auth_token",
        "authtoken",
        "bearer",
        "sessiontoken",
        "session_token",
    ];
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let serde_json::Value::String(s) = v {
                    let key = k.to_lowercase();
                    if KEYS.contains(&key.as_str()) && !s.is_empty() {
                        return Some(s.clone());
                    }
                }
            }
            // Recurse (e.g. {"data": {"access_token": …}}).
            for v in map.values() {
                if let Some(t) = find_token(v) {
                    return Some(t);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(find_token),
        _ => None,
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
