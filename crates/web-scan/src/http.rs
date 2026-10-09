//! A small blocking HTTP client for the scanner.
//!
//! It wraps one `ureq` agent with a cookie jar, keeps redirects unfollowed so
//! a check can inspect a `Location` header, counts every request against a
//! shared budget, and refuses any host other than the target's. The client is
//! deliberately simple: the scanner only needs GET and form POST.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use url::Url;

/// How the scanner identifies itself to the site it checks.
pub const USER_AGENT: &str = concat!("soc-dfir-platform-webscan/", env!("CARGO_PKG_VERSION"));

/// The response the scanner works with: status, headers and the body text
/// (read up to a cap). The body is kept as a `String`; binary responses are
/// lossily decoded, which is fine because the checks only look for markers.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// The URL actually requested (after the client applied the base).
    pub url: String,
}

impl Response {
    /// The first value of a header, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of a header, case-insensitively.
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("за один проход сделано слишком много запросов ({0})")]
    BudgetSpent(u32),
    #[error("адрес вне проверяемого сайта: {0}")]
    OffSite(String),
    #[error("{0}")]
    Transport(String),
    #[error("неверный адрес: {0}")]
    BadUrl(String),
}

/// A request the scanner made, kept on a finding so the operator can repeat it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestRecord {
    pub method: String,
    pub url: String,
    /// Form body for a POST, as sent (already encoded), empty for a GET.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
}

impl RequestRecord {
    /// A `curl` command that reproduces the request, for the report.
    pub fn as_curl(&self) -> String {
        if self.method == "GET" {
            format!("curl -i '{}'", self.url)
        } else {
            format!(
                "curl -i -X {} --data '{}' '{}'",
                self.method, self.body, self.url
            )
        }
    }
}

pub struct Client {
    agent: ureq::Agent,
    /// Scheme + host (+ port) the scan is confined to.
    origin: Url,
    cookies: Mutex<BTreeMap<String, String>>,
    /// Raw `Set-Cookie` header values seen, for the cookie-flag check.
    set_cookies: Mutex<Vec<String>>,
    budget: AtomicU32,
    body_limit: usize,
}

impl Client {
    /// Builds a client confined to `base`'s origin. `budget` caps the total
    /// number of requests across the whole scan.
    pub fn new(base: &Url, budget: u32, timeout: Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .http_status_as_error(false)
            // The checks read `Location` themselves; following would hide it.
            .max_redirects(0)
            .user_agent(USER_AGENT)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into();
        Self {
            agent,
            origin: origin_of(base),
            cookies: Mutex::new(BTreeMap::new()),
            set_cookies: Mutex::new(Vec::new()),
            budget: AtomicU32::new(budget),
            body_limit: 2 * 1024 * 1024,
        }
    }

    /// How many requests are still allowed.
    pub fn remaining(&self) -> u32 {
        self.budget.load(Ordering::Relaxed)
    }

    /// True when `url` is on the same scheme/host/port as the scan's origin.
    pub fn same_origin(&self, url: &Url) -> bool {
        origin_of(url) == self.origin
    }

    fn take_budget(&self) -> Result<(), HttpError> {
        // Decrement only while positive, so the count never wraps.
        loop {
            let left = self.budget.load(Ordering::Relaxed);
            if left == 0 {
                return Err(HttpError::BudgetSpent(0));
            }
            if self
                .budget
                .compare_exchange(left, left - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    fn cookie_header(&self) -> Option<String> {
        let jar = self.cookies.lock().unwrap_or_else(|p| p.into_inner());
        if jar.is_empty() {
            return None;
        }
        Some(
            jar.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    fn store_cookies(&self, resp: &Response) {
        let mut jar = self.cookies.lock().unwrap_or_else(|p| p.into_inner());
        let mut raw = self.set_cookies.lock().unwrap_or_else(|p| p.into_inner());
        for set in resp.headers_all("set-cookie") {
            if raw.len() < 200 && !raw.iter().any(|s| s == set) {
                raw.push(set.to_string());
            }
            let pair = set.split(';').next().unwrap_or("").trim();
            if let Some((name, value)) = pair.split_once('=') {
                let name = name.trim();
                if !name.is_empty() {
                    jar.insert(name.to_string(), value.trim().to_string());
                }
            }
        }
    }

    /// Every distinct `Set-Cookie` header value seen during the scan.
    pub fn set_cookie_headers(&self) -> Vec<String> {
        self.set_cookies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The cookies the client holds, for the passive flag check.
    pub fn cookies(&self) -> Vec<(String, String)> {
        let jar = self.cookies.lock().unwrap_or_else(|p| p.into_inner());
        jar.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Fetches `url` with GET. Enforces the origin and the budget.
    pub fn get(&self, url: &Url) -> Result<Response, HttpError> {
        if !self.same_origin(url) {
            return Err(HttpError::OffSite(url.to_string()));
        }
        self.take_budget()?;
        let mut req = self.agent.get(url.as_str());
        if let Some(cookie) = self.cookie_header() {
            req = req.header("Cookie", &cookie);
        }
        let resp = req
            .call()
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        let out = self.read(resp, url.as_str())?;
        self.store_cookies(&out);
        Ok(out)
    }

    /// Submits `fields` to `url` as `application/x-www-form-urlencoded`.
    pub fn post_form(&self, url: &Url, fields: &[(String, String)]) -> Result<Response, HttpError> {
        if !self.same_origin(url) {
            return Err(HttpError::OffSite(url.to_string()));
        }
        self.take_budget()?;
        let body = encode_form(fields);
        let mut req = self
            .agent
            .post(url.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded");
        if let Some(cookie) = self.cookie_header() {
            req = req.header("Cookie", &cookie);
        }
        let resp = req
            .send(body.as_bytes())
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        let out = self.read(resp, url.as_str())?;
        self.store_cookies(&out);
        Ok(out)
    }

    fn read(
        &self,
        resp: ureq::http::Response<ureq::Body>,
        url: &str,
    ) -> Result<Response, HttpError> {
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = resp
            .into_body()
            .into_with_config()
            .limit(self.body_limit as u64)
            .read_to_string()
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        Ok(Response {
            status,
            headers,
            body,
            url: url.to_string(),
        })
    }
}

/// Scheme + host + port, the identity a same-origin check compares.
fn origin_of(url: &Url) -> Url {
    let mut o = url.clone();
    o.set_path("");
    o.set_query(None);
    o.set_fragment(None);
    let _ = o.set_username("");
    let _ = o.set_password(None);
    o
}

/// `application/x-www-form-urlencoded` body from name/value pairs.
pub fn encode_form(fields: &[(String, String)]) -> String {
    use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
    // Keep the few characters a form value may carry unescaped-safe set small;
    // NON_ALPHANUMERIC errs toward encoding, which servers always accept.
    fields
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent_encode(k.as_bytes(), NON_ALPHANUMERIC),
                percent_encode(v.as_bytes(), NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_ignores_path_and_credentials() {
        let a = Url::parse("http://user:pw@example.test:8080/a/b?x=1#f").unwrap();
        let b = Url::parse("http://example.test:8080/c").unwrap();
        assert_eq!(origin_of(&a), origin_of(&b));
        let c = Url::parse("http://example.test:9090/c").unwrap();
        assert_ne!(origin_of(&a), origin_of(&c));
    }

    #[test]
    fn curl_repro_covers_get_and_post() {
        let get = RequestRecord {
            method: "GET".into(),
            url: "http://h/t?q=1".into(),
            body: String::new(),
        };
        assert_eq!(get.as_curl(), "curl -i 'http://h/t?q=1'");
        let post = RequestRecord {
            method: "POST".into(),
            url: "http://h/login".into(),
            body: "u=a&p=b".into(),
        };
        assert_eq!(
            post.as_curl(),
            "curl -i -X POST --data 'u=a&p=b' 'http://h/login'"
        );
    }

    #[test]
    fn form_encoding_escapes_reserved_characters() {
        let body = encode_form(&[("q".into(), "a b&c".into()), ("x".into(), "<svg>".into())]);
        assert_eq!(body, "q=a%20b%26c&x=%3Csvg%3E");
    }
}
