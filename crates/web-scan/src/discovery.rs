//! Content discovery: finding paths the site links to nowhere.
//!
//! A single-page app serves one HTML shell and all its real surface lives at
//! API paths no `<a>` points to, so the crawler alone sees one page. This
//! module brute-forces a built-in list of common paths — as a tool like ffuf
//! does — and returns the ones that answer, to seed the crawl and the checks.
//!
//! The hard part is a site that returns `200` for *every* path (the SPA shell,
//! or a soft "not found" page). To avoid taking those as real, the scan first
//! requests a random path that cannot exist and remembers that response; a
//! candidate counts only when its answer differs from that baseline, or when
//! the status itself proves the path exists (`401`/`403`/`405`).

use crate::http::{Client, Response};
use crate::Options;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// Common paths worth probing: admin and auth surfaces, API roots and their
/// documentation, health and metrics endpoints, and files that leak when
/// present. Kept deliberately broad but finite.
const WORDLIST: &[&str] = &[
    // Auth and accounts.
    "admin",
    "administrator",
    "login",
    "logout",
    "signin",
    "sign-in",
    "signup",
    "register",
    "auth",
    "oauth",
    "oauth2",
    "token",
    "session",
    "sso",
    "account",
    "accounts",
    "profile",
    "user",
    "users",
    "me",
    "password",
    "reset",
    "forgot-password",
    // API roots and versions.
    "api",
    "api/v1",
    "api/v2",
    "api/v3",
    "v1",
    "v2",
    "v3",
    "rest",
    "graphql",
    "graphiql",
    "api/users",
    "api/user",
    "api/login",
    "api/auth",
    "api/admin",
    "api/config",
    "api/health",
    "api/status",
    "api/me",
    "api/token",
    "api/data",
    "api/search",
    "api/orders",
    "api/products",
    // API documentation / specs.
    "openapi.json",
    "swagger.json",
    "swagger",
    "swagger-ui",
    "swagger-ui.html",
    "api-docs",
    "v2/api-docs",
    "v3/api-docs",
    "api/openapi.json",
    "api/swagger.json",
    "docs",
    "redoc",
    // Operations and health.
    "health",
    "healthz",
    "readyz",
    "livez",
    "status",
    "ping",
    "metrics",
    "actuator",
    "actuator/health",
    "actuator/env",
    "actuator/metrics",
    "server-status",
    "monitor",
    "monitoring",
    "stats",
    "version",
    "info",
    "debug",
    // Dashboards and admin tools.
    "dashboard",
    "console",
    "manager",
    "portal",
    "settings",
    "setup",
    "install",
    "config",
    "configuration",
    "grafana",
    "prometheus",
    "kibana",
    "alerts",
    "nodes",
    "services",
    "agents",
    "events",
    "tasks",
    "jobs",
    "queue",
    "reports",
    "report",
    // Content and data.
    "search",
    "export",
    "import",
    "upload",
    "uploads",
    "files",
    "file",
    "download",
    "data",
    "db",
    "backup",
    "backups",
    "logs",
    "log",
    "static",
    "assets",
    "media",
    "images",
    "img",
    "products",
    "product",
    "orders",
    "order",
    "items",
    "customers",
    "messages",
    "notifications",
    // Files that disclose when exposed.
    ".env",
    ".git/config",
    ".git/HEAD",
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.json",
    "appsettings.json",
    "web.config",
    "phpinfo.php",
    "info.php",
    "test.php",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "dump.sql",
    "database.sql",
    "backup.zip",
    "wp-login.php",
    "wp-admin",
    "wp-json",
];

/// A compact signature of a response: its status, the broad kind of its body,
/// and the body length, to tell a real answer from the catch-all baseline.
struct Fingerprint {
    status: u16,
    kind: BodyKind,
    len: usize,
}

#[derive(PartialEq, Eq)]
enum BodyKind {
    Html,
    Json,
    Other,
}

fn body_kind(resp: &Response) -> BodyKind {
    match resp.header("content-type") {
        Some(ct) if ct.to_lowercase().contains("json") => BodyKind::Json,
        Some(ct) if ct.to_lowercase().contains("html") => BodyKind::Html,
        _ => BodyKind::Other,
    }
}

fn fingerprint(resp: &Response) -> Fingerprint {
    Fingerprint {
        status: resp.status,
        kind: body_kind(resp),
        len: resp.body.len(),
    }
}

/// Whether a probe's response means the path really exists, given the baseline
/// seen for a path that cannot.
fn exists(baseline: &Fingerprint, resp: &Response) -> bool {
    let fp = fingerprint(resp);
    if fp.status == 404 {
        return false;
    }
    // A protected or method-mismatched path exists even without a body.
    if matches!(fp.status, 401 | 403 | 405) {
        return true;
    }
    if fp.status != baseline.status {
        return true;
    }
    // Same status as the "not found" baseline: a different body shape or a
    // meaningfully different length marks a real, distinct resource.
    fp.kind != baseline.kind || fp.len.abs_diff(baseline.len) > 24
}

/// The site root to probe from, regardless of the path the operator entered.
fn root(base: &Url) -> Url {
    let mut r = base.clone();
    r.set_path("/");
    r.set_query(None);
    r.set_fragment(None);
    r
}

/// Probes the word list against `base`'s origin and returns the same-origin
/// URLs that answered, to seed the crawl. Leaves a quarter of the request
/// budget for the checks that follow.
pub fn discover(
    client: &Client,
    base: &Url,
    options: &Options,
    notes: &mut Vec<String>,
) -> Vec<Url> {
    let root = root(base);
    let reserve = options.max_requests / 4;

    // Calibrate against a path that cannot exist.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = match root.join(&format!("soc-discovery-{nonce:x}-zzz")) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let baseline = match client.get(&probe) {
        Ok(resp) => fingerprint(&resp),
        Err(_) => return Vec::new(),
    };

    let mut found = Vec::new();
    for word in WORDLIST {
        if client.remaining() <= reserve {
            notes.push("Перебор путей остановлен ради запаса запросов на проверки".into());
            break;
        }
        let Ok(url) = root.join(word) else { continue };
        if !client.same_origin(&url) {
            continue;
        }
        if let Ok(resp) = client.get(&url) {
            if exists(&baseline, &resp) {
                found.push(url);
            }
        }
    }

    if !found.is_empty() {
        notes.push(format!("Перебор путей нашёл адресов: {}", found.len()));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, ct: &str, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), ct.into())],
            body: body.into(),
            url: "http://h/x".into(),
        }
    }

    #[test]
    fn spa_catch_all_is_not_treated_as_found() {
        // Every unknown path returns the same HTML shell.
        let shell = resp(
            200,
            "text/html",
            "<html><body><div id=app></div></body></html>",
        );
        let baseline = fingerprint(&shell);
        // A path that returns the identical shell is not a real endpoint.
        assert!(!exists(&baseline, &shell));
    }

    #[test]
    fn differing_responses_are_found() {
        let baseline = fingerprint(&resp(200, "text/html", "<html>shell shell shell</html>"));
        // A JSON API answer differs in kind.
        assert!(exists(
            &baseline,
            &resp(200, "application/json", "{\"ok\":true}")
        ));
        // A protected path exists even with the same body kind.
        assert!(exists(&baseline, &resp(401, "text/html", "")));
        // A 405 means the path exists but wants another method.
        assert!(exists(&baseline, &resp(405, "text/html", "")));
        // A genuine 404 is not a hit.
        assert!(!exists(&baseline, &resp(404, "text/html", "nope")));
    }
}
