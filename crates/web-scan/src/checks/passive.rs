//! Weaknesses visible in a response without sending a payload: missing
//! security headers, cookies without protective flags, and software versions
//! disclosed in headers. These describe how the application is served rather
//! than a single injectable parameter, so each is reported once for the site.

use crate::http::{Client, RequestRecord, Response};
use crate::{Finding, Severity};
use url::Url;

pub fn check(base: &Url, resp: &Response, client: &Client, findings: &mut Vec<Finding>) {
    let https = base.scheme() == "https";
    let record = RequestRecord {
        method: "GET".into(),
        url: base.to_string(),
        body: String::new(),
    };
    let one = |rule: &str,
               cwe: u32,
               severity: Severity,
               title: &str,
               message: String,
               evidence: String|
     -> Finding {
        Finding {
            rule: rule.into(),
            cwe,
            severity,
            title: title.into(),
            message,
            url: base.to_string(),
            method: "GET".into(),
            param: None,
            evidence,
            request: record.as_curl(),
            request_detail: record.clone(),
        }
    };

    let csp = resp.header("content-security-policy");
    if csp.is_none() {
        findings.push(one(
            "missing-csp",
            693,
            Severity::Low,
            "Нет Content-Security-Policy",
            "У страниц нет заголовка Content-Security-Policy, который ограничивает, откуда грузятся скрипты и ресурсы. Это последний рубеж против XSS и внедрения чужих ресурсов. Задайте политику, начав с запрета inline-скриптов.".into(),
            "Заголовок Content-Security-Policy отсутствует".into(),
        ));
    }

    let framing_protected = resp.header("x-frame-options").is_some()
        || csp
            .map(|c| c.to_lowercase().contains("frame-ancestors"))
            .unwrap_or(false);
    if !framing_protected {
        findings.push(one(
            "clickjacking",
            1021,
            Severity::Medium,
            "Нет защиты от кликджекинга",
            "Нет ни X-Frame-Options, ни frame-ancestors в CSP: страницу можно встроить в чужой сайт в скрытый фрейм и обманом собирать клики жертвы. Добавьте X-Frame-Options: DENY или frame-ancestors 'self'.".into(),
            "Нет X-Frame-Options и frame-ancestors".into(),
        ));
    }

    if resp
        .header("x-content-type-options")
        .map(|v| !v.to_lowercase().contains("nosniff"))
        .unwrap_or(true)
    {
        findings.push(one(
            "no-sniff-missing",
            16,
            Severity::Low,
            "Нет X-Content-Type-Options",
            "Нет заголовка X-Content-Type-Options: nosniff: браузер может угадать тип ответа и выполнить как скрипт то, что задумано данными. Добавьте nosniff ко всем ответам.".into(),
            "Нет X-Content-Type-Options: nosniff".into(),
        ));
    }

    if https && resp.header("strict-transport-security").is_none() {
        findings.push(one(
            "hsts-missing",
            319,
            Severity::Low,
            "Нет HSTS",
            "Сайт по HTTPS не присылает Strict-Transport-Security, поэтому первый заход по http и активная атака способны понизить соединение. Добавьте HSTS с достаточным max-age.".into(),
            "Нет Strict-Transport-Security".into(),
        ));
    }

    cookies(resp, https, base, &record, findings);
    versions(resp, base, &record, findings);
    // Cookies set on earlier responses (e.g. the login) are checked too.
    for raw in client.set_cookie_headers() {
        cookie_flags(&raw, https, base, &record, findings);
    }
}

fn cookies(
    resp: &Response,
    https: bool,
    base: &Url,
    record: &RequestRecord,
    findings: &mut Vec<Finding>,
) {
    for raw in resp.headers_all("set-cookie") {
        cookie_flags(raw, https, base, record, findings);
    }
}

/// Judges one `Set-Cookie` value and, when a protective flag is missing,
/// appends a finding keyed by the cookie's name (deduped later).
fn cookie_flags(
    raw: &str,
    https: bool,
    base: &Url,
    record: &RequestRecord,
    findings: &mut Vec<Finding>,
) {
    let name = raw.split('=').next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return;
    }
    let lower = raw.to_lowercase();
    let session_like = ["sess", "sid", "auth", "token", "jwt", "login", "csrf"]
        .iter()
        .any(|k| name.to_lowercase().contains(k));
    let mut missing = Vec::new();
    if !lower.contains("httponly") {
        missing.push("HttpOnly");
    }
    if https && !lower.contains("secure") {
        missing.push("Secure");
    }
    if !lower.contains("samesite") {
        missing.push("SameSite");
    }
    if missing.is_empty() {
        return;
    }
    // A session cookie reachable from JS (no HttpOnly) is the worst case.
    let severity = if session_like && missing.contains(&"HttpOnly") {
        Severity::Medium
    } else {
        Severity::Low
    };
    findings.push(Finding {
        rule: "cookie-flags".into(),
        cwe: 1004,
        severity,
        title: "Cookie без защитных флагов".into(),
        message: format!(
            "Cookie «{name}» выставлена без флагов: {}. Без HttpOnly её читает скрипт при XSS, без Secure она уходит по открытому HTTP, без SameSite её шлют при межсайтовых запросах (CSRF). Добавьте недостающие флаги{}.",
            missing.join(", "),
            if session_like { ", особенно для сессионной cookie" } else { "" }
        ),
        url: base.to_string(),
        method: "GET".into(),
        param: Some(name),
        evidence: format!("Set-Cookie: {}", raw.split(';').next().unwrap_or(raw).trim()),
        request: record.as_curl(),
        request_detail: record.clone(),
    });
}

/// Server/X-Powered-By headers that reveal a product and version.
fn versions(resp: &Response, base: &Url, record: &RequestRecord, findings: &mut Vec<Finding>) {
    for header in ["server", "x-powered-by", "x-aspnet-version"] {
        if let Some(value) = resp.header(header) {
            // Only interesting when a version number is present.
            if value.chars().any(|c| c.is_ascii_digit()) && value.len() <= 120 {
                findings.push(Finding {
                    rule: "version-disclosure".into(),
                    cwe: 200,
                    severity: Severity::Low,
                    title: "Раскрыта версия ПО".into(),
                    message: format!(
                        "Заголовок {header} называет версию серверного ПО ({value}). По ней подбирают известные уязвимости именно этой версии. Скройте версию в настройках сервера или фреймворка."
                    ),
                    url: base.to_string(),
                    method: "GET".into(),
                    param: None,
                    evidence: format!("{header}: {value}"),
                    request: record.as_curl(),
                    request_detail: record.clone(),
                });
            }
        }
    }
}
