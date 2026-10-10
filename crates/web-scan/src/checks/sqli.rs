//! SQL injection, surfaced two ways.
//!
//! First, error-based: the point is fetched at its baseline value and again
//! with a single quote appended; a database error that appears only in the
//! quoted response is evidence. This is conservative — it misses injection
//! that shows no error — but it almost never fires falsely.
//!
//! When the error-based step finds nothing, a time-based blind step runs. It
//! asks the database to sleep for a few seconds through the parameter and
//! measures the response time. To avoid blaming a slow endpoint, it compares
//! the delayed request against the same payload with a zero-second sleep (a
//! control) and confirms the delay a second time: only a response that is
//! consistently slower than its own control by about the requested delay is
//! reported. These checks are for authorized testing of systems the operator
//! controls.

use crate::http::{Client, RequestRecord, Response};
use crate::{Finding, InjectionPoint, Severity};
use regex::Regex;
use std::sync::OnceLock;
use std::time::Instant;

/// Signatures of a database complaining about broken SQL, across engines.
fn signatures() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(you have an error in your sql syntax|warning:\s*mysqli?|unclosed quotation mark after the character string|quoted string not properly terminated|microsoft ole db provider for sql server|odbc sql server driver|sqlstate\[|org\.postgresql\.util\.psqlexception|psqlexception|syntax error at or near|pg_query\(\)|unterminated quoted string|sqlite3?::|sqlite3\.operationalerror|sqlite error|unrecognized token|near \".*\": syntax error|ora-0[0-9]{4}|oracle error|system\.data\.sqlclient|sqlalchemy\.exc\.|org\.hibernate|jdbc|db2 sql error)"#,
        )
        .expect("sqli signature regex")
    })
}

/// The first signature match in `body`, if any.
fn first_match(body: &str) -> Option<String> {
    signatures()
        .find(body)
        .map(|m| m.as_str().trim().to_string())
}

pub fn check(client: &Client, point: &InjectionPoint, index: usize, findings: &mut Vec<Finding>) {
    if let Some(f) = error_based(client, point, index) {
        findings.push(f);
        return;
    }
    // Boolean-based next: it is cheap (no waiting) and often enough, so the
    // slow time-based probe runs only when it too comes up empty.
    if let Some(f) = boolean_based(client, point, index) {
        findings.push(f);
        return;
    }
    if let Some(f) = time_based(client, point, index) {
        findings.push(f);
    }
}

/// Reports injection shown by a fresh database error on a stray quote.
fn error_based(client: &Client, point: &InjectionPoint, index: usize) -> Option<Finding> {
    // Baseline: the point as crawled. A DB error already here is the app's,
    // not ours, so it must not count toward a finding.
    let baseline = point.params[index].1.clone();
    let base_err = match point.send(client, Some(index), &baseline) {
        Ok((resp, _)) => first_match(&resp.body),
        Err(_) => return None,
    };
    if client.remaining() == 0 {
        return None;
    }
    let payload = format!("{baseline}'");
    let (resp, record) = point.send(client, Some(index), &payload).ok()?;
    let err = first_match(&resp.body)?;
    // Only a *new* error, caused by the quote, is evidence.
    if base_err.as_deref() == Some(err.as_str()) {
        return None;
    }
    let name = point.params[index].0.clone();
    Some(Finding {
        rule: "sql-injection".into(),
        cwe: 89,
        severity: Severity::Critical,
        title: "SQL-инъекция".into(),
        message: format!(
            "Одиночная кавычка в параметре «{name}» вызвала ошибку базы данных: значение попадает в SQL-запрос без параметризации. Так можно прочитать или изменить чужие данные. Используйте подготовленные выражения (параметры запроса), а не склейку строк."
        ),
        url: record.url.clone(),
        method: point.method.as_str().into(),
        param: Some(name),
        evidence: format!("Ошибка БД в ответе: {err}"),
        request: record.as_curl(),
        request_detail: record,
    })
}

/// Pairs of (true, false) conditions appended to the baseline value. Each
/// relies on the query's own closing quote (string context) or needs none
/// (numeric), so no comment terminator is required.
fn boolean_pairs(base: &str) -> [(String, String); 2] {
    [
        (format!("{base}' AND '1'='1"), format!("{base}' AND '1'='2")),
        (format!("{base} AND 1=1"), format!("{base} AND 1=2")),
    ]
}

/// Two responses are "close" when the server answered the same way and the
/// bodies are within 2% in length — tolerant of small volatility, strict
/// enough that a true/false branch with different content reads as "far".
fn close(a: &Response, b: &Response) -> bool {
    if a.status != b.status {
        return false;
    }
    let (la, lb) = (a.body.len(), b.body.len());
    let (lo, hi) = (la.min(lb), la.max(lb));
    hi == 0 || lo as f64 / hi as f64 >= 0.98
}

/// Reports injection shown by the parameter steering a boolean condition: a
/// true condition answers like the baseline, a false one answers differently.
fn boolean_based(client: &Client, point: &InjectionPoint, index: usize) -> Option<Finding> {
    let base = point.params[index].1.clone();
    let (baseline, _) = point.send(client, Some(index), &base).ok()?;
    for (true_cond, false_cond) in boolean_pairs(&base) {
        if client.remaining() < 4 {
            return None;
        }
        let (t, _) = point.send(client, Some(index), &true_cond).ok()?;
        let (f, _) = point.send(client, Some(index), &false_cond).ok()?;
        // The true branch must track the baseline while the false branch
        // diverges from both — the signature of a condition we control.
        if !(close(&baseline, &t) && !close(&baseline, &f) && !close(&t, &f)) {
            continue;
        }
        // Confirm the same relationship a second time, so a one-off difference
        // (a rotating ad, a timestamp) does not masquerade as injection.
        let (t2, _) = point.send(client, Some(index), &true_cond).ok()?;
        let (f2, record) = point.send(client, Some(index), &false_cond).ok()?;
        if !(close(&baseline, &t2) && !close(&baseline, &f2) && !close(&t2, &f2)) {
            continue;
        }
        let name = point.params[index].0.clone();
        return Some(Finding {
            rule: "sql-injection".into(),
            cwe: 89,
            severity: Severity::Critical,
            title: "SQL-инъекция".into(),
            message: format!(
                "Параметр «{name}» управляет логическим условием в SQL-запросе: при истинном условии ответ совпадает с обычным, при ложном — отличается. Значит, значение попадает в запрос без параметризации, даже если ошибка и задержка не видны (слепая инъекция по ответу). Так можно по одному биту вытащить чужие данные. Используйте подготовленные выражения (параметры запроса)."
            ),
            url: record.url.clone(),
            method: point.method.as_str().into(),
            param: Some(name),
            evidence: format!(
                "Условие по ответу: истинное «AND 1=1» дало {} байт (как обычный ответ), ложное «AND 1=2» — {} байт.",
                t2.body.len(),
                f2.body.len()
            ),
            request: record.as_curl(),
            request_detail: record,
        });
    }
    None
}

/// Seconds the probe asks the database to sleep.
const DELAY: u32 = 3;
/// A delayed response must take at least this long to be a candidate.
const THRESHOLD: f64 = DELAY as f64 * 0.6;
/// A candidate is confirmed only if it beats its own zero-second control by
/// at least this much, which cancels a uniformly slow endpoint.
const MARGIN: f64 = DELAY as f64 * 0.5;
/// The time-based step needs this many requests free to confirm one payload
/// (one delayed, one control, one delayed again).
const CONFIRM_BUDGET: u32 = 3;

/// Payloads that make a vulnerable query sleep `secs` seconds, one per common
/// engine and query context. The same list with `secs = 0` is the control.
fn sleep_payloads(base: &str, secs: u32) -> Vec<(&'static str, String)> {
    vec![
        ("MySQL", format!("{base}' AND SLEEP({secs})-- -")),
        ("MySQL", format!("{base} AND SLEEP({secs})-- -")),
        (
            "PostgreSQL",
            format!("{base}' AND (SELECT 1 FROM PG_SLEEP({secs})) IS NOT NULL-- -"),
        ),
        (
            "MS SQL Server",
            format!("{base}';WAITFOR DELAY '0:0:{secs}'-- -"),
        ),
    ]
}

/// Sends one payload and times the whole round trip, including reading the
/// body. `None` on a transport error so the caller moves on.
fn timed(
    client: &Client,
    point: &InjectionPoint,
    index: usize,
    payload: &str,
) -> Option<(Response, RequestRecord, f64)> {
    let start = Instant::now();
    let (resp, record) = point.send(client, Some(index), payload).ok()?;
    Some((resp, record, start.elapsed().as_secs_f64()))
}

/// Reports injection shown by the parameter controlling the response time.
fn time_based(client: &Client, point: &InjectionPoint, index: usize) -> Option<Finding> {
    let base = point.params[index].1.clone();
    let slow = sleep_payloads(&base, DELAY);
    let control = sleep_payloads(&base, 0);
    for ((engine, slow_payload), (_, control_payload)) in slow.iter().zip(control.iter()) {
        if client.remaining() < CONFIRM_BUDGET {
            return None;
        }
        // One cheap probe first: a parameter that is not injectable answers
        // fast, so most points cost a single request here and never confirm.
        let (_, _, first) = timed(client, point, index, slow_payload)?;
        if first < THRESHOLD {
            continue;
        }
        // Candidate. Prove the delay is the sleep, not a slow page: the same
        // payload with a zero-second sleep must come back quickly, and a
        // second delayed request must be slow again.
        let (_, _, control_time) = timed(client, point, index, control_payload)?;
        let (_, record, confirm) = timed(client, point, index, slow_payload)?;
        let delayed = first.min(confirm);
        if delayed - control_time >= MARGIN && confirm >= THRESHOLD {
            let name = point.params[index].0.clone();
            return Some(Finding {
                rule: "sql-injection".into(),
                cwe: 89,
                severity: Severity::Critical,
                title: "SQL-инъекция".into(),
                message: format!(
                    "Параметр «{name}» управляет временем ответа базы данных: запрос со «спящей» вставкой ({engine}) выполнялся заметно дольше, чем тот же запрос без задержки. Значит, значение попадает в SQL-запрос без параметризации, даже если ошибка на странице не видна (слепая инъекция). Так можно прочитать или изменить чужие данные. Используйте подготовленные выражения (параметры запроса)."
                ),
                url: record.url.clone(),
                method: point.method.as_str().into(),
                param: Some(name),
                evidence: format!(
                    "Задержка по времени ({engine}): с паузой {DELAY}с ответ {delayed:.1}с, без паузы {control_time:.1}с."
                ),
                request: record.as_curl(),
                request_detail: record,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_match_common_engines() {
        assert!(first_match("You have an error in your SQL syntax; check").is_some());
        assert!(first_match("sqlite3.OperationalError: near \"'\": syntax error").is_some());
        assert!(first_match("org.postgresql.util.PSQLException: ERROR").is_some());
        assert!(first_match("ORA-00933: SQL command not properly ended").is_some());
        assert!(first_match("a normal page about SQL databases").is_none());
    }

    #[test]
    fn boolean_pairs_balance_the_quote() {
        let p = boolean_pairs("1");
        assert_eq!(p[0], ("1' AND '1'='1".into(), "1' AND '1'='2".into()));
        assert_eq!(p[1], ("1 AND 1=1".into(), "1 AND 1=2".into()));
    }

    #[test]
    fn close_compares_status_and_length() {
        let mk = |status, body: String| Response {
            status,
            headers: Vec::new(),
            body,
            url: "x".into(),
        };
        let a = mk(200, "x".repeat(100));
        assert!(close(&a, &mk(200, "x".repeat(99)))); // within 2%
        assert!(!close(&a, &mk(200, "x".repeat(50)))); // far shorter
        assert!(!close(&a, &mk(404, "x".repeat(100)))); // different status
    }

    #[test]
    fn a_control_payload_requests_no_sleep() {
        // The zero-second control carries the same shape as the delayed probe,
        // so a non-sleeping reference isolates the sleep as the only variable.
        let control = sleep_payloads("1", 0);
        assert!(control.iter().any(|(_, p)| p.contains("SLEEP(0)")));
        assert!(control.iter().any(|(_, p)| p.contains("0:0:0")));
        let slow = sleep_payloads("1", DELAY);
        assert!(slow.iter().any(|(_, p)| p.contains("SLEEP(3)")));
    }
}
