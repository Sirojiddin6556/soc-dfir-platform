//! SQL injection surfaced by a database error.
//!
//! The check first fetches the point at its baseline value, then with a single
//! quote appended. It reports only when a database error signature appears in
//! the quoted response but not the baseline one, so a page that always prints
//! the word "SQL" is not flagged. Error-based detection is conservative: it
//! misses blind injection but almost never fires falsely.

use crate::http::Client;
use crate::{Finding, InjectionPoint, Severity};
use regex::Regex;
use std::sync::OnceLock;

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
    // Baseline: the point as crawled. A DB error already here is the app's,
    // not ours, so it must not count toward a finding.
    let baseline = point.params[index].1.clone();
    let base_err = match point.send(client, Some(index), &baseline) {
        Ok((resp, _)) => first_match(&resp.body),
        Err(_) => return,
    };
    if client.remaining() == 0 {
        return;
    }
    let payload = format!("{baseline}'");
    let Ok((resp, record)) = point.send(client, Some(index), &payload) else {
        return;
    };
    let Some(err) = first_match(&resp.body) else {
        return;
    };
    // Only a *new* error, caused by the quote, is evidence.
    if base_err.as_deref() == Some(err.as_str()) {
        return;
    }
    let name = point.params[index].0.clone();
    findings.push(Finding {
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
    });
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
}
