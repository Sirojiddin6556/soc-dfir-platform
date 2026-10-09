//! Reflected cross-site scripting.
//!
//! The check sends a marker carrying HTML-significant characters into one
//! parameter and reports only when those characters come back verbatim in an
//! HTML response — i.e. the application did not escape them, so a script the
//! marker stands for would run. Because the dangerous sequence is distinctive,
//! an escaped reflection (`&lt;svg…`) does not match and is not reported.

use crate::http::Client;
use crate::{Finding, InjectionPoint, Severity};

/// Marker that precedes the payload so a reflection is unmistakably ours.
const MARKER: &str = "socx9173";
/// The dangerous tail; it only survives intact if nothing was escaped.
const TAIL: &str = "\"'><svg/onload=alert(1)>";

pub fn check(client: &Client, point: &InjectionPoint, index: usize, findings: &mut Vec<Finding>) {
    let payload = format!("{MARKER}{TAIL}");
    let Ok((resp, record)) = point.send(client, Some(index), &payload) else {
        return;
    };
    if !super::is_html(&resp) {
        return;
    }
    // The whole payload, including the characters that must stay unescaped.
    let needle = format!("{MARKER}{TAIL}");
    if !resp.body.contains(&needle) {
        return;
    }
    let name = point.params[index].0.clone();
    findings.push(Finding {
        rule: "reflected-xss".into(),
        cwe: 79,
        severity: Severity::High,
        title: "Отражённый XSS".into(),
        message: format!(
            "Значение параметра «{name}» возвращается на страницу без экранирования: внедрённый тег <svg onload> попал в ответ как есть. Злоумышленник сможет выполнить свой скрипт в браузере жертвы по ссылке. Экранируйте вывод по контексту (HTML, атрибут, JS) или примените автоэкранирование шаблонизатора."
        ),
        url: record.url.clone(),
        method: point.method.as_str().into(),
        param: Some(name),
        evidence: snippet(&resp.body, &needle),
        request: record.as_curl(),
        request_detail: record,
    });
}

/// A short window of the body around the reflected payload, for the report.
fn snippet(body: &str, needle: &str) -> String {
    let Some(pos) = body.find(needle) else {
        return needle.to_string();
    };
    let start = body[..pos]
        .char_indices()
        .rev()
        .nth(30)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let end = (pos + needle.len() + 20).min(body.len());
    let end = body[..end]
        .char_indices()
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(end);
    body[start..end].replace(['\n', '\r'], " ")
}
