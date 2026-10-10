//! Stored (persistent) cross-site scripting.
//!
//! Reflected XSS shows up in the same response that carries the payload; a
//! stored one is saved by the application and served later, to anyone who
//! views the page. This check works in two phases. First it plants a uniquely
//! marked payload through every input. Then it re-fetches the site's GET pages
//! at their baseline values — with no payload in the request — and reports a
//! marker that comes back verbatim: the only way it can appear in a clean
//! response is that the application stored it. The dangerous characters must
//! survive unescaped, exactly as in the reflected check, so an escaped copy is
//! not flagged. These checks write data, so they run only with active checks
//! enabled. Test only a site you are authorized to.

use crate::http::Client;
use crate::{Finding, InjectionPoint, Severity};
use std::collections::HashSet;
use url::Url;

/// The dangerous tail; it survives intact only if nothing was escaped.
const TAIL: &str = "\"'><svg/onload=alert(1)>";
/// Prefix shared by every planted marker, so observation can skip a page fast.
const PREFIX: &str = "socxst";

/// One payload planted through one input, tracked so a later sighting can be
/// traced back to where it was submitted.
struct Mark {
    /// The full planted string, including the unescaped tail.
    payload: String,
    /// Parameter the payload went into.
    param: String,
    /// Human description of the request that stored it, e.g. `POST /comment`.
    origin: String,
}

pub fn check(
    client: &Client,
    points: &[InjectionPoint],
    observe_urls: &[Url],
    findings: &mut Vec<Finding>,
) {
    // Keep enough budget to re-fetch every observation page after planting.
    let observe_pages = observe_urls.len() as u32;

    // Phase 1: plant a uniquely marked payload through each parameter.
    let mut marks: Vec<Mark> = Vec::new();
    'plant: for (pi, point) in points.iter().enumerate() {
        let origin = format!("{} {}", point.method.as_str(), point.url.path());
        for ai in 0..point.params.len() {
            if client.remaining() <= observe_pages {
                break 'plant;
            }
            let marker = format!("{PREFIX}{pi}z{ai}");
            let payload = format!("{marker}{TAIL}");
            if point.send(client, Some(ai), &payload).is_ok() {
                marks.push(Mark {
                    payload,
                    param: point.params[ai].0.clone(),
                    origin: origin.clone(),
                });
            }
        }
    }
    if marks.is_empty() {
        return;
    }

    // Phase 2: re-fetch each GET page at its baseline and look for a planted
    // payload surfacing. A marker reported once, at the first page it is seen.
    let mut reported: HashSet<usize> = HashSet::new();
    let mut fetched: HashSet<String> = HashSet::new();

    for url in observe_urls {
        if client.remaining() == 0 || reported.len() == marks.len() {
            break;
        }
        if !fetched.insert(url.as_str().to_string()) {
            continue;
        }
        let Ok(resp) = client.get(url) else { continue };
        // A marker-free page cannot hold any planted payload; skip the scan.
        if !resp.body.contains(PREFIX) {
            continue;
        }
        for (i, mark) in marks.iter().enumerate() {
            if reported.contains(&i) || !resp.body.contains(&mark.payload) {
                continue;
            }
            reported.insert(i);
            findings.push(stored_finding(mark, &resp.url, &resp.body));
        }
    }
}

/// Builds the finding for a planted payload seen on a page it was not sent to.
fn stored_finding(mark: &Mark, page_url: &str, body: &str) -> Finding {
    Finding {
        rule: "stored-xss".into(),
        cwe: 79,
        severity: Severity::High,
        title: "Хранимый XSS".into(),
        message: format!(
            "Значение, отправленное через «{}» ({}), сохранилось и возвращается на этой странице без экранирования — внедрённый тег <svg onload> попал в ответ как есть. Такой скрипт выполнится в браузере каждого, кто откроет страницу, не переходя ни по какой ссылке. Экранируйте сохранённые данные при выводе по контексту (HTML, атрибут, JS) или применяйте автоэкранирование шаблонизатора.",
            mark.param, mark.origin
        ),
        url: page_url.to_string(),
        method: "GET".into(),
        param: Some(mark.param.clone()),
        evidence: format!("Сохранено через {}; всплыло здесь: {}", mark.origin, snippet(body, &mark.payload)),
        request: format!("curl -i '{page_url}'"),
        request_detail: crate::http::RequestRecord {
            method: "GET".into(),
            url: page_url.to_string(),
            body: String::new(),
            content_type: None,
        },
    }
}

/// A short window of the body around the payload, for the report.
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
