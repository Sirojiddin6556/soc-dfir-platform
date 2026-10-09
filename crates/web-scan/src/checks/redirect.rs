//! Open redirect — sending the browser to an attacker's address.
//!
//! Parameters that plausibly carry a redirect target are set to an external
//! URL. The check reports when the response sends the browser there: a 3xx
//! `Location` to the outside host, or a meta-refresh / `location =` in the
//! body pointing at it. Because redirects are not followed by the client, the
//! `Location` is visible to read.

use crate::http::Client;
use crate::{Finding, InjectionPoint, Severity};

/// The outside host the payload points at; distinctive so a match is certain.
const MARK: &str = "soc-open-redirect.example";

/// Whether a parameter plausibly holds a redirect destination.
fn looks_redirecty(name: &str, value: &str) -> bool {
    let name = name.to_lowercase();
    const HINTS: &[&str] = &[
        "redirect",
        "redir",
        "url",
        "next",
        "return",
        "returnurl",
        "return_url",
        "dest",
        "destination",
        "continue",
        "goto",
        "go",
        "target",
        "out",
        "link",
        "forward",
        "to",
        "callback",
        "redirect_uri",
        "image_url",
        "checkout_url",
    ];
    if HINTS.iter().any(|h| name == *h || name.contains(h)) {
        return true;
    }
    let v = value.to_lowercase();
    v.starts_with("http://") || v.starts_with("https://") || v.starts_with('/')
}

pub fn check(client: &Client, point: &InjectionPoint, index: usize, findings: &mut Vec<Finding>) {
    let (name, value) = point.params[index].clone();
    if !looks_redirecty(&name, &value) {
        return;
    }
    // Both an absolute and a scheme-relative form; apps block one but not the other.
    for payload in [format!("https://{MARK}/"), format!("//{MARK}/")] {
        if client.remaining() == 0 {
            return;
        }
        let Ok((resp, record)) = point.send(client, Some(index), &payload) else {
            continue;
        };
        let via_header = (300..400).contains(&resp.status)
            && resp
                .header("location")
                .map(location_points_out)
                .unwrap_or(false);
        let via_body = body_redirects_out(&resp.body);
        if via_header || via_body {
            let how = if via_header {
                format!("ответ {} с Location на {MARK}", resp.status)
            } else {
                format!("в теле ответа переход на {MARK}")
            };
            findings.push(Finding {
                rule: "open-redirect".into(),
                cwe: 601,
                severity: Severity::Medium,
                title: "Открытое перенаправление".into(),
                message: format!(
                    "Параметр «{name}» уводит браузер на произвольный внешний адрес. Такой ссылкой маскируют фишинг под ваш домен. Разрешайте переход только на свои адреса или на записи из белого списка, а не на любой URL из запроса."
                ),
                url: record.url.clone(),
                method: point.method.as_str().into(),
                param: Some(name),
                evidence: how,
                request: record.as_curl(),
                request_detail: record,
            });
            return;
        }
    }
}

/// A `Location` that leads to the marker host (absolute or scheme-relative).
fn location_points_out(location: &str) -> bool {
    let l = location.trim().to_lowercase();
    l.starts_with(&format!("https://{MARK}"))
        || l.starts_with(&format!("http://{MARK}"))
        || l.starts_with(&format!("//{MARK}"))
}

/// A meta-refresh or a client-side `location=` to the marker host.
fn body_redirects_out(body: &str) -> bool {
    let b = body.to_lowercase();
    if !b.contains(MARK) {
        return false;
    }
    (b.contains("http-equiv") && b.contains("refresh") && b.contains(MARK))
        || b.contains(&format!("location='https://{MARK}"))
        || b.contains(&format!("location=\"https://{MARK}"))
        || b.contains(&format!("location.href='https://{MARK}"))
        || b.contains(&format!("location.href=\"https://{MARK}"))
        || b.contains(&format!("location = 'https://{MARK}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_catch_redirect_parameters() {
        assert!(looks_redirecty("next", ""));
        assert!(looks_redirecty("returnUrl", ""));
        assert!(looks_redirecty("q", "https://x/"));
        assert!(looks_redirecty("q", "/dashboard"));
        assert!(!looks_redirecty("comment", "hello"));
    }

    #[test]
    fn location_and_body_detectors() {
        assert!(location_points_out("https://soc-open-redirect.example/"));
        assert!(location_points_out("//soc-open-redirect.example/x"));
        assert!(!location_points_out("/local/path"));
        assert!(body_redirects_out(
            "<meta http-equiv=\"refresh\" content=\"0;url=https://soc-open-redirect.example/\">"
        ));
        assert!(!body_redirects_out("<p>no redirect here</p>"));
    }
}
