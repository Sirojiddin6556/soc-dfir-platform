//! Path traversal — reading a file outside the intended directory.
//!
//! Only parameters that plausibly name a file are tested, to keep the scan
//! quiet. The check injects a climb to a well-known system file and reports
//! only on that file's unmistakable contents, so a page that merely echoes
//! the path is not flagged.

use crate::http::Client;
use crate::{Finding, InjectionPoint, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// A `/etc/passwd` line or a `win.ini` section proves the file was read.
fn evidence_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?im)^root:.*:0:0:|\[fonts\]|\[extensions\]|for 16-bit app support")
            .expect("traversal evidence regex")
    })
}

/// Whether a parameter is worth testing: its name or value hints at a file.
fn looks_file_like(name: &str, value: &str) -> bool {
    let name = name.to_lowercase();
    const HINTS: &[&str] = &[
        "file",
        "path",
        "page",
        "doc",
        "document",
        "template",
        "tpl",
        "include",
        "inc",
        "dir",
        "folder",
        "load",
        "read",
        "download",
        "name",
        "view",
        "img",
        "image",
        "photo",
        "attachment",
        "item",
        "conf",
        "config",
        "lang",
        "locale",
    ];
    if HINTS.iter().any(|h| name.contains(h)) {
        return true;
    }
    let v = value.to_lowercase();
    v.contains('/') || v.contains('\\') || v.contains('.') && v.len() <= 64
}

pub fn check(client: &Client, point: &InjectionPoint, index: usize, findings: &mut Vec<Finding>) {
    let (name, value) = point.params[index].clone();
    if !looks_file_like(&name, &value) {
        return;
    }
    const PAYLOADS: &[&str] = &[
        "../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    ];
    for payload in PAYLOADS {
        if client.remaining() == 0 {
            return;
        }
        let Ok((resp, record)) = point.send(client, Some(index), payload) else {
            continue;
        };
        if let Some(m) = evidence_re().find(&resp.body) {
            findings.push(Finding {
                rule: "path-traversal".into(),
                cwe: 22,
                severity: Severity::High,
                title: "Обход каталога".into(),
                message: format!(
                    "Параметр «{name}» позволяет выйти за пределы папки и прочитать произвольный файл: в ответ попало содержимое системного файла. Так читают конфигурацию и секреты. Не стройте путь из ввода: сопоставляйте его с белым списком и запрещайте «..»."
                ),
                url: record.url.clone(),
                method: point.method.as_str().into(),
                param: Some(name),
                evidence: format!("В ответе содержимое файла: {}", m.as_str().trim()),
                request: record.as_curl(),
                request_detail: record,
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_file_like_parameters_are_tested() {
        assert!(looks_file_like("page", ""));
        assert!(looks_file_like("include", ""));
        assert!(looks_file_like("q", "report.pdf"));
        assert!(looks_file_like("x", "a/b/c"));
        assert!(!looks_file_like("token", "abcdef"));
        assert!(!looks_file_like("id", "42"));
    }

    #[test]
    fn evidence_matches_passwd_and_win_ini() {
        assert!(evidence_re().is_match("root:x:0:0:root:/root:/bin/bash"));
        assert!(evidence_re().is_match("; for 16-bit app support\n[fonts]"));
        assert!(!evidence_re().is_match("nothing to see here"));
    }
}
