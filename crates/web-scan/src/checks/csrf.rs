//! Missing cross-site request forgery protection on state-changing forms.
//!
//! A POST form that carries no anti-CSRF token can be submitted by another
//! site on the victim's behalf, because the browser attaches the session
//! cookie automatically. This check is passive: it reads the forms the crawl
//! already found and flags a POST one whose fields hold nothing token-like. It
//! stays quiet when every cookie the site set is `SameSite=Lax`/`Strict`,
//! since the browser then withholds the cookie on a cross-site POST and the
//! forged request arrives unauthenticated.

use crate::{Finding, InjectionPoint, Method, Severity};

/// Whether a field name looks like an anti-CSRF token. Broad on purpose: any
/// token-bearing field means the form has some protection, so we do not flag.
fn looks_like_token(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("csrf")
        || n.contains("xsrf")
        || n.contains("token")
        || n.contains("authenticity")
        || n.contains("nonce")
        || n.contains("verification")
}

/// Whether a raw `Set-Cookie` value pins the cookie to same-site requests.
fn same_site(raw: &str) -> bool {
    let r = raw.to_ascii_lowercase();
    r.contains("samesite=lax") || r.contains("samesite=strict")
}

pub fn check(points: &[InjectionPoint], set_cookies: &[String], findings: &mut Vec<Finding>) {
    // If every cookie the site set is same-site, a cross-site POST carries no
    // session and cannot forge an authenticated action: nothing to report.
    if !set_cookies.is_empty() && set_cookies.iter().all(|c| same_site(c)) {
        return;
    }

    for point in points.iter().filter(|p| p.method == Method::Post) {
        if point.params.iter().any(|(name, _)| looks_like_token(name)) {
            continue;
        }
        let fields: Vec<&str> = point.params.iter().map(|(n, _)| n.as_str()).collect();
        findings.push(Finding {
            rule: "csrf".into(),
            cwe: 352,
            severity: Severity::Medium,
            title: "Нет защиты от CSRF".into(),
            message:
                "Форма отправляется методом POST и меняет состояние, но не содержит анти-CSRF-токена. Чужой сайт сможет отправить такой запрос от имени вошедшего пользователя — браузер сам приложит cookie сессии. Добавьте в форму скрытый одноразовый токен и проверяйте его на сервере, либо выставьте сессионной cookie атрибут SameSite=Lax или Strict."
                    .into(),
            url: point.url.to_string(),
            method: "POST".into(),
            param: None,
            evidence: format!("Поля формы без токена: {}", fields.join(", ")),
            request: format!("curl -i -X POST '{}'", point.url),
            request_detail: crate::http::RequestRecord {
                method: "POST".into(),
                url: point.url.to_string(),
                body: String::new(),
                content_type: Some("application/x-www-form-urlencoded".into()),
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_names_are_recognised() {
        for n in [
            "csrf_token",
            "_token",
            "authenticity_token",
            "csrfmiddlewaretoken",
            "__RequestVerificationToken",
            "xsrfToken",
        ] {
            assert!(looks_like_token(n), "{n} should look like a token");
        }
        assert!(!looks_like_token("username"));
        assert!(!looks_like_token("bio"));
    }

    #[test]
    fn same_site_cookie_detected() {
        assert!(same_site("sid=1; Path=/; SameSite=Lax"));
        assert!(same_site("sid=1; samesite=strict"));
        assert!(!same_site("sid=1; Path=/"));
        assert!(!same_site("sid=1; SameSite=None"));
    }
}
