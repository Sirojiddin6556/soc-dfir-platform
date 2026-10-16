//! Pulling links and forms out of an HTML page.
//!
//! This is regex extraction, not a full parser: it is enough to drive a
//! crawler and to find the inputs a form offers. It tolerates the malformed
//! markup real sites serve and never executes anything.

use regex::Regex;
use std::sync::OnceLock;

/// A form the scanner can submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// The `action`, as written (may be relative or empty).
    pub action: String,
    /// `GET` or `POST`, upper-cased; defaults to `GET`.
    pub method: String,
    pub fields: Vec<Field>,
}

/// One input of a form, with the default value the page gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    /// `text`, `password`, `hidden`, `submit`, `textarea`, `select` ...
    pub kind: String,
    pub value: String,
}

impl Field {
    /// Inputs that carry a value the server reads back; a submit/button/file
    /// is not something the scanner should fuzz.
    pub fn is_fuzzable(&self) -> bool {
        !matches!(
            self.kind.as_str(),
            "submit" | "button" | "image" | "reset" | "file"
        )
    }
}

fn attr(tag: &str, name: &str) -> Option<String> {
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<String, Regex>>> =
        OnceLock::new();
    let map = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut map = map.lock().unwrap_or_else(|p| p.into_inner());
    let re = map.entry(name.to_string()).or_insert_with(|| {
        Regex::new(&format!(
            r#"(?is)\b{}\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))"#,
            regex::escape(name)
        ))
        .expect("attr regex")
    });
    re.captures(tag).map(|c| {
        c.get(2)
            .or_else(|| c.get(3))
            .or_else(|| c.get(4))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default()
    })
}

/// Every `href` of an `<a>` tag, in order, with duplicates kept so the caller
/// can decide. Values are raw (not resolved against the base).
pub fn links(body: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?is)<a\b[^>]*>"#).expect("anchor regex"));
    re.find_iter(body)
        .filter_map(|m| attr(m.as_str(), "href"))
        .filter(|h| !h.is_empty())
        .collect()
}

/// Every form on the page, with its action, method and fuzzable inputs.
pub fn forms(body: &str) -> Vec<Form> {
    static OPEN: OnceLock<Regex> = OnceLock::new();
    static INPUT: OnceLock<Regex> = OnceLock::new();
    let open = OPEN.get_or_init(|| Regex::new(r#"(?is)<form\b[^>]*>"#).expect("form regex"));
    let input = INPUT
        .get_or_init(|| Regex::new(r#"(?is)<(input|textarea|select)\b[^>]*>"#).expect("input re"));

    let mut forms = Vec::new();
    for m in open.find_iter(body) {
        let tag = m.as_str();
        // The form's inner markup: up to the next </form>, or the next form, or end.
        let rest = &body[m.end()..];
        let end = rest.to_lowercase().find("</form>").unwrap_or(rest.len());
        let inner = &rest[..end];

        let mut fields: Vec<Field> = Vec::new();
        for i in input.captures_iter(inner) {
            let whole = i.get(0).map(|x| x.as_str()).unwrap_or("");
            let elem = i.get(1).map(|x| x.as_str()).unwrap_or("").to_lowercase();
            let Some(name) = attr(whole, "name").filter(|n| !n.is_empty()) else {
                continue;
            };
            let kind = match elem.as_str() {
                "textarea" => "textarea".to_string(),
                "select" => "select".to_string(),
                _ => attr(whole, "type").unwrap_or_else(|| "text".to_string()),
            }
            .to_lowercase();
            let value = attr(whole, "value").unwrap_or_default();
            if !fields.iter().any(|f| f.name == name) {
                fields.push(Field { name, kind, value });
            }
        }
        forms.push(Form {
            action: attr(tag, "action").unwrap_or_default(),
            method: attr(tag, "method")
                .unwrap_or_default()
                .to_uppercase()
                .trim()
                .to_string(),
            fields,
        });
    }
    for f in &mut forms {
        if f.method != "POST" {
            f.method = "GET".to_string();
        }
    }
    forms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_reads_single_and_double_quotes() {
        let html = r#"<a href="/a">A</a> <a href='/b?x=1'>B</a> <A HREF=/c>C</A>"#;
        assert_eq!(links(html), vec!["/a", "/b?x=1", "/c"]);
    }

    #[test]
    fn forms_capture_method_action_and_named_inputs() {
        let html = r#"
          <form action="/login" method="post">
            <input type="text" name="user" value="admin">
            <input type="password" name="pass">
            <textarea name="comment"></textarea>
            <input type="submit" value="Go">
            <input value="no-name">
          </form>"#;
        let forms = forms(html);
        assert_eq!(forms.len(), 1);
        let f = &forms[0];
        assert_eq!(f.action, "/login");
        assert_eq!(f.method, "POST");
        let names: Vec<&str> = f.fields.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["user", "pass", "comment"]);
        assert_eq!(f.fields[0].value, "admin");
        assert!(f.fields[0].is_fuzzable());
        assert!(!f.fields.iter().any(|x| x.kind == "submit"));
    }

    #[test]
    fn method_defaults_to_get() {
        let forms = forms(r#"<form action="/search"><input name="q"></form>"#);
        assert_eq!(forms[0].method, "GET");
    }
}
