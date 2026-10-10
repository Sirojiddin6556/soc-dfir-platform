//! Server-side template injection (SSTI).
//!
//! A value placed into a server-side template that is then rendered can be
//! made to carry a template expression the engine evaluates. The check sends
//! an arithmetic expression — a product of two fixed numbers — wrapped in the
//! delimiters of the common engines (Jinja2/Twig/Nunjucks `{{ }}`, Freemarker
//! `${ }`, ERB/EJS `<%= %>`, and so on) and looks for the *computed product*
//! in the response. To separate evaluation from mere reflection it requires
//! the product to appear while the literal expression (`A*B`) does not, and it
//! first confirms the product is absent from the benign baseline. The product
//! is a large, distinctive number, so a chance match is implausible. For
//! authorized testing of systems the operator controls.

use crate::http::Client;
use crate::{Finding, InjectionPoint, Severity};

/// Two factors whose product is large and distinctive, so finding the product
/// in a response is strong evidence the server computed it.
const A: u64 = 9973;
const B: u64 = 9967;

/// Wraps the `A*B` expression in each engine's delimiters. More specific
/// delimiters (`${{ }}`) come before the ones they contain (`${ }`).
fn payloads(expr: &str) -> Vec<String> {
    vec![
        format!("${{{{{expr}}}}}"), // ${{ A*B }}
        format!("{{{{{expr}}}}}"),  // {{ A*B }}
        format!("${{{expr}}}"),     // ${ A*B }
        format!("#{{{expr}}}"),     // #{ A*B }
        format!("<%= {expr} %>"),   // <%= A*B %>
    ]
}

pub fn check(client: &Client, point: &InjectionPoint, index: usize, findings: &mut Vec<Finding>) {
    let expr = format!("{A}*{B}");
    let product = (A * B).to_string();

    // Baseline: a page that already shows the product (unlikely, but cheap to
    // rule out) must not be mistaken for evaluation.
    let base = point.params[index].1.clone();
    let Ok((baseline, _)) = point.send(client, Some(index), &base) else {
        return;
    };
    if baseline.body.contains(&product) {
        return;
    }

    for payload in payloads(&expr) {
        if client.remaining() < 2 {
            return;
        }
        let Ok((resp, _)) = point.send(client, Some(index), &payload) else {
            continue;
        };
        // Evaluation, not reflection: the product is present and the literal
        // expression is gone (a page that merely echoed the payload would show
        // `A*B` verbatim and never the product).
        if !resp.body.contains(&product) || resp.body.contains(&expr) {
            continue;
        }
        // Confirm once more, so a coincidental number that happened to match is
        // not reported as injection.
        let Ok((again, record)) = point.send(client, Some(index), &payload) else {
            continue;
        };
        if !again.body.contains(&product) || again.body.contains(&expr) {
            continue;
        }
        let name = point.params[index].0.clone();
        findings.push(Finding {
            rule: "template-injection".into(),
            cwe: 94,
            severity: Severity::Critical,
            title: "Инъекция в шаблон (SSTI)".into(),
            message: format!(
                "Параметр «{name}» попадает в серверный шаблон, который его вычисляет: выражение «{expr}» вернулось как результат {product}, а не как текст. Так выполняют произвольный код на сервере (путь к RCE). Не подставляйте ввод в тело шаблона: передавайте его только как данные (переменные контекста), а не как часть самого шаблона."
            ),
            url: record.url.clone(),
            method: point.method.as_str().into(),
            param: Some(name),
            evidence: format!("Шаблон вычислил «{expr}» → «{product}» (payload: {payload})"),
            request: record.as_curl(),
            request_detail: record,
        });
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_is_distinctive() {
        // Not a round or common number, so a chance appearance is implausible.
        assert_eq!(A * B, 99400891);
    }

    #[test]
    fn payloads_cover_the_common_engines() {
        let p = payloads("9973*9967");
        assert!(p.iter().any(|s| s == "{{9973*9967}}"));
        assert!(p.iter().any(|s| s == "${9973*9967}"));
        assert!(p.iter().any(|s| s == "${{9973*9967}}"));
        assert!(p.iter().any(|s| s == "#{9973*9967}"));
        assert!(p.iter().any(|s| s == "<%= 9973*9967 %>"));
    }
}
