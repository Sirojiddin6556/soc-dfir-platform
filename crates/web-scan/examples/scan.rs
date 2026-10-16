//! Scans a running web application and prints the findings.
//!
//! cargo run --release -p web-scan --example scan -- URL [--json] \
//!   [--no-active] [--no-forms] [--max-pages N] [--max-requests N] \
//!   [--login URL] [--field name=value] [--success TEXT]
//!
//! Point it only at a system you are authorized to test.

use web_scan::{scan, Login, Options};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned().unwrap_or_else(|| {
        eprintln!("usage: web-scan URL [--json] [--no-active] [--login URL --field n=v ...]");
        std::process::exit(2);
    });

    let value = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let login = value("--login").map(|url| Login {
        url,
        fields: args
            .iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == "--field")
            .filter_map(|(i, _)| args.get(i + 1))
            .filter_map(|kv| {
                kv.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect(),
        success_text: value("--success"),
        json: args.iter().any(|a| a == "--login-json"),
    });
    let options = Options {
        active: !args.iter().any(|a| a == "--no-active"),
        submit_forms: !args.iter().any(|a| a == "--no-forms"),
        discover_paths: !args.iter().any(|a| a == "--no-discover"),
        use_openapi: !args.iter().any(|a| a == "--no-openapi"),
        max_pages: value("--max-pages")
            .and_then(|v| v.parse().ok())
            .unwrap_or(200),
        max_requests: value("--max-requests")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4000),
        login,
        ..Options::default()
    };

    let report = scan(&target, &options).unwrap_or_else(|e| {
        eprintln!("scan failed: {e}");
        std::process::exit(1);
    });

    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&report).expect("json"));
        return;
    }
    for f in &report.findings {
        let param = f
            .param
            .as_deref()
            .map(|p| format!(" [{p}]"))
            .unwrap_or_default();
        println!(
            "{:?} {} {}{} CWE-{} {}\n    {}\n    {}",
            f.severity, f.method, f.url, param, f.cwe, f.title, f.evidence, f.request
        );
    }
    eprintln!(
        "{} findings; {} pages, {} forms, {} requests, auth={}, {} ms{}",
        report.findings.len(),
        report.pages_crawled,
        report.forms_found,
        report.requests_made,
        report.authenticated,
        report.duration_ms,
        if report.notes.is_empty() {
            String::new()
        } else {
            format!("\nnotes: {}", report.notes.join("; "))
        }
    );
}
