//! End-to-end scan against a deliberately vulnerable in-process server.
//!
//! The server below is a stand-in for an application the operator runs: it
//! reflects input, surfaces a database error on a stray quote, serves a system
//! file on a path climb, redirects anywhere, and sets a flagless cookie with
//! no security headers. The test asserts the scanner finds each of these and,
//! importantly, does not flag a sibling endpoint that escapes its output.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use web_scan::{scan, Login, Options};

struct MockServer {
    base: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| pct_decode(v))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, &str)], body: &str) {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    out.push_str("Connection: close\r\n");
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    let mut had_ct = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-type") {
            had_ct = true;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !had_ct {
        out.push_str("Content-Type: text/html; charset=utf-8\r\n");
    }
    out.push_str("\r\n");
    out.push_str(body);
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.flush();
}

fn handle(mut stream: TcpStream) {
    // On Windows a socket from accept() inherits the listener's non-blocking
    // flag; force blocking so the reads and writes below behave like Linux.
    stream.set_nonblocking(false).ok();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut buf = [0u8; 8192];
    let mut data = Vec::new();
    // Read until headers are complete, then the declared body.
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&data);
                if let Some(h_end) = text.find("\r\n\r\n") {
                    let head = &text[..h_end];
                    let len = head
                        .lines()
                        .find_map(|l| {
                            let l = l.to_lowercase();
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if data.len() >= h_end + 4 + len {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&data);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    // For a POST the parameters are in the body.
    let params_src = if method == "POST" {
        body.clone()
    } else {
        query.clone()
    };

    match path.as_str() {
        "/" => respond(
            &mut stream,
            "200 OK",
            // A flagless session cookie, no security headers at all.
            &[
                ("Set-Cookie", "session=abc123; Path=/"),
                ("Server", "nginx/1.18.0"),
            ],
            r#"<html><body>
              <a href="/search?q=hello">search</a>
              <a href="/item?id=1">item</a>
              <a href="/page?file=home.txt">page</a>
              <a href="/go?next=/dashboard">go</a>
              <a href="/safe?q=hi">safe</a>
              <form action="/login" method="post">
                <input name="username" value=""><input type="password" name="password">
                <input type="submit" value="in">
              </form>
            </body></html>"#,
        ),
        // Reflects q with no escaping -> reflected XSS.
        "/search" => {
            let q = param(&params_src, "q").unwrap_or_default();
            respond(
                &mut stream,
                "200 OK",
                &[],
                &format!("<html><body>Результаты для: {q}</body></html>"),
            );
        }
        // Escapes q -> must NOT be flagged.
        "/safe" => {
            let q = param(&params_src, "q").unwrap_or_default();
            respond(
                &mut stream,
                "200 OK",
                &[],
                &format!("<html><body>Safe: {}</body></html>", html_escape(&q)),
            );
        }
        // A stray quote in id yields a database error -> SQL injection.
        "/item" => {
            let id = param(&params_src, "id").unwrap_or_default();
            if id.contains('\'') {
                respond(
                    &mut stream,
                    "500 Internal Server Error",
                    &[],
                    "<html><body>sqlite3.OperationalError: near \"'\": syntax error</body></html>",
                );
            } else {
                respond(
                    &mut stream,
                    "200 OK",
                    &[],
                    "<html><body>item 1</body></html>",
                );
            }
        }
        // A path climb returns a system file -> path traversal.
        "/page" => {
            let file = param(&params_src, "file").unwrap_or_default();
            if file.contains("etc/passwd") {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "text/plain")],
                    "root:x:0:0:root:/root:/bin/bash\n",
                );
            } else {
                respond(&mut stream, "200 OK", &[], "<html><body>home</body></html>");
            }
        }
        // Redirects to wherever next says -> open redirect.
        "/go" => {
            let next = param(&params_src, "next").unwrap_or_default();
            respond(
                &mut stream,
                "302 Found",
                &[("Location", &next)],
                "redirecting",
            );
        }
        "/login" => {
            let user = param(&params_src, "username").unwrap_or_default();
            if user == "admin" {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Set-Cookie", "auth=yes; Path=/")],
                    "<html><body>Welcome admin</body></html>",
                );
            } else {
                respond(
                    &mut stream,
                    "200 OK",
                    &[],
                    "<html><body>login</body></html>",
                );
            }
        }
        _ => respond(
            &mut stream,
            "404 Not Found",
            &[],
            "<html><body>nope</body></html>",
        ),
    }
}

fn start() -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle(stream),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });
    MockServer {
        base: format!("http://127.0.0.1:{port}/"),
        stop,
        handle: Some(handle),
    }
}

fn rules(report: &web_scan::Report) -> Vec<String> {
    let mut r: Vec<String> = report.findings.iter().map(|f| f.rule.clone()).collect();
    r.sort();
    r.dedup();
    r
}

#[test]
fn finds_the_planted_vulnerabilities_and_spares_the_safe_endpoint() {
    let server = start();
    let report = scan(
        &server.base,
        &Options {
            login: Some(Login {
                url: "/login".into(),
                fields: vec![
                    ("username".into(), "admin".into()),
                    ("password".into(), "admin".into()),
                ],
                success_text: Some("Welcome admin".into()),
            }),
            ..Options::default()
        },
    )
    .expect("scan runs");

    assert!(
        report.authenticated,
        "login should succeed: {:?}",
        report.notes
    );
    let found = rules(&report);
    for rule in [
        "reflected-xss",
        "sql-injection",
        "path-traversal",
        "open-redirect",
        "clickjacking",
        "missing-csp",
        "cookie-flags",
        "version-disclosure",
    ] {
        assert!(
            found.contains(&rule.to_string()),
            "missing {rule}; got {found:?}"
        );
    }

    // The escaped /safe endpoint must not be a reflected-XSS finding.
    let xss: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.rule == "reflected-xss")
        .map(|f| f.url.as_str())
        .collect();
    assert!(
        xss.iter().any(|u| u.contains("/search")),
        "xss on search: {xss:?}"
    );
    assert!(
        !xss.iter().any(|u| u.contains("/safe")),
        "false XSS on /safe: {xss:?}"
    );

    // Each finding keeps a reproducible request.
    for f in &report.findings {
        assert!(f.request.starts_with("curl"), "no repro for {}", f.rule);
    }

    // The session cookie set at login is judged, not just page cookies.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule == "cookie-flags" && f.param.as_deref() == Some("auth")),
        "login cookie flags not checked"
    );
}

#[test]
fn stays_on_the_target_origin() {
    let server = start();
    let report = scan(&server.base, &Options::default()).expect("scan runs");
    for f in &report.findings {
        assert!(
            f.url.contains("127.0.0.1"),
            "finding left the origin: {}",
            f.url
        );
    }
    assert!(report.pages_crawled >= 4, "should crawl linked pages");
}
