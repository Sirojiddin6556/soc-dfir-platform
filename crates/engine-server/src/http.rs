#![forbid(unsafe_code)]

//! Embedded HTTP server: serves the desktop UI, the `/rpc` endpoint and the
//! evidence chunk upload. It is meant for the local machine only, so it
//! refuses requests whose `Host` or `Origin` is not a loopback name (this
//! blocks DNS rebinding and cross-site requests), never sends CORS grants,
//! and requires a session token for every non-public RPC method.

use crate::EngineApp;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Largest accepted header block.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Largest accepted `/rpc` body. The legacy `evidence.ingest` call carries
/// up to 256 MiB of file data as base64, which is about 342 MiB.
pub const MAX_RPC_BODY_BYTES: usize = 384 * 1024 * 1024;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; \
connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
frame-ancestors 'none'";

/// Host names the server answers to. Loopback names are always allowed;
/// more can be added with `SOC_ALLOWED_HOSTS` (comma separated), for example
/// when the engine runs behind a reverse proxy.
#[derive(Debug, Clone)]
pub struct HttpPolicy {
    allowed_hosts: Vec<String>,
}

impl HttpPolicy {
    pub fn loopback_only() -> Self {
        Self {
            allowed_hosts: vec![
                "127.0.0.1".to_string(),
                "localhost".to_string(),
                "::1".to_string(),
            ],
        }
    }

    pub fn from_env() -> Self {
        let mut policy = Self::loopback_only();
        if let Ok(extra) = std::env::var("SOC_ALLOWED_HOSTS") {
            policy.allowed_hosts.extend(
                extra
                    .split(',')
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty()),
            );
        }
        policy
    }

    fn allows_host_header(&self, value: &str) -> bool {
        let name = strip_port(value.trim()).to_ascii_lowercase();
        self.allowed_hosts.contains(&name)
    }

    fn allows_origin(&self, origin: &str) -> bool {
        let rest = match origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
        {
            Some(r) => r,
            None => return false,
        };
        self.allows_host_header(rest.trim_end_matches('/'))
    }
}

/// `host:port`, `[v6]:port`, `[v6]` or `host` -> host name without port/brackets.
fn strip_port(value: &str) -> &str {
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            host
        }
        _ => value,
    }
}

/// Robustly binds to preferred port or falls back to an available dynamic port
pub async fn bind_server(preferred_port: u16) -> Result<TcpListener, std::io::Error> {
    match TcpListener::bind(format!("127.0.0.1:{}", preferred_port)).await {
        Ok(l) => Ok(l),
        Err(_) => TcpListener::bind("127.0.0.1:0").await,
    }
}

/// Runs the embedded HTTP & IPC server on the specified listener
pub async fn run_server_loop(
    listener: TcpListener,
    cas_dir: PathBuf,
    db_path: PathBuf,
    ui_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Arc::new(EngineApp::new(cas_dir, db_path)?);
    serve(listener, app, ui_dir, HttpPolicy::from_env()).await
}

/// Accept loop for an already constructed engine.
pub async fn serve(
    listener: TcpListener,
    app: Arc<EngineApp>,
    ui_dir: PathBuf,
    policy: HttpPolicy,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!(
        "Embedded Desktop Server listening on http://{}",
        listener.local_addr()?
    );
    let policy = Arc::new(policy);
    loop {
        let (socket, _) = listener.accept().await?;
        let app_clone = Arc::clone(&app);
        let ui_dir_clone = ui_dir.clone();
        let policy = Arc::clone(&policy);

        tokio::spawn(async move {
            if let Err(e) = handle_connection_with(socket, app_clone, &ui_dir_clone, &policy).await
            {
                tracing::debug!("Connection error: {}", e);
            }
        });
    }
}

/// Runs the embedded HTTP & IPC server on the specified address
pub async fn run_embedded_server(
    addr: &str,
    cas_dir: PathBuf,
    db_path: PathBuf,
    ui_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    run_server_loop(listener, cas_dir, db_path, ui_dir).await
}

pub async fn handle_connection(
    stream: TcpStream,
    app: Arc<EngineApp>,
    ui_dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    handle_connection_with(stream, app, ui_dir, &HttpPolicy::from_env()).await
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    content_length: Option<usize>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_head(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let path = target.split(['?', '#']).next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let content_length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok());
    Some(Request {
        method,
        path,
        headers,
        content_length,
    })
}

pub async fn handle_connection_with(
    mut stream: TcpStream,
    app: Arc<EngineApp>,
    ui_dir: &Path,
    policy: &HttpPolicy,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer = Vec::with_capacity(8192);
    let mut temp = [0u8; 8192];
    let body_start = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&temp[..n]);
        if let Some(pos) = find_header_end(&buffer) {
            break pos;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return send_text(&mut stream, 431, "Request Header Fields Too Large").await;
        }
    };

    let head = String::from_utf8_lossy(&buffer[..body_start]).to_string();
    let Some(req) = parse_head(&head) else {
        return send_text(&mut stream, 400, "Bad Request").await;
    };

    match req.header("host") {
        Some(h) if policy.allows_host_header(h) => {}
        _ => return send_text(&mut stream, 403, "Host not allowed").await,
    }
    if let Some(origin) = req.header("origin") {
        if !policy.allows_origin(origin) {
            return send_text(&mut stream, 403, "Cross-origin request refused").await;
        }
    }

    if req.path == "/rpc" {
        if req.method != "POST" {
            return send_text(&mut stream, 405, "Method Not Allowed").await;
        }
        let Some(content_len) = req.content_length else {
            return send_text(&mut stream, 411, "Length Required").await;
        };
        if content_len > MAX_RPC_BODY_BYTES {
            return send_text(&mut stream, 413, "Payload Too Large").await;
        }
        let mut body = buffer.split_off(body_start);
        body.truncate(content_len);
        while body.len() < content_len {
            let to_read = (content_len - body.len()).min(temp.len());
            let n = stream.read(&mut temp[..to_read]).await?;
            if n == 0 {
                return send_text(&mut stream, 400, "Incomplete body").await;
            }
            body.extend_from_slice(&temp[..n]);
        }
        let body = String::from_utf8_lossy(&body);
        let (status, result) = match crate::auth::authorize_rpc(&app, &body) {
            Ok(()) => (200, app.dispatch_request(&body).await),
            Err(denied) => (401, denied),
        };
        return send(
            &mut stream,
            status,
            "application/json",
            result.as_bytes(),
            true,
        )
        .await;
    }

    if req.path == "/health/live" {
        return send(
            &mut stream,
            200,
            "application/json",
            br#"{"status":"ok"}"#,
            true,
        )
        .await;
    }

    if req.method != "GET" && req.method != "HEAD" {
        return send_text(&mut stream, 405, "Method Not Allowed").await;
    }

    let Some(file_path) = resolve_static_path(ui_dir, &req.path) else {
        return send_text(&mut stream, 404, "Not Found").await;
    };
    match tokio::fs::read(&file_path).await {
        Ok(content) => {
            let mime = mime_for(&file_path);
            if req.method == "HEAD" {
                let header = response_head(200, mime, content.len(), false);
                stream.write_all(header.as_bytes()).await?;
                Ok(())
            } else {
                send(&mut stream, 200, mime, &content, false).await
            }
        }
        Err(_) => send_text(&mut stream, 404, "Not Found").await,
    }
}

/// Maps a request path onto a file inside `ui_dir`. Returns `None` for
/// anything that could leave the directory: `..`, absolute or drive paths,
/// backslashes, NUL bytes, bad percent-encoding, and symlinks resolving
/// outside of it.
pub fn resolve_static_path(ui_dir: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(request_path)?;
    let rel = if decoded == "/" || decoded.is_empty() {
        "index.html"
    } else {
        decoded.trim_start_matches('/')
    };
    if rel.contains('\\') || rel.contains('\0') || rel.contains(':') {
        return None;
    }
    let rel_path = Path::new(rel);
    if !rel_path
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
    {
        return None;
    }
    let root = ui_dir.canonicalize().ok()?;
    let full = root.join(rel_path).canonicalize().ok()?;
    if full.starts_with(&root) && full.is_file() {
        Some(full)
    } else {
        None
    }
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let s = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(s, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

fn response_head(status: u16, content_type: &str, len: usize, no_store: bool) -> String {
    format!(
        "HTTP/1.1 {status} {}\r\n\
Content-Type: {content_type}\r\n\
Content-Length: {len}\r\n\
Content-Security-Policy: {CONTENT_SECURITY_POLICY}\r\n\
X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Referrer-Policy: no-referrer\r\n\
Cross-Origin-Opener-Policy: same-origin\r\n\
Cross-Origin-Resource-Policy: same-origin\r\n\
Cache-Control: {}\r\n\
Connection: close\r\n\r\n",
        reason(status),
        if no_store { "no-store" } else { "no-cache" },
    )
}

async fn send(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    no_store: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let head = response_head(status, content_type, body.len(), no_store);
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

async fn send_text(
    stream: &mut TcpStream,
    status: u16,
    text: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    send(
        stream,
        status,
        "text/plain; charset=utf-8",
        text.as_bytes(),
        true,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ports_and_brackets() {
        assert_eq!(strip_port("127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(strip_port("localhost"), "localhost");
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("evil.example:80"), "evil.example");
    }

    #[test]
    fn loopback_policy_rejects_foreign_hosts_and_origins() {
        let p = HttpPolicy::loopback_only();
        assert!(p.allows_host_header("127.0.0.1:8080"));
        assert!(p.allows_host_header("LOCALHOST:1234"));
        assert!(p.allows_host_header("[::1]:8080"));
        assert!(!p.allows_host_header("attacker.example:8080"));
        assert!(!p.allows_host_header("127.0.0.1.attacker.example"));
        assert!(p.allows_origin("http://127.0.0.1:8080"));
        assert!(!p.allows_origin("https://evil.example"));
        assert!(!p.allows_origin("null"));
    }

    #[test]
    fn static_paths_cannot_escape_ui_dir() {
        let base = std::env::temp_dir().join(format!("soc-ui-{}", uuid::Uuid::now_v7()));
        let ui = base.join("ui");
        std::fs::create_dir_all(ui.join("js")).unwrap();
        std::fs::write(ui.join("index.html"), "<html>").unwrap();
        std::fs::write(ui.join("js/app.js"), "//").unwrap();
        std::fs::write(base.join("secret.txt"), "secret").unwrap();

        assert!(resolve_static_path(&ui, "/").is_some());
        assert!(resolve_static_path(&ui, "/js/app.js").is_some());
        assert!(resolve_static_path(&ui, "/js%2Fapp.js").is_some());
        for bad in [
            "/../secret.txt",
            "/js/../../secret.txt",
            "/%2e%2e/secret.txt",
            "/..%2fsecret.txt",
            "/..\\secret.txt",
            "//etc/passwd",
            "/C:/Windows/win.ini",
            "/%zz",
            "/js",
        ] {
            assert!(
                resolve_static_path(&ui, bad).is_none(),
                "{bad} must be refused"
            );
        }
        std::fs::remove_dir_all(&base).ok();
    }
}
