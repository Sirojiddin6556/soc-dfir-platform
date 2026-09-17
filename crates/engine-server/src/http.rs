#![forbid(unsafe_code)]

use crate::EngineApp;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
    ui_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Arc::new(EngineApp::new_in_memory(cas_dir));
    tracing::info!(
        "Embedded Desktop Server listening on http://{}",
        listener.local_addr()?
    );

    loop {
        let (socket, _) = listener.accept().await?;
        let app_clone = Arc::clone(&app);
        let ui_dir_clone = ui_dir.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, app_clone, &ui_dir_clone).await {
                tracing::debug!("Connection error: {}", e);
            }
        });
    }
}

/// Runs the embedded HTTP & IPC server on the specified address
pub async fn run_embedded_server(
    addr: &str,
    cas_dir: PathBuf,
    ui_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    run_server_loop(listener, cas_dir, ui_dir).await
}

pub async fn handle_connection(
    mut stream: TcpStream,
    app: Arc<EngineApp>,
    ui_dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer = Vec::with_capacity(8192);
    let mut temp = [0u8; 4096];
    let (body_start, content_len) = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&temp[..n]);
        let s = String::from_utf8_lossy(&buffer);
        if let Some(pos) = s.find("\r\n\r\n") {
            let cl = s[..pos]
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (pos + 4, cl);
        } else if let Some(pos) = s.find("\n\n") {
            let cl = s[..pos]
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (pos + 2, cl);
        }
        if buffer.len() > 65536 {
            return Ok(());
        }
    };

    while buffer.len() < body_start + content_len {
        let needed = (body_start + content_len) - buffer.len();
        let to_read = needed.min(temp.len());
        let n = stream.read(&mut temp[..to_read]).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..n]);
    }

    let req_str = String::from_utf8_lossy(&buffer);
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1].split('?').next().unwrap_or("/");

    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if method == "POST" && path == "/rpc" {
        let body_bytes = if buffer.len() >= body_start + content_len {
            &buffer[body_start..body_start + content_len]
        } else {
            &buffer[body_start..]
        };
        let body = String::from_utf8_lossy(body_bytes);
        let result = app.dispatch_request(&body).await;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
            result.len(),
            result
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let rel_path = if path == "/" || path == "/index.html" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };

    let file_path = ui_dir.join(rel_path);
    if file_path.exists() && file_path.is_file() {
        let mime = if rel_path.ends_with(".html") {
            "text/html; charset=utf-8"
        } else if rel_path.ends_with(".css") {
            "text/css; charset=utf-8"
        } else if rel_path.ends_with(".js") {
            "application/javascript; charset=utf-8"
        } else if rel_path.ends_with(".json") {
            "application/json"
        } else {
            "application/octet-stream"
        };

        if let Ok(content) = tokio::fs::read(&file_path).await {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
                mime, content.len()
            );
            stream.write_all(resp.as_bytes()).await?;
            stream.write_all(&content).await?;
            return Ok(());
        }
    }

    let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
    stream.write_all(not_found.as_bytes()).await?;
    Ok(())
}
