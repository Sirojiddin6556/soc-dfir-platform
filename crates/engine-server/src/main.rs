#![forbid(unsafe_code)]

use engine_server::EngineApp;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("============================================================");
    tracing::info!("  SOC / DFIR PLATFORM & BLUE TEAM CYBER RANGE (DESKTOP)     ");
    tracing::info!(
        "  Version: {} | Architecture: Desktop-First Offline        ",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("============================================================");

    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cas_dir = base_dir.join("data").join("cas");
    let db_path = base_dir.join("data").join("case.db");
    let ui_dir = base_dir.join("apps").join("desktop-ui");

    let app = Arc::new(EngineApp::new(cas_dir, db_path)?);
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let addr = listener.local_addr()?;
    tracing::info!("Desktop Server Listening on http://{}", addr);
    tracing::info!("Serving Desktop Cockpit UI from: {}", ui_dir.display());

    // Auto-launch dedicated standalone desktop application window
    #[cfg(target_os = "windows")]
    {
        let url = format!("http://{}", addr);
        let edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        let chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
        let temp_profile = std::env::temp_dir().join("soc-dfir-desktop-profile");

        let launched = if std::path::Path::new(edge_path).exists() {
            std::process::Command::new(edge_path)
                .args([
                    &format!("--app={}", url),
                    "--window-size=1440,900",
                    &format!("--user-data-dir={}", temp_profile.display()),
                ])
                .spawn()
                .is_ok()
        } else if std::path::Path::new(chrome_path).exists() {
            std::process::Command::new(chrome_path)
                .args([
                    &format!("--app={}", url),
                    "--window-size=1440,900",
                    &format!("--user-data-dir={}", temp_profile.display()),
                ])
                .spawn()
                .is_ok()
        } else {
            false
        };

        if !launched {
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", &url])
                .spawn();
        }
    }
    #[cfg(target_os = "linux")]
    {
        let url = format!("http://{}", addr);
        let temp_profile = std::env::temp_dir().join("soc-dfir-desktop-profile");
        let app_arg = format!("--app={}", url);
        let profile_arg = format!("--user-data-dir={}", temp_profile.display());

        let launched = std::process::Command::new("google-chrome")
            .args([&app_arg, "--window-size=1440,900", &profile_arg])
            .spawn()
            .is_ok()
            || std::process::Command::new("chromium")
                .args([&app_arg, "--window-size=1440,900", &profile_arg])
                .spawn()
                .is_ok();

        if !launched {
            let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
        }
    }

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

async fn handle_connection(
    mut stream: TcpStream,
    app: Arc<EngineApp>,
    ui_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0u8; 8192];
    let bytes_read = stream.read(&mut buffer).await?;
    if bytes_read == 0 {
        return Ok(());
    }

    let req_str = String::from_utf8_lossy(&buffer[..bytes_read]);
    let mut lines = req_str.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let raw_path = parts[1];
    let path = raw_path.split('?').next().unwrap_or("/");

    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type\r\n\
Content-Length: 0\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if method == "POST" && path == "/rpc" {
        let body = if let Some(pos) = req_str.find("\r\n\r\n") {
            &req_str[pos + 4..]
        } else {
            ""
        };

        let result = app.dispatch_request(body).await;
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\n\r\n{}",
            result.len(),
            result
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Static file serving for Desktop Cockpit
    let rel_path = if path == "/" || path == "/index.html" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };

    let file_path = ui_dir.join(rel_path);
    if file_path.exists() && file_path.is_file() {
        let content = tokio::fs::read(&file_path).await?;
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

        let header = format!(
            "HTTP/1.1 200 OK\r\n\
Content-Type: {}\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\n\r\n",
            mime,
            content.len()
        );
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&content).await?;
    } else {
        let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
        stream.write_all(not_found.as_bytes()).await?;
    }

    Ok(())
}
