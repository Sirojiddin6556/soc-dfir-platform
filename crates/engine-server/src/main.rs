#![forbid(unsafe_code)]

use engine_server::EngineApp;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `engine-server --healthcheck` probes a running instance and exits 0/1,
    // so container images need no curl.
    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        std::process::exit(if healthcheck().await { 0 } else { 1 });
    }

    tracing_subscriber::fmt::init();
    tracing::info!("============================================================");
    tracing::info!("  SOC / DFIR PLATFORM & BLUE TEAM CYBER RANGE (DESKTOP)     ");
    tracing::info!(
        "  Version: {} | Architecture: Desktop-First Offline        ",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("============================================================");

    // Configuration (all optional):
    //   SOC_BIND           listen address, default 127.0.0.1:8080
    //   SOC_DATA_DIR       case database and CAS root, default ./data
    //   SOC_UI_DIR         desktop UI assets, default ./apps/desktop-ui
    //   SOC_ALLOWED_HOSTS  extra Host names to accept (reverse proxy setups)
    //   SOC_NO_BROWSER=1   do not open a browser window on start
    //   SOC_VULNDB_OFFLINE_DIR  import vulnerability feeds from this directory
    //                      instead of downloading them (air-gapped installs)
    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let data_dir = env_path("SOC_DATA_DIR").unwrap_or_else(|| base_dir.join("data"));
    let ui_dir = env_path("SOC_UI_DIR").unwrap_or_else(|| base_dir.join("apps").join("desktop-ui"));
    let bind = std::env::var("SOC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let cas_dir = data_dir.join("cas");
    let db_path = data_dir.join("case.db");

    let app = Arc::new(EngineApp::new(cas_dir, db_path)?);
    let listener = TcpListener::bind(&bind).await?;
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback() {
        tracing::warn!(
            "Listening on non-loopback address {}: only Host names from SOC_ALLOWED_HOSTS and loopback are accepted",
            addr
        );
    }
    tracing::info!("Desktop Server Listening on http://{}", addr);
    tracing::info!("Serving Desktop Cockpit UI from: {}", ui_dir.display());
    if app.storage.auth_setup_required().unwrap_or(false) {
        tracing::warn!(
            "Owner password is not set yet: open http://{} and complete the first-run setup",
            addr
        );
    }

    let open_browser = std::env::var("SOC_NO_BROWSER")
        .map(|v| v != "1")
        .unwrap_or(true);
    // Auto-launch dedicated standalone desktop application window
    #[cfg(target_os = "windows")]
    if open_browser {
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
    if open_browser {
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

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let _ = open_browser;

    engine_server::http::serve(
        listener,
        app,
        ui_dir,
        engine_server::http::HttpPolicy::from_env(),
    )
    .await
    .map_err(|e| e as Box<dyn std::error::Error>)
}

async fn healthcheck() -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let bind = std::env::var("SOC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let port = bind.rsplit(':').next().unwrap_or("8080");
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await?;
        stream
            .write_all(b"GET /health/live HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok::<bool, std::io::Error>(buf.starts_with(b"HTTP/1.1 200"))
    };
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(4), probe).await,
        Ok(Ok(true))
    )
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}
