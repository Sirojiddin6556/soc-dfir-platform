#![forbid(unsafe_code)]

use engine_server::EngineApp;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!(
        "Starting SOC-DFIR Engine Core Server v{}",
        env!("CARGO_PKG_VERSION")
    );

    let cas_dir = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data")
        .join("cas");

    let app = EngineApp::new_in_memory(cas_dir);
    let health = app
        .dispatch_request(
            r#"{"api_version": 1, "request_id": "boot-1", "method": "health", "params": {}}"#,
        )
        .await;
    tracing::info!("Engine Health Check Status: {}", health);
    tracing::info!("Engine Ready. Ready for IPC connections.");
}
