#![forbid(unsafe_code)]

//! Security behaviour of the embedded HTTP server, exercised over real TCP
//! connections: session enforcement, first-run setup, Host/Origin checks,
//! static path traversal and the body size limit.

use engine_server::http::{serve, HttpPolicy};
use engine_server::EngineApp;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestServer {
    port: u16,
    app: Arc<EngineApp>,
    root: PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn start() -> TestServer {
    let root = std::env::temp_dir().join(format!("soc-http-sec-{}", uuid::Uuid::now_v7()));
    let ui = root.join("ui");
    std::fs::create_dir_all(&ui).unwrap();
    std::fs::write(ui.join("index.html"), "<html>ui</html>").unwrap();
    std::fs::write(root.join("secret.txt"), "TOP-SECRET").unwrap();

    let app = Arc::new(EngineApp::new(root.join("cas"), root.join("case.db")).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_app = Arc::clone(&app);
    tokio::spawn(async move {
        let _ = serve(listener, server_app, ui, HttpPolicy::loopback_only()).await;
    });
    TestServer { port, app, root }
}

/// Sends a raw request and returns (status, body).
async fn raw(port: u16, request: String) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn rpc_with(
    port: u16,
    extra_headers: &str,
    method: &str,
    params: serde_json::Value,
) -> (u16, serde_json::Value) {
    let body = serde_json::json!({
        "api_version": 1, "request_id": "t", "method": method, "params": params
    })
    .to_string();
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra_headers}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (status, body) = raw(port, req).await;
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

async fn rpc(port: u16, method: &str, params: serde_json::Value) -> (u16, serde_json::Value) {
    rpc_with(port, "", method, params).await
}

#[tokio::test]
async fn rpc_requires_a_session_except_public_methods() {
    let srv = start().await;

    let (status, body) = rpc(srv.port, "cases.list", serde_json::json!({})).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["status"], 401);

    let (status, _) = rpc(
        srv.port,
        "cases.list",
        serde_json::json!({"token": "tk_forged"}),
    )
    .await;
    assert_eq!(status, 401, "an invented token must not work");

    let (status, body) = rpc(srv.port, "health", serde_json::json!({})).await;
    assert_eq!(status, 200);
    assert!(body["error"].is_null());

    // The CTF client speaks JSON-RPC 2.0; refusals keep that shape.
    let body = r#"{"jsonrpc":"2.0","id":"x1","method":"competitions.list","params":{}}"#;
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (status, text) = raw(srv.port, req).await;
    assert_eq!(status, 401);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], "x1");
    assert_eq!(v["error"]["code"], -32001);
}

#[tokio::test]
async fn first_run_setup_then_login_and_logout() {
    let srv = start().await;

    let (_, status) = rpc(srv.port, "auth.status", serde_json::json!({})).await;
    assert_eq!(status["result"]["setup_required"], true);

    // The old built-in credentials do not work.
    let (_, res) = rpc(
        srv.port,
        "auth.login",
        serde_json::json!({"username": "sirojiddin", "password": "admin"}),
    )
    .await;
    assert!(res["result"].is_null());

    let (_, res) = rpc(
        srv.port,
        "auth.setup",
        serde_json::json!({"password": "short"}),
    )
    .await;
    assert!(res["result"].is_null(), "short passwords are refused");

    let (_, res) = rpc(
        srv.port,
        "auth.setup",
        serde_json::json!({"password": "correct horse battery"}),
    )
    .await;
    let token = res["result"]["session"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(token.len() >= 64, "token carries 256 bits of randomness");

    // Setup cannot be replayed to take over the account.
    let (_, res) = rpc(
        srv.port,
        "auth.setup",
        serde_json::json!({"password": "attacker-password"}),
    )
    .await;
    assert!(res["result"].is_null());

    let (status, res) = rpc(srv.port, "cases.list", serde_json::json!({"token": token})).await;
    assert_eq!(status, 200);
    assert!(res["error"].is_null());

    let (_, res) = rpc(
        srv.port,
        "auth.login",
        serde_json::json!({"username": "sirojiddin", "password": "correct horse battery"}),
    )
    .await;
    assert!(res["result"]["session"]["token"].is_string());

    rpc(srv.port, "auth.logout", serde_json::json!({"token": token})).await;
    let (status, _) = rpc(srv.port, "cases.list", serde_json::json!({"token": token})).await;
    assert_eq!(status, 401, "logged-out token is dead");

    // Session tokens are stored hashed, not in clear.
    let user = srv
        .app
        .storage
        .verify_user_password("sirojiddin", "correct horse battery")
        .unwrap()
        .unwrap();
    let s = srv
        .app
        .storage
        .create_session(user.id, &user.username)
        .unwrap();
    let db = std::fs::read(srv.root.join("case.db")).unwrap_or_default();
    let wal = std::fs::read(srv.root.join("case.db-wal")).unwrap_or_default();
    let needle = s.token.as_bytes();
    let contains = |hay: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(&db) && !contains(&wal));
}

#[tokio::test]
async fn repeated_wrong_passwords_lock_login() {
    let srv = start().await;
    srv.app
        .storage
        .complete_initial_setup("the-real-password")
        .unwrap();
    for _ in 0..5 {
        rpc(
            srv.port,
            "auth.login",
            serde_json::json!({"username": "sirojiddin", "password": "guess"}),
        )
        .await;
    }
    let (_, res) = rpc(
        srv.port,
        "auth.login",
        serde_json::json!({"username": "sirojiddin", "password": "the-real-password"}),
    )
    .await;
    assert!(
        res["result"].is_null(),
        "locked even with the right password"
    );
    assert_eq!(res["error"]["status"], 403);
}

#[tokio::test]
async fn foreign_host_and_origin_are_refused() {
    let srv = start().await;
    let (status, _) = rpc_with(
        srv.port,
        "Origin: https://evil.example\r\n",
        "health",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 403);

    let (status, _) = rpc_with(
        srv.port,
        "Origin: http://127.0.0.1:1234\r\n",
        "health",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "same-machine origin is fine");

    // DNS rebinding: the browser sends the attacker's name as Host.
    let (status, _) = raw(
        srv.port,
        "GET / HTTP/1.1\r\nHost: rebind.attacker.example:8080\r\n\r\n".to_string(),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = raw(srv.port, "GET / HTTP/1.1\r\n\r\n".to_string()).await;
    assert_eq!(status, 403, "Host header is mandatory");
}

#[tokio::test]
async fn static_files_cannot_escape_the_ui_directory() {
    let srv = start().await;
    let (status, body) = raw(srv.port, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".into()).await;
    assert_eq!(status, 200);
    assert!(body.contains("ui"));

    for path in [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/..%2fsecret.txt",
        "/..\\secret.txt",
    ] {
        let (status, body) = raw(
            srv.port,
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 404, "{path}");
        assert!(!body.contains("TOP-SECRET"), "{path} leaked a file");
    }
}

#[tokio::test]
async fn oversized_rpc_body_is_refused_before_reading() {
    let srv = start().await;
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        engine_server::http::MAX_RPC_BODY_BYTES + 1
    );
    let (status, _) = raw(srv.port, req).await;
    assert_eq!(status, 413);

    let (status, _) = raw(
        srv.port,
        "POST /rpc HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
    )
    .await;
    assert_eq!(status, 411);
}

#[tokio::test]
async fn chat_identity_comes_from_the_session() {
    let srv = start().await;
    srv.app
        .storage
        .complete_initial_setup("chat-test-password")
        .unwrap();
    let (_, res) = rpc(
        srv.port,
        "auth.login",
        serde_json::json!({"username": "sirojiddin", "password": "chat-test-password"}),
    )
    .await;
    let token = res["result"]["session"]["token"].as_str().unwrap();
    let (_, res) = rpc(
        srv.port,
        "chat.send",
        serde_json::json!({
            "token": token,
            "body": "hello",
            "author_name": "Somebody Else",
            "author_role": "Owner"
        }),
    )
    .await;
    assert_eq!(res["result"]["author_name"], "Сироҷиддин");
}

#[tokio::test]
async fn database_with_legacy_default_password_requires_setup() {
    let root = std::env::temp_dir().join(format!("soc-legacy-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("case.db");
    {
        let app = EngineApp::new(root.join("cas"), db_path.clone()).unwrap();
        assert!(app.storage.auth_setup_required().unwrap());
    }
    // Older releases seeded the owner with the password "admin".
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE role = 'Owner'",
            [storage_sqlite::collaboration::hash_password("admin")],
        )
        .unwrap();
    }
    let app = EngineApp::new(root.join("cas"), db_path).unwrap();
    assert!(app.storage.auth_setup_required().unwrap());
    assert!(app
        .storage
        .verify_user_password("sirojiddin", "admin")
        .unwrap()
        .is_some());
    assert!(app
        .storage
        .complete_initial_setup("a-new-strong-pass")
        .is_ok());
    assert!(!app.storage.auth_setup_required().unwrap());
    assert!(app
        .storage
        .verify_user_password("sirojiddin", "admin")
        .unwrap()
        .is_none());
    std::fs::remove_dir_all(&root).ok();
}
