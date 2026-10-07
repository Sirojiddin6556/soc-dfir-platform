#![forbid(unsafe_code)]

//! Session gate for the RPC endpoint.
//!
//! Every RPC method except the few listed in [`PUBLIC_METHODS`] requires a
//! valid session token in `params.token`. The check runs at the HTTP
//! boundary, before the request reaches [`EngineApp::dispatch_request`], so
//! a page in the user's browser that cannot read the token cannot drive the
//! engine either.

use crate::EngineApp;
use core_domain::collaboration::User;
use ipc_protocol::{IpcResponse, ProblemDetails};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Methods callable without a session: liveness, the first-run setup and
/// the login itself.
pub const PUBLIC_METHODS: &[&str] = &["health", "auth.status", "auth.setup", "auth.login"];

pub fn is_public_method(method: &str) -> bool {
    PUBLIC_METHODS.contains(&method)
}

/// Resolves the user behind `params.token`, if the session is valid and not
/// expired.
pub fn user_from_params(app: &EngineApp, params: &serde_json::Value) -> Option<User> {
    let token = params.get("token").and_then(|t| t.as_str())?;
    app.storage.get_user_by_token(token).ok().flatten()
}

/// Checks that an RPC body may be dispatched. On refusal returns the error
/// body to send, already shaped for the protocol the caller used (JSON-RPC
/// 2.0 for the CTF client, the IPC envelope otherwise).
pub fn authorize_rpc(app: &EngineApp, body: &str) -> Result<(), String> {
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return Err(ipc_error(
                "unknown",
                ProblemDetails::bad_request(&e.to_string(), vec!["json".to_string()]),
            ))
        }
    };
    let method = value.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if is_public_method(method) {
        return Ok(());
    }
    let params = value.get("params").cloned().unwrap_or_default();
    if user_from_params(app, &params).is_some() {
        return Ok(());
    }

    let detail = "Требуется вход в систему: сессия отсутствует или истекла";
    if value.get("jsonrpc").is_some() {
        let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
        Err(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32001, "message": detail, "data": { "status": 401 } }
        })
        .to_string())
    } else {
        let req_id = value
            .get("request_id")
            .and_then(|r| r.as_str())
            .unwrap_or("unknown");
        Err(ipc_error(req_id, ProblemDetails::unauthorized(detail)))
    }
}

fn ipc_error(request_id: &str, problem: ProblemDetails) -> String {
    serde_json::to_string(&IpcResponse::<()> {
        api_version: 1,
        request_id: request_id.to_string(),
        result: None,
        error: Some(problem),
    })
    .unwrap_or_default()
}

/// Slows down password guessing: after [`MAX_FAILURES`] wrong passwords in a
/// row, logins are refused for [`LOCKOUT`].
pub struct LoginThrottle {
    state: Mutex<(u32, Option<Instant>)>,
}

const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(30);

impl LoginThrottle {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new((0, None)),
        }
    }

    /// Seconds left before another attempt is allowed, if locked.
    pub fn locked_for(&self) -> Option<u64> {
        let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match guard.1 {
            Some(until) if until > Instant::now() => {
                Some((until - Instant::now()).as_secs().max(1))
            }
            _ => None,
        }
    }

    pub fn record_failure(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        guard.0 += 1;
        if guard.0 >= MAX_FAILURES {
            guard.0 = 0;
            guard.1 = Some(Instant::now() + LOCKOUT);
        }
    }

    pub fn record_success(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        *guard = (0, None);
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// Handles the `auth.*` methods.
pub fn handle_auth(
    app: &EngineApp,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, ProblemDetails> {
    match method {
        "auth.status" => {
            let setup_required = app.storage.auth_setup_required().map_err(storage_err)?;
            Ok(serde_json::json!({
                "setup_required": setup_required,
                "min_password_length": storage_sqlite::collaboration::MIN_PASSWORD_LEN,
            }))
        }
        "auth.setup" => {
            let password = str_param(&params, "password")?;
            let user = app
                .storage
                .complete_initial_setup(password)
                .map_err(storage_err)?;
            let session = app
                .storage
                .create_session(user.id, &user.username)
                .map_err(storage_err)?;
            tracing::info!("Initial owner password set for '{}'", user.username);
            Ok(serde_json::json!({ "user": user, "session": session }))
        }
        "auth.login" => {
            if let Some(secs) = app.login_throttle.locked_for() {
                return Err(ProblemDetails::forbidden(&format!(
                    "Слишком много неудачных попыток. Повторите через {secs} с"
                )));
            }
            if app.storage.auth_setup_required().map_err(storage_err)? {
                return Err(ProblemDetails::forbidden(
                    "Пароль владельца ещё не задан: выполните первичную настройку",
                ));
            }
            let username = str_param(&params, "username")?;
            let password = params
                .get("password")
                .and_then(|p| p.as_str())
                .unwrap_or("");
            let user = app
                .storage
                .verify_user_password(username, password)
                .map_err(storage_err)?;
            let Some(user) = user else {
                app.login_throttle.record_failure();
                return Err(ProblemDetails::unauthorized(
                    "Неверное имя пользователя или пароль",
                ));
            };
            app.login_throttle.record_success();
            let session = app
                .storage
                .create_session(user.id, &user.username)
                .map_err(storage_err)?;
            Ok(serde_json::json!({ "user": user, "session": session }))
        }
        "auth.logout" => {
            let token = params.get("token").and_then(|t| t.as_str()).unwrap_or("");
            app.storage.delete_session(token).map_err(storage_err)?;
            Ok(serde_json::json!({ "success": true }))
        }
        "auth.session" => {
            let user = user_from_params(app, &params)
                .ok_or_else(|| ProblemDetails::unauthorized("Сессия не найдена или истекла"))?;
            Ok(serde_json::json!({ "user": user }))
        }
        "auth.change_password" => {
            let user = user_from_params(app, &params)
                .ok_or_else(|| ProblemDetails::unauthorized("Сессия не найдена или истекла"))?;
            let current = str_param(&params, "current_password")?;
            let new = str_param(&params, "new_password")?;
            let changed = app
                .storage
                .change_user_password(user.id, current, new)
                .map_err(storage_err)?;
            if !changed {
                return Err(ProblemDetails::unauthorized("Текущий пароль неверен"));
            }
            let session = app
                .storage
                .create_session(user.id, &user.username)
                .map_err(storage_err)?;
            Ok(serde_json::json!({ "user": user, "session": session }))
        }
        _ => Err(ProblemDetails::not_found(&format!(
            "Неизвестный метод: {method}"
        ))),
    }
}

fn str_param<'a>(params: &'a serde_json::Value, name: &str) -> Result<&'a str, ProblemDetails> {
    params
        .get(name)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            ProblemDetails::bad_request(
                &format!("Параметр {name} обязателен"),
                vec![name.to_string()],
            )
        })
}

fn storage_err(e: storage_sqlite::SqliteStorageError) -> ProblemDetails {
    match e {
        storage_sqlite::SqliteStorageError::Validation(msg) => {
            ProblemDetails::bad_request(&msg, vec!["password".to_string()])
        }
        other => ProblemDetails::bad_request(&other.to_string(), vec![]),
    }
}
