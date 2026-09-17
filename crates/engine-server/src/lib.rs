#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use correlation_engine::DeterministicCorrelationEngine;
use diagram_engine::DiagramEngine;
use graph_engine::DeterministicGraphEngine;
use ipc_protocol::{ApiDispatcher, CreateCaseParams, IpcRequest, IpcResponse, ProblemDetails};
use privilege_broker::PrivilegeBroker;
use storage_cas::ContentAddressedStorage;
use storage_sqlite::SqliteStorage;
use workflow_dag::{ResourceLimiter, WorkflowScheduler};

use std::path::PathBuf;

pub struct EngineApp {
    pub storage: SqliteStorage,
    pub cas: ContentAddressedStorage,
    pub scheduler: WorkflowScheduler,
    pub broker: PrivilegeBroker,
    pub correlation: DeterministicCorrelationEngine,
    pub graph: DeterministicGraphEngine,
    pub diagram: DiagramEngine,
}

impl EngineApp {
    pub fn new_in_memory(cas_root: PathBuf) -> Self {
        let storage = SqliteStorage::open_in_memory().expect("Failed to init in-memory DB");
        let cas = ContentAddressedStorage::new(cas_root);
        let limiter = ResourceLimiter::new(8, 4, 4, 2, 2);
        let scheduler = WorkflowScheduler::new(limiter);
        let broker = PrivilegeBroker::new(vec![
            core_domain::broker::BrokerCapability::ReadProcesses,
            core_domain::broker::BrokerCapability::ReadFirewall,
        ]);

        Self {
            storage,
            cas,
            scheduler,
            broker,
            correlation: DeterministicCorrelationEngine::new(),
            graph: DeterministicGraphEngine::new(),
            diagram: DiagramEngine::new(),
        }
    }

    /// Dispatches incoming JSON-RPC command
    pub async fn dispatch_request(&self, req_json: &str) -> String {
        let parsed: Result<IpcRequest<serde_json::Value>, _> = serde_json::from_str(req_json);
        let req = match parsed {
            Ok(r) => r,
            Err(e) => {
                let err_resp: IpcResponse<()> = IpcResponse {
                    api_version: 1,
                    request_id: "unknown".to_string(),
                    result: None,
                    error: Some(ProblemDetails::bad_request(
                        &e.to_string(),
                        vec!["json".to_string()],
                    )),
                };
                return serde_json::to_string(&err_resp).unwrap();
            }
        };

        if let Err(err) = ApiDispatcher::validate_version(req.api_version) {
            let err_resp: IpcResponse<()> = IpcResponse {
                api_version: req.api_version,
                request_id: req.request_id,
                result: None,
                error: Some(err),
            };
            return serde_json::to_string(&err_resp).unwrap();
        }

        match req.method.as_str() {
            "health" => {
                let health = ApiDispatcher::handle_health();
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(serde_json::to_value(health).unwrap()),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "cases.create" => {
                let params: Result<CreateCaseParams, _> = serde_json::from_value(req.params);
                match params {
                    Ok(p) => {
                        let new_id = EntityId::new_v7();
                        if let Err(e) =
                            self.storage
                                .insert_case(new_id, &p.title, p.description.as_deref())
                        {
                            let resp: IpcResponse<()> = IpcResponse {
                                api_version: 1,
                                request_id: req.request_id,
                                result: None,
                                error: Some(ProblemDetails::bad_request(&e.to_string(), vec![])),
                            };
                            serde_json::to_string(&resp).unwrap()
                        } else {
                            let resp = IpcResponse {
                                api_version: 1,
                                request_id: req.request_id,
                                result: Some(serde_json::json!({
                                    "case_id": new_id.to_string(),
                                    "title": p.title,
                                    "status": "Active"
                                })),
                                error: None,
                            };
                            serde_json::to_string(&resp).unwrap()
                        }
                    }
                    Err(e) => {
                        let resp: IpcResponse<()> = IpcResponse {
                            api_version: 1,
                            request_id: req.request_id,
                            result: None,
                            error: Some(ProblemDetails::bad_request(
                                &e.to_string(),
                                vec!["params".to_string()],
                            )),
                        };
                        serde_json::to_string(&resp).unwrap()
                    }
                }
            }
            "cases.list" => match self.storage.list_cases() {
                Ok(cases) => {
                    let resp = IpcResponse {
                        api_version: 1,
                        request_id: req.request_id,
                        result: Some(serde_json::to_value(cases).unwrap()),
                        error: None,
                    };
                    serde_json::to_string(&resp).unwrap()
                }
                Err(e) => {
                    let resp: IpcResponse<()> = IpcResponse {
                        api_version: 1,
                        request_id: req.request_id,
                        result: None,
                        error: Some(ProblemDetails::bad_request(&e.to_string(), vec![])),
                    };
                    serde_json::to_string(&resp).unwrap()
                }
            },
            "broker.execute" => {
                let op: Result<core_domain::broker::PrivilegedOperation, _> =
                    serde_json::from_value(req.params);
                match op {
                    Ok(operation) => match self.broker.execute_operation(operation).await {
                        Ok(tool_res) => {
                            let val = serde_json::from_slice::<serde_json::Value>(&tool_res)
                                .unwrap_or_else(|_| {
                                    serde_json::Value::String(
                                        String::from_utf8_lossy(&tool_res).to_string(),
                                    )
                                });
                            let resp = IpcResponse {
                                api_version: 1,
                                request_id: req.request_id,
                                result: Some(val),
                                error: None,
                            };
                            serde_json::to_string(&resp).unwrap()
                        }
                        Err(e) => {
                            let resp: IpcResponse<()> = IpcResponse {
                                api_version: 1,
                                request_id: req.request_id,
                                result: None,
                                error: Some(ProblemDetails::forbidden(&e.to_string())),
                            };
                            serde_json::to_string(&resp).unwrap()
                        }
                    },
                    Err(e) => {
                        let resp: IpcResponse<()> = IpcResponse {
                            api_version: 1,
                            request_id: req.request_id,
                            result: None,
                            error: Some(ProblemDetails::bad_request(
                                &e.to_string(),
                                vec!["operation".to_string()],
                            )),
                        };
                        serde_json::to_string(&resp).unwrap()
                    }
                }
            }
            "facts.list" => {
                let case_id_opt = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str().map(|s| s.to_string()));
                match case_id_opt {
                    Some(cid_str) => {
                        if let Ok(cid) = EntityId::parse(&cid_str) {
                            match self.storage.get_facts_for_case(cid) {
                                Ok(facts) => {
                                    let resp = IpcResponse {
                                        api_version: 1,
                                        request_id: req.request_id,
                                        result: Some(serde_json::to_value(facts).unwrap()),
                                        error: None,
                                    };
                                    serde_json::to_string(&resp).unwrap()
                                }
                                Err(e) => {
                                    let resp: IpcResponse<()> = IpcResponse {
                                        api_version: 1,
                                        request_id: req.request_id,
                                        result: None,
                                        error: Some(ProblemDetails::bad_request(
                                            &e.to_string(),
                                            vec![],
                                        )),
                                    };
                                    serde_json::to_string(&resp).unwrap()
                                }
                            }
                        } else {
                            let resp: IpcResponse<()> = IpcResponse {
                                api_version: 1,
                                request_id: req.request_id,
                                result: None,
                                error: Some(ProblemDetails::bad_request(
                                    "Invalid case_id format",
                                    vec!["case_id".to_string()],
                                )),
                            };
                            serde_json::to_string(&resp).unwrap()
                        }
                    }
                    None => {
                        let resp: IpcResponse<()> = IpcResponse {
                            api_version: 1,
                            request_id: req.request_id,
                            result: None,
                            error: Some(ProblemDetails::bad_request(
                                "Missing case_id parameter",
                                vec!["case_id".to_string()],
                            )),
                        };
                        serde_json::to_string(&resp).unwrap()
                    }
                }
            }
            _ => {
                let resp: IpcResponse<()> = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: None,
                    error: Some(ProblemDetails::not_found(&format!(
                        "Unknown method: {}",
                        req.method
                    ))),
                };
                serde_json::to_string(&resp).unwrap()
            }
        }
    }
}

use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Runs the embedded HTTP & IPC server on the specified address
pub async fn run_embedded_server(
    addr: &str,
    cas_dir: PathBuf,
    ui_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Arc::new(EngineApp::new_in_memory(cas_dir));
    let listener = TcpListener::bind(addr).await?;
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

pub async fn handle_connection(
    mut stream: TcpStream,
    app: Arc<EngineApp>,
    ui_dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_engine_app_composition_and_dispatch() {
        let temp_dir = std::env::temp_dir().join(format!("engine_test_{}", uuid::Uuid::now_v7()));
        let app = Arc::new(EngineApp::new_in_memory(temp_dir.clone()));

        // 1. Test Health Probe
        let health_req =
            r#"{"api_version": 1, "request_id": "req-1", "method": "health", "params": {}}"#;
        let health_resp = app.dispatch_request(health_req).await;
        assert!(health_resp.contains("\"live\":true"));

        // 2. Test Case Creation
        let case_req = r#"{"api_version": 1, "request_id": "req-2", "method": "cases.create", "params": {"title": "Incident Beta", "description": "Automated test"}}"#;
        let case_resp = app.dispatch_request(case_req).await;
        assert!(case_resp.contains("\"case_id\""));
        assert!(case_resp.contains("\"status\":\"Active\""));

        // 3. Test Cases List
        let list_req =
            r#"{"api_version": 1, "request_id": "req-3", "method": "cases.list", "params": {}}"#;
        let list_resp = app.dispatch_request(list_req).await;
        assert!(list_resp.contains("Incident Beta"));

        // 4. Test Broker Execute (Authorized: ReadProcesses)
        let broker_req = r#"{"api_version": 1, "request_id": "req-4", "method": "broker.execute", "params": {"CollectProcessMetadata": {"pid": 1234}}}"#;
        let broker_resp = app.dispatch_request(broker_req).await;
        assert!(broker_resp.contains("\"status\":\"running\""));

        // 5. Test Broker Execute (Forbidden: AcquireMemorySample without capability)
        let mem_req = r#"{"api_version": 1, "request_id": "req-5", "method": "broker.execute", "params": {"AcquireMemorySample": {"target": {"ProcessPid": 1234}, "chunk_size_mb": 64}}}"#;
        let mem_resp = app.dispatch_request(mem_req).await;
        assert!(mem_resp.contains("\"status\":403"));
        assert!(mem_resp.contains("Forbidden"));

        // 6. Test Unknown Method -> RFC 7807 404
        let unknown_req =
            r#"{"api_version": 1, "request_id": "req-6", "method": "non_existent", "params": {}}"#;
        let unknown_resp = app.dispatch_request(unknown_req).await;
        assert!(unknown_resp.contains("\"status\":404"));
        assert!(unknown_resp.contains("Not Found"));

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }
}
