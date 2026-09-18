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

pub mod collaboration;
pub mod evidence;
pub mod host_inspector;
pub mod investigation;
pub mod membership;
pub mod scanner;
pub mod scenario_eval;
pub mod scope;

/// Real hostname of the machine this engine is running on, resolved once and
/// cached. Used as the default `host_id` wherever a request omits one --
/// never a placeholder like a hardcoded machine name.
pub fn default_host_id() -> &'static str {
    static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOSTNAME.get_or_init(platform_windows::local_hostname)
}

pub struct EngineApp {
    pub storage: SqliteStorage,
    pub cas: ContentAddressedStorage,
    pub scheduler: WorkflowScheduler,
    pub broker: PrivilegeBroker,
    pub correlation: DeterministicCorrelationEngine,
    pub graph: DeterministicGraphEngine,
    pub diagram: DiagramEngine,
    pub verifier: scenario_verifier::ScenarioVerifier,
    pub scoring: scoring_engine::ScoringEngine,
}

impl EngineApp {
    /// Opens (or creates) a persistent, on-disk case database under `db_path` so
    /// cases, facts and evidence survive process restarts. This is the
    /// constructor production entry points (desktop-app, engine-server bin) must use.
    pub fn new(
        cas_root: PathBuf,
        db_path: PathBuf,
    ) -> Result<Self, storage_sqlite::SqliteStorageError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let storage = SqliteStorage::open(db_path)?;
        Ok(Self::from_storage(storage, cas_root))
    }

    /// Ephemeral, in-memory database. Use only for tests -- all data is lost
    /// when the process exits.
    pub fn new_in_memory(cas_root: PathBuf) -> Self {
        let storage = SqliteStorage::open_in_memory().expect("Failed to init in-memory DB");
        Self::from_storage(storage, cas_root)
    }

    fn from_storage(storage: SqliteStorage, cas_root: PathBuf) -> Self {
        let cas = ContentAddressedStorage::new(cas_root);
        let limiter = ResourceLimiter::new(8, 4, 4, 2, 2);
        let scheduler = WorkflowScheduler::new(limiter);
        let broker = PrivilegeBroker::new(vec![
            core_domain::broker::BrokerCapability::ReadProcesses,
            core_domain::broker::BrokerCapability::ReadFirewall,
            core_domain::broker::BrokerCapability::NetworkScan,
            core_domain::broker::BrokerCapability::CapturePcap,
            core_domain::broker::BrokerCapability::ReadRegistry,
        ]);

        Self {
            storage,
            cas,
            scheduler,
            broker,
            correlation: DeterministicCorrelationEngine::new(),
            graph: DeterministicGraphEngine::new(),
            diagram: DiagramEngine::new(),
            verifier: scenario_verifier::ScenarioVerifier::new(),
            scoring: scoring_engine::ScoringEngine::new(),
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
            "evidence.ingest" => {
                let (res, err) = match evidence::handle_evidence_ingest(
                    req.params,
                    &self.storage,
                    &self.cas,
                    &self.correlation,
                )
                .await
                {
                    Ok(val) => (Some(val), None),
                    Err(e) => (None, Some(e)),
                };
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: res,
                    error: err,
                })
                .unwrap()
            }
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
                let cid = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok());
                let (res, err) = match cid {
                    Some(id) => match self.storage.get_facts_for_case(id) {
                        Ok(f) => (Some(serde_json::to_value(f).unwrap()), None),
                        Err(e) => (
                            None,
                            Some(ProblemDetails::bad_request(&e.to_string(), vec![])),
                        ),
                    },
                    None => (
                        None,
                        Some(ProblemDetails::bad_request(
                            "Missing or invalid case_id",
                            vec!["case_id".to_string()],
                        )),
                    ),
                };
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: res,
                    error: err,
                })
                .unwrap()
            }
            "scan.network" => {
                let subnet = req
                    .params
                    .get("subnet")
                    .and_then(|v| v.as_str())
                    .unwrap_or("192.168.1.0/24");
                let mode = req
                    .params
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("quick");
                let result = scanner::execute_network_scan(subnet, mode).await;
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(result),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "scan.cve" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("h1");
                let result = scanner::execute_cve_scan(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(result),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.overview" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                let val = host_inspector::handle_host_overview(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.snapshot" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                let snap = host_inspector::get_or_collect_snapshot(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(serde_json::to_value(snap).unwrap()),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.processes" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(host_inspector::handle_host_processes(hid)),
                    error: None,
                })
                .unwrap()
            }
            "host.sockets" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(host_inspector::handle_host_sockets(hid)),
                    error: None,
                })
                .unwrap()
            }
            "host.services" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(host_inspector::handle_host_services(hid)),
                    error: None,
                })
                .unwrap()
            }
            "host.persistence" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(host_inspector::handle_host_persistence(hid)),
                    error: None,
                })
                .unwrap()
            }
            "host.software" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(host_inspector::handle_host_software(hid)),
                    error: None,
                })
                .unwrap()
            }
            "scenario.evaluate" => {
                let sid = req
                    .params
                    .get("scenario_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("SCEN-APT29");
                let hyp = req
                    .params
                    .get("hypothesis")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let cid = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok())
                    .unwrap_or_else(EntityId::new_v7);
                let res = scenario_eval::evaluate_scenario(
                    &self.storage,
                    &self.verifier,
                    &self.scoring,
                    sid,
                    hyp,
                    cid,
                );
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(res),
                    error: None,
                })
                .unwrap()
            }
            "host.correlate" | "correlation.evaluate" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host_id());
                let raw_case_id = req.params.get("case_id").and_then(|v| v.as_str());
                let cid = match raw_case_id.map(EntityId::parse) {
                    Some(Ok(id)) => id,
                    _ => {
                        let resp: IpcResponse<()> = IpcResponse {
                            api_version: 1,
                            request_id: req.request_id,
                            result: None,
                            error: Some(ProblemDetails::bad_request(
                                "Missing or invalid case_id -- create or select a case first",
                                vec!["case_id".to_string()],
                            )),
                        };
                        return serde_json::to_string(&resp).unwrap();
                    }
                };
                if req
                    .params
                    .get("refresh")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    host_inspector::refresh_snapshot(hid);
                }
                let val = host_inspector::handle_host_correlation(
                    hid,
                    cid,
                    &self.storage,
                    &self.correlation,
                );
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                })
                .unwrap()
            }
            m if m.starts_with("investigation.")
                || m.starts_with("graph.")
                || m.starts_with("timeline.")
                || m == "chat.entity.thread" =>
            {
                let handler = investigation::InvestigationHandler::new(
                    &self.storage,
                    &self.correlation,
                    &self.graph,
                );
                let (res, err) = match handler.handle(m, req.params).await {
                    Ok(val) => (Some(val), None),
                    Err(e) => (None, Some(e)),
                };
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: res,
                    error: err,
                })
                .unwrap()
            }
            m if m.starts_with("auth.")
                || m.starts_with("team.")
                || m.starts_with("chat.")
                || m.starts_with("presence.")
                || m.starts_with("invite.")
                || m.starts_with("workspace.")
                || m.starts_with("member.")
                || m.starts_with("case.")
                || m == "ownership.transfer"
                || m == "membership.audit"
                || m == "entity.get" =>
            {
                let handler = collaboration::CollabHandler::new(&self.storage);
                let (res, err) = match handler.handle(m, req.params) {
                    Ok(val) => (Some(val), None),
                    Err(e) => (None, Some(e)),
                };
                serde_json::to_string(&IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: res,
                    error: err,
                })
                .unwrap()
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

pub mod http;
pub use http::{bind_server, handle_connection, run_embedded_server, run_server_loop};
