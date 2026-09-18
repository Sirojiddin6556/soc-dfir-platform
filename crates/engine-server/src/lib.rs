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

pub mod host_inspector;
pub mod scanner;
pub mod scenario_eval;

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
    pub fn new_in_memory(cas_root: PathBuf) -> Self {
        let storage = SqliteStorage::open_in_memory().expect("Failed to init in-memory DB");
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
                    .unwrap_or("PC-3002");
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
                    .unwrap_or("PC-3002");
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
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PC-3002");
                let val = host_inspector::handle_host_processes(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.sockets" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PC-3002");
                let val = host_inspector::handle_host_sockets(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.services" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PC-3002");
                let val = host_inspector::handle_host_services(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.persistence" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PC-3002");
                let val = host_inspector::handle_host_persistence(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.software" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PC-3002");
                let val = host_inspector::handle_host_software(host_id);
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "scenario.evaluate" => {
                let scenario_id = req
                    .params
                    .get("scenario_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("SCEN-APT29");
                let hypothesis = req
                    .params
                    .get("hypothesis")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let case_id = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok())
                    .unwrap_or_else(EntityId::new_v7);
                let result = scenario_eval::evaluate_scenario(
                    &self.storage,
                    &self.verifier,
                    &self.scoring,
                    scenario_id,
                    hypothesis,
                    case_id,
                );
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(result),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
            }
            "host.correlate" | "correlation.evaluate" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PC-3002");
                let case_id = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok())
                    .unwrap_or_else(EntityId::new_v7);
                let val = host_inspector::handle_host_correlation(
                    host_id,
                    case_id,
                    &self.storage,
                    &self.correlation,
                );
                let resp = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: Some(val),
                    error: None,
                };
                serde_json::to_string(&resp).unwrap()
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
