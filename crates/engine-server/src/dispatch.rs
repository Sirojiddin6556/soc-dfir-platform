#![forbid(unsafe_code)]

use crate::collaboration;
use crate::evidence;
use crate::host_inspector;
use crate::investigation;
use crate::scanner;
use crate::scenario_eval;
use crate::EngineApp;
use core_domain::id::EntityId;
use ipc_protocol::{ApiDispatcher, CreateCaseParams, IpcRequest, IpcResponse, ProblemDetails};

fn respond_res<T: serde::Serialize>(req_id: String, res: Result<T, ProblemDetails>) -> String {
    let (val, err) = match res {
        Ok(v) => (
            Some(serde_json::to_value(v).unwrap_or(serde_json::Value::Null)),
            None,
        ),
        Err(e) => (None, Some(e)),
    };
    serde_json::to_string(&IpcResponse {
        api_version: 1,
        request_id: req_id,
        result: val,
        error: err,
    })
    .unwrap()
}

impl EngineApp {
    /// Dispatches incoming JSON-RPC command
    pub async fn dispatch_request(&self, req_json: &str) -> String {
        if req_json.contains("\"jsonrpc\"") {
            if let Some(resp) = crate::ctf_dispatch::try_dispatch_jsonrpc(self, req_json).await {
                return resp;
            }
        }

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

        let method = req.method.as_str();
        match method {
            "health" => {
                let health = ApiDispatcher::handle_health();
                respond_res(req.request_id, Ok::<_, ProblemDetails>(health))
            }
            "cases.list" => {
                let res = self
                    .storage
                    .list_cases()
                    .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]));
                respond_res(req.request_id, res)
            }
            "cases.create" => {
                let params_res: Result<CreateCaseParams, _> = serde_json::from_value(req.params);
                match params_res {
                    Ok(p) => {
                        let case_id = EntityId::new_v7();
                        let desc = p.description.as_deref();
                        let res = self
                            .storage
                            .insert_case(case_id, &p.title, desc)
                            .map(|_| {
                                serde_json::json!({
                                    "case_id": case_id.to_string(),
                                    "id": case_id.to_string(),
                                    "title": p.title,
                                    "description": p.description,
                                    "status": "Active",
                                })
                            })
                            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]));
                        respond_res(req.request_id, res)
                    }
                    Err(e) => respond_res::<()>(
                        req.request_id,
                        Err(ProblemDetails::bad_request(
                            &e.to_string(),
                            vec!["params".to_string()],
                        )),
                    ),
                }
            }
            "evidence.ingest.begin" => {
                let res =
                    evidence::handle_ingest_begin(req.params, &self.session_mgr, &self.storage)
                        .await;
                respond_res(req.request_id, res)
            }
            "evidence.ingest.complete" => {
                let res = evidence::handle_ingest_complete(
                    req.params,
                    &self.session_mgr,
                    &self.storage,
                    &self.cas,
                    &self.correlation,
                )
                .await;
                respond_res(req.request_id, res)
            }
            "evidence.ingest.status" => {
                let res =
                    evidence::handle_ingest_status(req.params, &self.session_mgr, &self.storage)
                        .await;
                respond_res(req.request_id, res)
            }
            "evidence.ingest.cancel" => {
                let res =
                    evidence::handle_ingest_cancel(req.params, &self.session_mgr, &self.storage)
                        .await;
                respond_res(req.request_id, res)
            }
            "evidence.custody.verify" => {
                let res = evidence::handle_custody_verify(req.params, &self.storage).await;
                respond_res(req.request_id, res)
            }
            "evidence.ingest" => {
                let res = evidence::handle_evidence_ingest(
                    req.params,
                    &self.storage,
                    &self.cas,
                    &self.correlation,
                )
                .await;
                respond_res(req.request_id, res)
            }
            "broker.execute" => {
                let op: Result<core_domain::broker::PrivilegedOperation, _> =
                    serde_json::from_value(req.params);
                match op {
                    Ok(operation) => {
                        let res = match self.broker.execute_operation(operation).await {
                            Ok(tool_res) => {
                                let val = serde_json::from_slice::<serde_json::Value>(&tool_res)
                                    .unwrap_or_else(|_| {
                                        serde_json::Value::String(
                                            String::from_utf8_lossy(&tool_res).to_string(),
                                        )
                                    });
                                Ok(val)
                            }
                            Err(e) => Err(ProblemDetails::forbidden(&e.to_string())),
                        };
                        respond_res(req.request_id, res)
                    }
                    Err(e) => respond_res::<()>(
                        req.request_id,
                        Err(ProblemDetails::bad_request(
                            &e.to_string(),
                            vec!["operation".to_string()],
                        )),
                    ),
                }
            }
            "facts.list" => {
                let cid = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok());
                let res = match cid {
                    Some(id) => self
                        .storage
                        .get_facts_for_case(id)
                        .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![])),
                    None => Err(ProblemDetails::bad_request(
                        "Missing or invalid case_id",
                        vec!["case_id".to_string()],
                    )),
                };
                respond_res(req.request_id, res)
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
                respond_res(req.request_id, Ok::<_, ProblemDetails>(result))
            }
            "scan.cve" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("h1");
                let result = scanner::execute_cve_scan(host_id);
                respond_res(req.request_id, Ok::<_, ProblemDetails>(result))
            }
            "host.overview" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let val = host_inspector::handle_host_overview(host_id);
                respond_res(req.request_id, Ok::<_, ProblemDetails>(val))
            }
            "host.snapshot" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let snap = host_inspector::get_or_collect_snapshot(host_id);
                respond_res(
                    req.request_id,
                    Ok::<_, ProblemDetails>(serde_json::to_value(snap).unwrap()),
                )
            }
            "host.processes" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let val = host_inspector::handle_host_processes(hid);
                respond_res(req.request_id, Ok::<_, ProblemDetails>(val))
            }
            "host.sockets" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let val = host_inspector::handle_host_sockets(hid);
                respond_res(req.request_id, Ok::<_, ProblemDetails>(val))
            }
            "host.services" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let val = host_inspector::handle_host_services(hid);
                respond_res(req.request_id, Ok::<_, ProblemDetails>(val))
            }
            "host.persistence" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let val = host_inspector::handle_host_persistence(hid);
                respond_res(req.request_id, Ok::<_, ProblemDetails>(val))
            }
            "host.software" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let val = host_inspector::handle_host_software(hid);
                respond_res(req.request_id, Ok::<_, ProblemDetails>(val))
            }
            "host.correlate" | "correlation.evaluate" => {
                let hid = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id());
                let raw_case_id = req.params.get("case_id").and_then(|v| v.as_str());
                let cid = match raw_case_id.map(EntityId::parse) {
                    Some(Ok(id)) => id,
                    _ => {
                        return respond_res::<()>(
                            req.request_id,
                            Err(ProblemDetails::bad_request(
                                "Missing or invalid case_id -- create or select a case first",
                                vec!["case_id".to_string()],
                            )),
                        );
                    }
                };
                if req
                    .params
                    .get("refresh")
                    .or_else(|| req.params.get("force_refresh"))
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
                respond_res(req.request_id, Ok::<_, ProblemDetails>(val))
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
                respond_res(req.request_id, Ok::<_, ProblemDetails>(res))
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
                let res = handler.handle(m, req.params).await;
                respond_res(req.request_id, res)
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
                let res = handler.handle(m, req.params);
                respond_res(req.request_id, res)
            }
            "evidence.list" => {
                let cid = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok());
                let res = match cid {
                    Some(cid) => self
                        .storage
                        .list_artifacts_for_case(cid)
                        .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![])),
                    None => Err(ProblemDetails::bad_request(
                        "Missing or invalid case_id",
                        vec!["case_id".to_string()],
                    )),
                };
                respond_res(req.request_id, res)
            }
            "evidence.observations" => {
                let aid = req
                    .params
                    .get("artifact_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok());
                let res = match aid {
                    Some(aid) => self
                        .storage
                        .list_observations_for_artifact(aid)
                        .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![])),
                    None => Err(ProblemDetails::bad_request(
                        "Missing or invalid artifact_id",
                        vec!["artifact_id".to_string()],
                    )),
                };
                respond_res(req.request_id, res)
            }
            "evidence.custody" => {
                let hash = req
                    .params
                    .get("artifact_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let res = if hash.is_empty() {
                    Err(ProblemDetails::bad_request(
                        "Missing artifact_hash",
                        vec!["artifact_hash".to_string()],
                    ))
                } else {
                    self.storage
                        .list_custody_chain(hash)
                        .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))
                };
                respond_res(req.request_id, res)
            }
            "evidence.delete" => {
                let aid = req
                    .params
                    .get("artifact_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok());
                let cid = req
                    .params
                    .get("case_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| EntityId::parse(s).ok());
                let res = match (aid, cid) {
                    (Some(a), Some(c)) => self
                        .storage
                        .delete_artifact(a, c)
                        .map(|deleted| serde_json::json!({ "deleted": deleted }))
                        .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![])),
                    _ => Err(ProblemDetails::bad_request(
                        "Missing artifact_id or case_id",
                        vec!["artifact_id".to_string(), "case_id".to_string()],
                    )),
                };
                respond_res(req.request_id, res)
            }
            m if m.starts_with("competitions.")
                || m.starts_with("challenges.")
                || m.starts_with("artifacts.")
                || m.starts_with("tools.")
                || m.starts_with("jobs.")
                || m.starts_with("recipes.")
                || m.starts_with("flags.")
                || m.starts_with("writeups.") =>
            {
                let res = crate::ctf_dispatch::handle_ctf_command(self, m, req.params)
                    .await
                    .map_err(|e| ipc_protocol::domain_error_to_problem_details(&e));
                respond_res(req.request_id, res)
            }
            _ => {
                let err_resp: IpcResponse<()> = IpcResponse {
                    api_version: 1,
                    request_id: req.request_id,
                    result: None,
                    error: Some(ProblemDetails::not_found(&format!(
                        "Unknown method: {}",
                        req.method
                    ))),
                };
                serde_json::to_string(&err_resp).unwrap()
            }
        }
    }
}
