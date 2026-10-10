#![forbid(unsafe_code)]

use crate::host_inspector;
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
            "scan.cve" => {
                let host_id = req
                    .params
                    .get("host_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::default_host_id())
                    .to_string();
                let vulndb = self.vulndb.clone();
                let result =
                    tokio::task::spawn_blocking(move || vulndb.scan_local_packages(&host_id))
                        .await
                        .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]));
                respond_res(req.request_id, result)
            }
            "vulndb.status" => {
                let vulndb = self.vulndb.clone();
                let result = tokio::task::spawn_blocking(move || vulndb.status())
                    .await
                    .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]));
                respond_res(req.request_id, result)
            }
            "vulndb.update" => {
                let ecosystems: Vec<String> = req
                    .params
                    .get("ecosystems")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|e| e.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let msrc_months = match req.params.get("msrc_months") {
                    None => Ok(None),
                    Some(v) if v.is_null() => Ok(None),
                    Some(v) => v
                        .as_u64()
                        .and_then(|m| u32::try_from(m).ok())
                        .map(Some)
                        .ok_or_else(|| "msrc_months должно быть целым числом месяцев".to_string()),
                };
                let res = msrc_months
                    .and_then(|months| self.vulndb.start_update(ecosystems, months))
                    .map_err(|e| {
                        let field = if e.contains("msrc_months") {
                            "msrc_months"
                        } else {
                            "ecosystems"
                        };
                        ProblemDetails::bad_request(&e, vec![field.to_string()])
                    });
                respond_res(req.request_id, res)
            }
            "code.scan" => {
                let path = req
                    .params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let flag = |name: &str| {
                    req.params
                        .get(name)
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                };
                let res = self
                    .code_scan
                    .start(path, flag("external_sources"), flag("include_tests"))
                    .map_err(|e| ProblemDetails::bad_request(&e, vec!["path".to_string()]));
                respond_res(req.request_id, res)
            }
            "code.status" => {
                let res = Ok::<_, ProblemDetails>(self.code_scan.status());
                respond_res(req.request_id, res)
            }
            "web.scan" => {
                let res = self
                    .web_scan
                    .start(&req.params)
                    .map_err(|e| ProblemDetails::bad_request(&e, vec!["url".to_string()]));
                respond_res(req.request_id, res)
            }
            "web.status" => {
                let res = Ok::<_, ProblemDetails>(self.web_scan.status());
                respond_res(req.request_id, res)
            }
            "code.deps" => {
                let code_scan = self.code_scan.clone();
                let res = tokio::task::spawn_blocking(move || code_scan.recheck_dependencies())
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| r)
                    .map_err(|e| ProblemDetails::bad_request(&e, vec![]));
                respond_res(req.request_id, res)
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
            m if m.starts_with("auth.") => {
                let res = crate::auth::handle_auth(self, m, req.params);
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
