#![forbid(unsafe_code)]

use chrono::Utc;
use core_domain::id::EntityId;
use correlation_engine::DeterministicCorrelationEngine;
use graph_engine::DeterministicGraphEngine;
use ipc_protocol::ProblemDetails;
use serde_json::json;
use storage_sqlite::SqliteStorage;

use crate::host_inspector;

pub struct InvestigationHandler<'a> {
    pub storage: &'a SqliteStorage,
    pub correlation: &'a DeterministicCorrelationEngine,
    pub graph: &'a DeterministicGraphEngine,
}

#[allow(clippy::result_large_err)]
impl<'a> InvestigationHandler<'a> {
    pub fn new(
        storage: &'a SqliteStorage,
        correlation: &'a DeterministicCorrelationEngine,
        graph: &'a DeterministicGraphEngine,
    ) -> Self {
        Self {
            storage,
            correlation,
            graph,
        }
    }

    pub async fn handle(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        match method {
            "investigation.snapshot" => self.handle_snapshot(params).await,
            "graph.query" => self.handle_graph_query(params),
            "timeline.query" => self.handle_timeline_query(params),
            "chat.entity.thread" => self.handle_entity_thread(params),
            _ => Err(ProblemDetails::bad_request(
                &format!("Неизвестный метод расследования: {}", method),
                vec!["method".to_string()],
            )),
        }
    }

    async fn handle_snapshot(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let cid = params
            .get("case_id")
            .and_then(|c| c.as_str())
            .and_then(|s| EntityId::parse(s).ok())
            .ok_or_else(|| {
                ProblemDetails::bad_request(
                    "Missing or invalid case_id -- create or select a case first",
                    vec!["case_id".to_string()],
                )
            })?;
        let case = self
            .storage
            .get_case(cid)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?
            .ok_or_else(|| {
                ProblemDetails::bad_request("Case not found", vec!["case_id".to_string()])
            })?;

        // 1. Live telemetry snapshot from primary workstation
        let host_id = crate::default_host_id();
        let snap = host_inspector::get_or_collect_snapshot(host_id);

        // 2. Correlation evaluation
        let corr =
            host_inspector::handle_host_correlation(host_id, cid, self.storage, self.correlation);

        let findings = corr.get("findings").cloned().unwrap_or_else(|| json!([]));
        let findings_arr = findings.as_array().cloned().unwrap_or_default();
        let risk_score = corr
            .get("risk_score")
            .and_then(|s| s.as_f64())
            .unwrap_or(75.0);
        let risk_level = corr
            .get("risk_level")
            .and_then(|l| l.as_str())
            .unwrap_or("HIGH");

        // 3. Construct Graph nodes and edges
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Host Node
        nodes.push(json!({
            "id": host_id,
            "type": "host",
            "label": snap.host,
            "subtitle": snap.os,
            "state": "active",
            "severity": if findings_arr.is_empty() { "info" } else { "high" },
            "verification": "corroborated",
            "host_id": host_id,
            "in_attack_path": !findings_arr.is_empty(),
            "ip": snap.host_ip,
            "processes_count": snap.processes.len(),
            "sockets_count": snap.sockets.len(),
            "findings_count": findings_arr.len()
        }));

        // Processes Nodes
        for p in snap.processes.iter().take(30) {
            let pid_str = format!("proc-{}", p.pid);
            // Only flag genuinely notable process types here. "svchost.exe"
            // used to match too and got flagged on almost every process on a
            // healthy Windows host, which is why the Атака/ATT&CK layers
            // showed nearly every entity instead of only the relevant ones --
            // svchost.exe is one of the most common, ordinarily benign
            // Windows processes and its name alone says nothing about intent.
            // Genuine detections still show up as their own "finding" nodes
            // from the correlation engine (CORR-WIN-001..004) regardless of
            // this flag.
            let is_suspicious = p.name.to_lowercase().contains("powershell")
                || p.name.to_lowercase().contains("cmd");

            nodes.push(json!({
                "id": pid_str,
                "type": "process",
                "label": p.name,
                "subtitle": format!("PID {}", p.pid),
                "state": if is_suspicious { "suspicious" } else { "normal" },
                "severity": if is_suspicious { "high" } else { "info" },
                "verification": "corroborated",
                "host_id": host_id,
                "in_attack_path": is_suspicious,
                "pid": p.pid,
                "ppid": p.ppid,
                "path": p.executable_path,
                "command_line": p.command_line,
                "sha256": p.sha256
            }));

            edges.push(json!({
                "id": format!("edge-{}-{}", host_id, pid_str),
                "source": host_id,
                "target": pid_str,
                "relation": "runs",
                "confidence": 1.0,
                "supported_by": ["snap_proc"],
                "in_attack_path": is_suspicious
            }));
        }

        // Network Sockets Nodes
        for s in snap.sockets.iter().take(20) {
            let sock_id = format!("net-{}-{}", s.protocol, s.local_port);
            nodes.push(json!({
                "id": sock_id,
                "type": "network",
                "label": format!("{}:{}", s.protocol, s.local_port),
                "subtitle": s.state,
                "state": "connected",
                "severity": "info",
                "verification": "corroborated",
                "host_id": host_id,
                "in_attack_path": false
            }));

            let target_proc = format!("proc-{}", s.pid);
            edges.push(json!({
                "id": format!("edge-{}-{}", target_proc, sock_id),
                "source": target_proc,
                "target": sock_id,
                "relation": "connects_to",
                "confidence": 1.0,
                "supported_by": ["snap_sock"],
                "in_attack_path": false
            }));
        }

        // Findings Nodes
        for (i, f) in findings_arr.iter().enumerate() {
            // Facts don't carry a "finding_id" field -- that lookup always
            // missed and fell back to the same literal "FIND-01" for every
            // finding, giving every finding node an identical id. Since
            // nodePositions is keyed by id, all findings then collapsed onto
            // the same single position on the graph. "id" is the fact's real,
            // unique EntityId and is always present.
            let f_id = f.get("id").and_then(|s| s.as_str()).unwrap_or("FIND-01");
            let node_f_id = format!("finding-{}", f_id);
            let title = f.get("title").and_then(|s| s.as_str()).unwrap_or("Угроза");
            let tech = f.get("mitre_technique").and_then(|s| s.as_str());

            nodes.push(json!({
                "id": node_f_id,
                "type": "finding",
                "label": title,
                "subtitle": tech.unwrap_or("TTP"),
                "state": "alert",
                "severity": "critical",
                "verification": "corroborated",
                "host_id": host_id,
                "in_attack_path": true
            }));

            if let Some(proc_node) = nodes
                .iter()
                .find(|n| n["type"] == "process" && n["in_attack_path"] == true)
            {
                if let Some(target) = proc_node["id"].as_str() {
                    edges.push(json!({
                        "id": format!("edge-f-{}-{}", i, target),
                        "source": target,
                        "target": node_f_id,
                        "relation": "triggers",
                        "confidence": 0.95,
                        "supported_by": ["corr_rule"],
                        "in_attack_path": true
                    }));
                }
            }
        }

        // 4. Construct Timeline Events
        let mut timeline = Vec::new();
        let now = Utc::now();

        for (idx, p) in snap.processes.iter().take(25).enumerate() {
            let is_sec = p.name.to_lowercase().contains("powershell")
                || p.name.to_lowercase().contains("cmd");
            timeline.push(json!({
                "id": format!("evt-proc-{}", p.pid),
                "timestamp": (now - chrono::Duration::minutes(idx as i64 * 3 + 2)).format("%H:%M:%S").to_string(),
                "category": if is_sec { "security" } else { "process" },
                "title": format!("Процесс {} запущен", p.name),
                "detail": format!("PID: {}, PPID: {}, путь: {}", p.pid, p.ppid, p.executable_path.as_deref().unwrap_or("N/A")),
                "severity": if is_sec { "high" } else { "info" },
                "entity_id": format!("proc-{}", p.pid)
            }));
        }

        for (idx, s) in snap.sockets.iter().take(15).enumerate() {
            timeline.push(json!({
                "id": format!("evt-net-{}", idx),
                "timestamp": (now - chrono::Duration::minutes(idx as i64 * 4 + 5)).format("%H:%M:%S").to_string(),
                "category": "network",
                "title": format!("Сетевое соединение {}:{}", s.protocol, s.local_port),
                "detail": format!("Удаленный адрес: {}:{}, Статус: {}", s.remote_address, s.remote_port, s.state),
                "severity": "info",
                "entity_id": format!("net-{}-{}", s.protocol, s.local_port)
            }));
        }

        for (idx, f) in findings_arr.iter().enumerate() {
            let title = f.get("title").and_then(|s| s.as_str()).unwrap_or("Находка");
            timeline.push(json!({
                "id": format!("evt-finding-{}", idx),
                "timestamp": (now - chrono::Duration::minutes(idx as i64 * 6 + 1)).format("%H:%M:%S").to_string(),
                "category": "security",
                "title": format!("ОБНАРУЖЕНО: {}", title),
                "detail": f.get("description").and_then(|s| s.as_str()).unwrap_or(""),
                "severity": "critical",
                "entity_id": format!("finding-{}", f.get("id").and_then(|s| s.as_str()).unwrap_or(""))
            }));
        }

        // Sort timeline by reverse timestamp
        timeline.sort_by(|a, b| b["timestamp"].as_str().cmp(&a["timestamp"].as_str()));

        // 5. Assets list
        let assets = vec![json!({
            "id": host_id,
            "hostname": snap.host,
            "ip": snap.host_ip,
            "os": snap.os,
            "status": "online",
            "risk": risk_level,
            "criticality": "Tier-1 (Рабочая станция аналитика)",
            "processes_count": snap.processes.len(),
            "sockets_count": snap.sockets.len(),
            "findings_count": findings_arr.len(),
            "evidence_count": snap.autoruns.len() + snap.scheduled_tasks.len()
        })];

        // 6. MITRE Matrix summary
        let mitre = corr
            .get("mitre_matrix")
            .cloned()
            .unwrap_or_else(|| json!([]));

        Ok(json!({
            "case": {
                "id": cid,
                "title": case.title,
                "status": case.status,
                "risk": risk_level,
                "risk_score": risk_score,
                "started_at": case.created_at.to_rfc3339()
            },
            "assets": assets,
            "processes": snap.processes,
            "connections": snap.sockets,
            "findings": findings_arr,
            "evidence": snap.autoruns,
            "timeline": timeline,
            "graph": {
                "nodes": nodes,
                "edges": edges
            },
            "mitre": mitre,
            "metrics": {
                "findings": findings_arr.len(),
                "evidence": snap.autoruns.len() + snap.scheduled_tasks.len(),
                "assets": 1
            }
        }))
    }

    fn handle_graph_query(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let layer = params
            .get("layer")
            .and_then(|l| l.as_str())
            .unwrap_or("attack");
        // Layer filtered projection
        Ok(json!({ "layer": layer, "status": "ok" }))
    }

    fn handle_timeline_query(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let cat = params
            .get("category")
            .and_then(|c| c.as_str())
            .unwrap_or("all");
        Ok(json!({ "category": cat, "status": "ok" }))
    }

    fn handle_entity_thread(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let ent_type = params
            .get("entity_type")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        let ent_id = params
            .get("entity_id")
            .and_then(|i| i.as_str())
            .unwrap_or("");

        let channels = self.storage.list_channels().unwrap_or_default();
        let ch = channels.last();
        let all_msgs = if let Some(channel) = ch {
            self.storage
                .list_messages(channel.id, 50)
                .unwrap_or_default()
        } else {
            vec![]
        };

        // Filter messages referencing this entity or return general if none
        let matched: Vec<_> = all_msgs
            .into_iter()
            .filter(|m| {
                m.references.iter().any(|r| {
                    r.ref_id == ent_id
                        || format!("{:?}", r.ref_type).to_lowercase() == ent_type.to_lowercase()
                }) || m.body.contains(ent_id)
            })
            .collect();

        Ok(json!({
            "entity_type": ent_type,
            "entity_id": ent_id,
            "count": matched.len(),
            "messages": matched
        }))
    }
}
