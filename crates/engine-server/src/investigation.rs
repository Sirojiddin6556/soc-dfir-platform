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
            .unwrap_or(0.0);
        let risk_level = corr
            .get("risk_level")
            .and_then(|l| l.as_str())
            .unwrap_or("НИЗКИЙ");
        let evidence_count = self
            .storage
            .list_artifacts_for_case(cid)
            .map(|a| a.len())
            .unwrap_or(0);

        // PIDs that a finding is about. Only these are marked suspicious and
        // put on the attack path -- never a guess from the process name.
        let flagged_pids: std::collections::HashSet<u64> = findings_arr
            .iter()
            .filter_map(|f| f.get("pid").and_then(|p| p.as_u64()))
            .collect();

        // 3. Construct Graph nodes and edges
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Host Node
        nodes.push(json!({
            "id": host_id,
            "type": "host",
            "label": snap.host,
            "hostname": snap.host,
            "os": snap.os,
            "subtitle": snap.os,
            "state": "active",
            "severity": if findings_arr.is_empty() { "info" } else { "high" },
            "risk": risk_level,
            "verification": "corroborated",
            "host_id": host_id,
            "in_attack_path": !findings_arr.is_empty(),
            "ip": snap.host_ip,
            "processes_count": snap.processes.len(),
            "sockets_count": snap.sockets.len(),
            "findings_count": findings_arr.len(),
            "evidence_count": evidence_count,
            "collected_at": snap.collected_at
        }));

        // Process nodes: every process a finding points at, then the first
        // others up to a readable total.
        const MAX_PROCESS_NODES: usize = 30;
        let mut shown_procs: Vec<&_> = snap
            .processes
            .iter()
            .filter(|p| flagged_pids.contains(&(p.pid as u64)))
            .collect();
        for p in &snap.processes {
            if shown_procs.len() >= MAX_PROCESS_NODES {
                break;
            }
            if !flagged_pids.contains(&(p.pid as u64)) {
                shown_procs.push(p);
            }
        }
        for p in &shown_procs {
            let pid_str = format!("proc-{}", p.pid);
            let is_suspicious = flagged_pids.contains(&(p.pid as u64));

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
                "username": p.username,
                "started_at": p.started_at,
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
        let shown_pids: std::collections::HashSet<u32> =
            shown_procs.iter().map(|p| p.pid).collect();

        // Network Sockets Nodes (only those whose owning process is shown,
        // so every edge has both ends)
        for s in snap
            .sockets
            .iter()
            .filter(|s| shown_pids.contains(&s.pid))
            .take(20)
        {
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

        // Findings Nodes, each linked to the process it is about (or to the
        // host when the finding is not about a single process).
        for (i, f) in findings_arr.iter().enumerate() {
            let f_id = f.get("id").and_then(|s| s.as_str()).unwrap_or("");
            let node_f_id = format!("finding-{}", f_id);
            let title = f.get("title").and_then(|s| s.as_str()).unwrap_or("Угроза");
            let tech = f.get("mitre_technique").and_then(|s| s.as_str());

            nodes.push(json!({
                "id": node_f_id,
                "type": "finding",
                "label": title,
                "subtitle": tech.unwrap_or("TTP"),
                "state": "alert",
                "severity": f.get("severity").and_then(|s| s.as_str()).unwrap_or("High").to_lowercase(),
                "verification": "corroborated",
                "host_id": host_id,
                "in_attack_path": true,
                "rule_id": f.get("rule_id"),
                "pid": f.get("pid")
            }));

            let source = match f.get("pid").and_then(|p| p.as_u64()) {
                Some(pid) if shown_pids.contains(&(pid as u32)) => format!("proc-{pid}"),
                _ => host_id.to_string(),
            };
            edges.push(json!({
                "id": format!("edge-f-{}-{}", i, source),
                "source": source,
                "target": node_f_id,
                "relation": "triggers",
                "confidence": 1.0,
                "supported_by": [f.get("rule_id").and_then(|r| r.as_str()).unwrap_or("corr_rule")],
                "in_attack_path": true
            }));
        }

        // 4. Timeline: real times only. Processes at their start time (when
        // the collector could read it), connections and findings at the time
        // they were observed.
        let mut timeline: Vec<(chrono::DateTime<Utc>, serde_json::Value)> = Vec::new();
        let parse_time = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        };
        let collected_at = parse_time(&snap.collected_at).unwrap_or_else(Utc::now);

        for p in shown_procs.iter().take(25) {
            let Some(started) = p.started_at.as_deref().and_then(parse_time) else {
                continue;
            };
            let flagged = flagged_pids.contains(&(p.pid as u64));
            timeline.push((
                started,
                json!({
                    "id": format!("evt-proc-{}", p.pid),
                    "category": if flagged { "security" } else { "process" },
                    "title": format!("Процесс {} запущен", p.name),
                    "detail": format!("PID: {}, PPID: {}, путь: {}", p.pid, p.ppid, p.executable_path.as_deref().unwrap_or("N/A")),
                    "severity": if flagged { "high" } else { "info" },
                    "entity_id": format!("proc-{}", p.pid)
                }),
            ));
        }

        for (idx, s) in snap
            .sockets
            .iter()
            .filter(|s| shown_pids.contains(&s.pid))
            .take(15)
            .enumerate()
        {
            timeline.push((
                collected_at,
                json!({
                    "id": format!("evt-net-{}", idx),
                    "category": "network",
                    "title": format!("Сетевое соединение {}:{}", s.protocol, s.local_port),
                    "detail": format!("Удаленный адрес: {}:{}, Статус: {} (на момент сбора)", s.remote_address, s.remote_port, s.state),
                    "severity": "info",
                    "entity_id": format!("net-{}-{}", s.protocol, s.local_port)
                }),
            ));
        }

        for f in &findings_arr {
            let title = f.get("title").and_then(|s| s.as_str()).unwrap_or("Находка");
            let when = f
                .get("created_at")
                .and_then(|s| s.as_str())
                .and_then(parse_time)
                .unwrap_or(collected_at);
            timeline.push((
                when,
                json!({
                    "id": format!("evt-finding-{}", f.get("id").and_then(|s| s.as_str()).unwrap_or("")),
                    "category": "security",
                    "title": format!("ОБНАРУЖЕНО: {}", title),
                    "detail": format!("Правило {}", f.get("rule_id").and_then(|s| s.as_str()).unwrap_or("—")),
                    "severity": "critical",
                    "entity_id": format!("finding-{}", f.get("id").and_then(|s| s.as_str()).unwrap_or(""))
                }),
            ));
        }

        // Newest first, ordered by the full timestamp (not the clock string,
        // which breaks across midnight).
        timeline.sort_by_key(|e| std::cmp::Reverse(e.0));
        let timeline: Vec<serde_json::Value> = timeline
            .into_iter()
            .map(|(when, mut ev)| {
                let local = when.with_timezone(&chrono::Local);
                ev["timestamp"] = json!(local.format("%H:%M:%S").to_string());
                ev["datetime"] = json!(when.to_rfc3339());
                ev
            })
            .collect();

        // 5. Assets list
        let assets = vec![json!({
            "id": host_id,
            "hostname": snap.host,
            "ip": snap.host_ip,
            "os": snap.os,
            "platform": snap.platform,
            "status": "online",
            "risk": risk_level,
            "processes_count": snap.processes.len(),
            "sockets_count": snap.sockets.len(),
            "findings_count": findings_arr.len(),
            "evidence_count": evidence_count
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
            "autoruns": snap.autoruns,
            "collection_errors": snap.collection_errors,
            "timeline": timeline,
            "graph": {
                "nodes": nodes,
                "edges": edges
            },
            "mitre": mitre,
            "metrics": {
                "findings": findings_arr.len(),
                "evidence": evidence_count,
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
