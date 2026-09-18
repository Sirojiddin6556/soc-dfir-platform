#![forbid(unsafe_code)]

use core_domain::epistemic::{AssertionType, Confidence, PainLevel, Severity, VerificationState};
use core_domain::fact::{EntityType, Fact};
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CorrelationError {
    #[error("Rule evaluation failed: {0}")]
    EvaluationError(String),
}

struct Cand {
    ent_type: EntityType,
    key: String,
    fact: &'static str,
    conf: f32,
    sev: Severity,
    risk: f32,
    pain: Option<PainLevel>,
    rule: &'static str,
    tech: Option<&'static str>,
    tac: Option<&'static str>,
    desc: String,
}

impl Cand {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ent_type: EntityType,
        key: String,
        fact: &'static str,
        conf: f32,
        sev: Severity,
        risk: f32,
        pain: Option<PainLevel>,
        rule: &'static str,
        tech: Option<&'static str>,
        tac: Option<&'static str>,
        desc: impl Into<String>,
    ) -> Self {
        Self {
            ent_type,
            key,
            fact,
            conf,
            sev,
            risk,
            pain,
            rule,
            tech,
            tac,
            desc: desc.into(),
        }
    }
}

pub struct DeterministicCorrelationEngine;

impl DeterministicCorrelationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates observations and derives verified security facts
    pub fn correlate(&self, observations: &[Observation]) -> Result<Vec<Fact>, CorrelationError> {
        use std::collections::HashMap;

        let mut facts: Vec<Fact> = Vec::new();
        let mut fact_indices: HashMap<(EntityId, EntityType, String, String), usize> =
            HashMap::new();

        for obs in observations {
            let mut candidate_facts = Vec::new();
            let gs = |k: &str| obs.data.get(k).and_then(|v| v.as_str()).unwrap_or("");
            let host = obs
                .data
                .get("host_ip")
                .or_else(|| obs.data.get("host"))
                .and_then(|h| h.as_str())
                .unwrap_or("localhost");
            let cmd_opt = obs.data.get("command_line").and_then(|c| c.as_str());
            let proc_name = obs
                .data
                .get("process_name")
                .or_else(|| obs.data.get("name"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            let parent_name = gs("parent_name");
            let exec_path = gs("executable_path");

            let proc_lower = proc_name.to_lowercase();
            let parent_lower = parent_name.to_lowercase();
            let exec_lower = exec_path.to_lowercase();

            if let Some(cmd) = cmd_opt {
                let cmd_lower = cmd.to_lowercase();

                if cmd_lower.contains("mimikatz")
                    || cmd_lower.contains("procdump")
                    || cmd_lower.contains("comsvcs.dll")
                    || cmd_lower.contains("sekurlsa")
                {
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:cred_dump", host),
                        "CredentialAccessAttempt",
                        0.95,
                        Severity::Critical,
                        95.0,
                        Some(PainLevel::Tools),
                        "CORR-WIN-001a",
                        Some("T1003.001"),
                        Some("Credential Access"),
                        "Попытка дампа учетных данных LSASS",
                    ));
                } else if cmd_lower.contains("schtasks") && cmd_lower.contains("/create") {
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:persist:schtasks", host),
                        "ScheduledTaskPersistence",
                        0.85,
                        Severity::High,
                        85.0,
                        Some(PainLevel::TTPs),
                        "CORR-WIN-001b",
                        Some("T1053.005"),
                        Some("Persistence"),
                        "Создание запланированной задачи для закрепления",
                    ));
                } else if cmd_lower.contains("whoami")
                    || cmd_lower.contains("net user")
                    || cmd_lower.contains("nltest")
                {
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:recon", host),
                        "DiscoveryReconnaissance",
                        0.75,
                        Severity::Medium,
                        60.0,
                        Some(PainLevel::TTPs),
                        "CORR-WIN-001c",
                        Some("T1087"),
                        Some("Discovery"),
                        "Разведка учетных записей и структуры домена",
                    ));
                } else if cmd_lower.contains("-enc") || cmd_lower.contains("-encodedcommand") {
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:obfuscated", host),
                        "ObfuscatedExecution",
                        0.85,
                        Severity::High,
                        80.0,
                        Some(PainLevel::Tools),
                        "CORR-WIN-001d",
                        Some("T1027"),
                        Some("Defense Evasion"),
                        "Запуск закодированной обфусцированной команды PowerShell",
                    ));
                }
            }

            // Parent-child anomaly (Office / Server spawning command interpreter)
            let is_office_parent = parent_lower.contains("winword")
                || parent_lower.contains("excel")
                || parent_lower.contains("powerpnt")
                || parent_lower.contains("outlook")
                || parent_lower.contains("w3wp");
            let is_shell_child = proc_lower.contains("cmd.exe")
                || proc_lower.contains("powershell.exe")
                || proc_lower.contains("pwsh.exe")
                || proc_lower.contains("wscript.exe")
                || proc_lower.contains("cscript.exe");

            if is_office_parent && is_shell_child {
                candidate_facts.push(Cand::new(
                    EntityType::Process,
                    format!("{}:proc:office_shell:{}", host, proc_name),
                    "OfficeSpawnedShell",
                    0.95,
                    Severity::Critical,
                    92.0,
                    Some(PainLevel::TTPs),
                    "CORR-WIN-001e",
                    Some("T1059.001"),
                    Some("Execution"),
                    format!(
                        "Аномальный запуск командной оболочки ({}) из офисного приложения ({})",
                        proc_name, parent_name
                    ),
                ));
            }

            // Suspicious process execution path (Temp / Public directory execution)
            if (exec_lower.contains("\\appdata\\local\\temp")
                || exec_lower.contains("\\users\\public"))
                && exec_lower.ends_with(".exe")
            {
                candidate_facts.push(Cand::new(
                    EntityType::Process,
                    format!("{}:proc:susp_path:{}", host, proc_name),
                    "SuspiciousProcessLocation",
                    0.80,
                    Severity::High,
                    75.0,
                    Some(PainLevel::HostArtifacts),
                    "CORR-WIN-001f",
                    Some("T1036.005"),
                    Some("Defense Evasion"),
                    format!(
                        "Выполнение исполняемого файла из временного/публичного каталога: {}",
                        exec_path
                    ),
                ));
            }

            // 2. Persistence correlation (CORR-WIN-002: Autoruns & Scheduled Tasks)
            let target_path = gs("target_path");
            let action_path = gs("action");
            let persist_str = format!("{} {}", target_path, action_path).to_lowercase();

            if persist_str.contains("\\appdata\\local\\temp")
                || persist_str.contains("\\users\\public")
                || (persist_str.contains("powershell") && persist_str.contains("-w hidden"))
            {
                candidate_facts.push(Cand::new(
                    EntityType::Host,
                    format!("{}:persist:suspicious", host),
                    "SuspiciousPersistenceMechanism",
                    0.90,
                    Severity::High,
                    85.0,
                    Some(PainLevel::TTPs),
                    "CORR-WIN-002",
                    Some("T1547.001"),
                    Some("Persistence"),
                    format!(
                        "Подозрительная точка закрепления (Autorun/Task) со ссылкой на: {}",
                        target_path
                    ),
                ));
            }

            // 3. Service correlation (CORR-WIN-004: Unquoted paths & suspicious binaries)
            if let Some(unquoted) = obs.data.get("unquoted_risk").and_then(|u| u.as_bool()) {
                if unquoted {
                    let srv_name = obs
                        .data
                        .get("service_name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("service");
                    let bin_path = gs("binary_path");
                    candidate_facts.push(Cand::new(
                        EntityType::Host,
                        format!("{}:service:unquoted:{}", host, srv_name),
                        "UnquotedServicePath",
                        0.85,
                        Severity::Medium,
                        55.0,
                        Some(PainLevel::HostArtifacts),
                        "CORR-WIN-004",
                        Some("T1574.009"),
                        Some("Privilege Escalation"),
                        format!(
                            "Служба '{}' имеет незакавыченный путь с пробелами: {}",
                            srv_name, bin_path
                        ),
                    ));
                }
            }

            // 4. Network socket correlation (CORR-WIN-003)
            if let Some(dest_ip) = obs.data.get("destination_ip").and_then(|ip| ip.as_str()) {
                let port = obs
                    .data
                    .get("destination_port")
                    .and_then(|p| p.as_u64())
                    .unwrap_or(0);
                let is_c2 =
                    port == 4444 || port == 1337 || port == 8888 || port == 9001 || port == 5555;

                if is_c2 {
                    candidate_facts.push(Cand::new(
                        EntityType::NetworkSocket,
                        format!("{}:{}", dest_ip, port),
                        "SuspiciousC2Connection",
                        0.90,
                        Severity::Critical,
                        88.0,
                        Some(PainLevel::IpAddresses),
                        "CORR-WIN-003a",
                        Some("T1071.001"),
                        Some("Command and Control"),
                        format!(
                            "Сетевое соединение на подозрительный порт C2/реверс-шелла: {}:{}",
                            dest_ip, port
                        ),
                    ));
                } else if is_shell_child
                    && !dest_ip.starts_with("127.")
                    && !dest_ip.starts_with("0.0.")
                    && !dest_ip.is_empty()
                {
                    candidate_facts.push(Cand::new(
                        EntityType::NetworkSocket, format!("{}:{}", dest_ip, port),
                        "ShellExternalConnection", 0.95, Severity::Critical, 94.0,
                        Some(PainLevel::NetworkArtifacts), "CORR-WIN-003b", Some("T1071"),
                        Some("Command and Control"), format!("Командный интерпретатор ({}) инициировал исходящее подключение к {}:{}", proc_name, dest_ip, port),
                    ));
                }
            }

            // Aggregate candidate facts into facts vector
            for cand in candidate_facts {
                let lookup_key = (
                    obs.case_id,
                    cand.ent_type,
                    cand.key.clone(),
                    cand.fact.to_string(),
                );

                if let Some(&idx) = fact_indices.get(&lookup_key) {
                    let fact = &mut facts[idx];
                    if !fact.evidence_ids.contains(&obs.id) {
                        fact.evidence_ids.push(obs.id);
                    }
                    if fact.evidence_ids.len() >= 3 {
                        fact.verification_state = VerificationState::Confirmed;
                        fact.confidence = Confidence::new((fact.confidence.value() + 0.1).min(1.0));
                        fact.evidence_strength = (fact.evidence_strength + 0.2).min(1.0);
                    } else if fact.evidence_ids.len() >= 2 {
                        fact.verification_state = VerificationState::Corroborated;
                        fact.confidence =
                            Confidence::new((fact.confidence.value() + 0.08).min(1.0));
                        fact.evidence_strength = (fact.evidence_strength + 0.15).min(1.0);
                    }
                    if obs.source_timestamp < fact.created_at {
                        fact.created_at = obs.source_timestamp;
                    }
                } else {
                    let idx = facts.len();
                    fact_indices.insert(lookup_key, idx);

                    let mut enriched_data = obs.data.clone();
                    if let Some(obj) = enriched_data.as_object_mut() {
                        obj.insert(
                            "rule_id".to_string(),
                            serde_json::Value::String(cand.rule.to_string()),
                        );
                        obj.insert(
                            "title".to_string(),
                            serde_json::Value::String(cand.desc.clone()),
                        );
                        if let Some(tech) = cand.tech {
                            obj.insert(
                                "mitre_technique".to_string(),
                                serde_json::Value::String(tech.to_string()),
                            );
                        }
                        if let Some(tac) = cand.tac {
                            obj.insert(
                                "mitre_tactic".to_string(),
                                serde_json::Value::String(tac.to_string()),
                            );
                        }
                    }

                    facts.push(Fact {
                        id: EntityId::new_v7(),
                        case_id: obs.case_id,
                        evidence_ids: vec![obs.id],
                        assertion_type: AssertionType::Fact,
                        verification_state: VerificationState::Candidate,
                        entity_type: cand.ent_type,
                        entity_key: cand.key,
                        fact_type: cand.fact.to_string(),
                        confidence: Confidence::new(cand.conf),
                        severity: cand.sev,
                        risk_score: cand.risk,
                        evidence_strength: 0.5,
                        pain_level: cand.pain,
                        data: enriched_data,
                        created_at: obs.source_timestamp,
                    });
                }
            }
        }

        Ok(facts)
    }
}

impl Default for DeterministicCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_obs(
        case_id: EntityId,
        tool: &str,
        event_type: &str,
        data: serde_json::Value,
    ) -> Observation {
        Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: tool.to_string(),
            raw_event_type: event_type.to_string(),
            source_timestamp: chrono::Utc::now(),
            ingest_timestamp: chrono::Utc::now(),
            data,
        }
    }

    #[test]
    fn test_credential_dumping_correlation() {
        let engine = DeterministicCorrelationEngine::new();
        let case_id = EntityId::new_v7();
        let data = serde_json::json!({
            "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
            "host_ip": "10.0.0.5"
        });
        let obs1 = make_test_obs(case_id, "evtx_parser", "process_create", data.clone());
        let facts1 = engine.correlate(std::slice::from_ref(&obs1)).unwrap();
        assert_eq!(facts1.len(), 1);
        assert_eq!(facts1[0].fact_type, "CredentialAccessAttempt");
        assert_eq!(facts1[0].severity, Severity::Critical);
        assert_eq!(facts1[0].verification_state, VerificationState::Candidate);

        let obs2 = make_test_obs(case_id, "sysmon_parser", "process_create", data);
        let facts2 = engine.correlate(&[obs1, obs2]).unwrap();
        assert_eq!(facts2.len(), 1);
        assert_eq!(
            facts2[0].verification_state,
            VerificationState::Corroborated
        );
        assert!(facts2[0].is_corroborated());
    }

    #[test]
    fn test_detection_rules() {
        let engine = DeterministicCorrelationEngine::new();
        let cid = EntityId::new_v7();

        let obs = make_test_obs(
            cid,
            "win_svc",
            "service",
            serde_json::json!({
                "service_name": "VulnerableAppSvc", "binary_path": "C:\\Program Files\\App\\svc.exe",
                "unquoted_risk": true, "host": "PC-3002"
            }),
        );
        let f = engine.correlate(&[obs]).unwrap();
        assert_eq!(f[0].fact_type, "UnquotedServicePath");
        assert_eq!(f[0].data["rule_id"], "CORR-WIN-004");

        let obs = make_test_obs(
            cid,
            "win_proc",
            "process",
            serde_json::json!({
                "name": "powershell.exe", "parent_name": "WINWORD.EXE", "host": "PC-3002"
            }),
        );
        let f = engine.correlate(&[obs]).unwrap();
        assert_eq!(f[0].fact_type, "OfficeSpawnedShell");
        assert_eq!(f[0].data["rule_id"], "CORR-WIN-001e");

        let obs = make_test_obs(
            cid,
            "win_sock",
            "network_socket",
            serde_json::json!({
                "destination_ip": "198.51.100.42", "destination_port": 4444, "host": "PC-3002"
            }),
        );
        let f = engine.correlate(&[obs]).unwrap();
        assert_eq!(f[0].fact_type, "SuspiciousC2Connection");
        assert_eq!(f[0].data["rule_id"], "CORR-WIN-003a");
    }
}
