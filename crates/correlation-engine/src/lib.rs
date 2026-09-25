#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use core_domain::epistemic::{AssertionType, Confidence, PainLevel, Severity, VerificationState};
use core_domain::fact::{EntityType, Fact};
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CorrelationError {
    #[error("Rule evaluation failed: {0}")]
    EvaluationError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationQuality {
    Unknown,
    Complete,
    Partial,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub version: String,
    pub temporal_window_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationProvenance {
    pub rule_id: String,
    pub rule_version: String,
    pub temporal_window_seconds: i64,
    pub matched_host: Option<String>,
    pub matched_domain: Option<String>,
    pub source_timestamps: Vec<Option<DateTime<Utc>>>,
    pub quality: CorrelationQuality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub correlation_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub supporting_observations: Vec<String>,
    pub assertion_type: AssertionType,
    pub verification_state: VerificationState,
    pub confidence: u8,
    pub provenance: CorrelationProvenance,
}

fn evtx_pcap_rule() -> CorrelationRule {
    CorrelationRule {
        id: "CORR-H01-EVTX-PCAP".to_string(),
        version: "1".to_string(),
        temporal_window_seconds: 300,
    }
}

fn process_network_pcap_rule() -> CorrelationRule {
    CorrelationRule {
        id: "CORR-H02-PROCESS-EVTX-PCAP-ENDPOINT".to_string(),
        version: "1".to_string(),
        temporal_window_seconds: 300,
    }
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(object) => {
            let mut fields: Vec<_> = object.iter().collect();
            fields.sort_by(|left, right| left.0.cmp(right.0));
            fields
                .into_iter()
                .map(|(key, value)| format!("{key}:{}", canonical_json(value)))
                .collect::<Vec<_>>()
                .join(",")
        }
        serde_json::Value::Array(values) => values
            .iter()
            .map(canonical_json)
            .collect::<Vec<_>>()
            .join(","),
        _ => value.to_string(),
    }
}

fn semantic_observation_id(observation: &Observation) -> String {
    let identity = format!(
        "observation-semantic-v1\0{}\0{}\0{}\0{}\0{}\0{}",
        observation.case_id,
        observation
            .artifact_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        observation.source_tool,
        observation.raw_event_type,
        observation
            .source_timestamp
            .map(|timestamp| timestamp.to_rfc3339())
            .unwrap_or_default(),
        canonical_json(&observation.data)
    );
    format!(
        "observation://{}",
        blake3::hash(identity.as_bytes()).to_hex()
    )
}

fn host_of(observation: &Observation, host_by_ip: &BTreeMap<String, String>) -> Option<String> {
    ["host", "host_ip", "computer"]
        .iter()
        .find_map(|key| observation.data.get(*key).and_then(|value| value.as_str()))
        .map(ToString::to_string)
        .or_else(|| {
            ["source_ip", "destination_ip"].iter().find_map(|key| {
                observation
                    .data
                    .get(*key)
                    .and_then(|value| value.as_str())
                    .and_then(|ip| host_by_ip.get(ip))
                    .cloned()
            })
        })
}

fn domain_of(observation: &Observation) -> Option<String> {
    ["qname", "sni", "host"]
        .iter()
        .find_map(|key| observation.data.get(*key).and_then(|value| value.as_str()))
        .map(|value| value.to_ascii_lowercase())
}

fn is_powershell(observation: &Observation) -> bool {
    ["process_name", "image", "Image", "new_process_name"]
        .iter()
        .filter_map(|key| observation.data.get(*key).and_then(|value| value.as_str()))
        .map(str::to_ascii_lowercase)
        .any(|process| process.contains("powershell") || process.ends_with("pwsh.exe"))
}

fn is_network_domain_observation(observation: &Observation) -> bool {
    matches!(
        observation.raw_event_type.as_str(),
        "dns_message" | "tls_handshake" | "http_message"
    ) && domain_of(observation).is_some()
}

fn observation_time(observation: &Observation) -> Option<DateTime<Utc>> {
    observation.source_timestamp
}

fn within_window(left: DateTime<Utc>, right: Option<DateTime<Utc>>, window_seconds: i64) -> bool {
    right
        .map(|right| (left - right).num_seconds().abs() <= window_seconds)
        .unwrap_or(false)
}

fn endpoint_value<'a>(observation: &'a Observation, key: &str) -> Option<&'a str> {
    observation.data.get(key).and_then(|value| value.as_str())
}

fn shares_endpoint(left: &Observation, right: &Observation) -> bool {
    let left_values = [
        endpoint_value(left, "source_ip"),
        endpoint_value(left, "destination_ip"),
    ];
    let right_values = [
        endpoint_value(right, "source_ip"),
        endpoint_value(right, "destination_ip"),
    ];
    left_values.into_iter().flatten().any(|left_ip| {
        right_values
            .into_iter()
            .flatten()
            .any(|right_ip| left_ip == right_ip)
    })
}

fn quality_of(observation: &Observation) -> CorrelationQuality {
    let Some(quality) = &observation.network_quality else {
        return CorrelationQuality::Unknown;
    };
    if matches!(
        quality.capture,
        core_domain::CaptureQuality::Degraded | core_domain::CaptureQuality::Failed
    ) || matches!(
        quality.protocol,
        Some(core_domain::ProtocolQuality::Degraded)
    ) {
        CorrelationQuality::Degraded
    } else if matches!(quality.capture, core_domain::CaptureQuality::Partial)
        || matches!(
            quality.flow,
            Some(core_domain::FlowQuality::Partial | core_domain::FlowQuality::Truncated)
        )
        || matches!(
            quality.protocol,
            Some(core_domain::ProtocolQuality::Partial)
        )
    {
        CorrelationQuality::Partial
    } else {
        CorrelationQuality::Complete
    }
}

fn merge_quality(left: CorrelationQuality, right: CorrelationQuality) -> CorrelationQuality {
    let rank = |quality: &CorrelationQuality| match quality {
        CorrelationQuality::Unknown => 0,
        CorrelationQuality::Complete => 1,
        CorrelationQuality::Partial => 2,
        CorrelationQuality::Degraded => 3,
    };
    if rank(&left) >= rank(&right) {
        left
    } else {
        right
    }
}

/// Stateful, deterministic Phase 4 correlation context. Each ingest call
/// updates a canonical observation set and recomputes projections from the
/// complete set, making batch boundaries semantically irrelevant.
#[derive(Debug, Default)]
pub struct CorrelationContext {
    observations: BTreeMap<String, Observation>,
}

impl CorrelationContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, observations: impl IntoIterator<Item = Observation>) {
        for observation in observations {
            self.observations
                .entry(semantic_observation_id(&observation))
                .or_insert(observation);
        }
    }

    pub fn results(&self) -> Vec<CorrelationResult> {
        let observations: Vec<&Observation> = self.observations.values().collect();
        let rule = evtx_pcap_rule();
        let mut host_by_ip = BTreeMap::new();
        for observation in &observations {
            if observation.raw_event_type != "network_connection" {
                continue;
            }
            let Some(host) = observation
                .data
                .get("computer")
                .and_then(|value| value.as_str())
            else {
                continue;
            };
            for key in ["source_ip", "destination_ip"] {
                if let Some(ip) = observation.data.get(key).and_then(|value| value.as_str()) {
                    host_by_ip.insert(ip.to_string(), host.to_string());
                }
            }
        }
        let mut network_by_domain: BTreeMap<String, Vec<&Observation>> = BTreeMap::new();
        for network in observations
            .iter()
            .copied()
            .filter(|observation| is_network_domain_observation(observation))
        {
            if let Some(domain) = domain_of(network) {
                network_by_domain.entry(domain).or_default().push(network);
            }
        }
        let mut results = Vec::new();
        for process in observations
            .iter()
            .copied()
            .filter(|observation| is_powershell(observation))
        {
            for (domain, network_events) in &network_by_domain {
                let Some(process_time) = observation_time(process) else {
                    continue;
                };
                let process_host = host_of(process, &host_by_ip);
                let matching: Vec<&Observation> = network_events
                    .iter()
                    .copied()
                    .filter(|network| {
                        let Some(network_time) = observation_time(network) else {
                            return false;
                        };
                        let within_window = (process_time - network_time).num_seconds().abs()
                            <= rule.temporal_window_seconds;
                        let network_host = host_of(network, &host_by_ip);
                        within_window
                            && process_host.is_some()
                            && network_host.is_some()
                            && process_host == network_host
                    })
                    .collect();
                let dns = matching
                    .iter()
                    .copied()
                    .find(|observation| observation.raw_event_type == "dns_message");
                let tls = matching
                    .iter()
                    .copied()
                    .find(|observation| observation.raw_event_type == "tls_handshake");
                let (Some(dns), Some(tls)) = (dns, tls) else {
                    continue;
                };
                let mut supporting = vec![
                    semantic_observation_id(process),
                    semantic_observation_id(dns),
                    semantic_observation_id(tls),
                ];
                supporting.sort();
                let quality = merge_quality(
                    merge_quality(quality_of(process), quality_of(dns)),
                    quality_of(tls),
                );
                let network_host = host_of(dns, &host_by_ip).or_else(|| host_of(tls, &host_by_ip));
                let correlation_key = format!(
                    "{}\0{}\0{}\0{}",
                    rule.id,
                    rule.version,
                    process_host
                        .clone()
                        .or(network_host.clone())
                        .unwrap_or_default(),
                    domain
                );
                let correlation_id = format!(
                    "correlation://{}",
                    blake3::hash(correlation_key.as_bytes()).to_hex()
                );
                results.push(CorrelationResult {
                    correlation_id,
                    rule_id: rule.id.clone(),
                    rule_version: rule.version.clone(),
                    supporting_observations: supporting,
                    assertion_type: AssertionType::Inference,
                    verification_state: VerificationState::Candidate,
                    confidence: if quality == CorrelationQuality::Degraded {
                        50
                    } else {
                        80
                    },
                    provenance: CorrelationProvenance {
                        rule_id: rule.id.clone(),
                        rule_version: rule.version.clone(),
                        temporal_window_seconds: rule.temporal_window_seconds,
                        matched_host: process_host.or(network_host),
                        matched_domain: Some(domain.clone()),
                        source_timestamps: vec![
                            process.source_timestamp,
                            dns.source_timestamp,
                            tls.source_timestamp,
                        ],
                        quality,
                    },
                });
            }
        }

        // Sysmon Event ID 3 is an explicit host attribution boundary: it
        // carries both the computer name and the endpoint tuple. Only use a
        // PCAP observation when it shares an endpoint and falls in the same
        // temporal window; time or domain equality alone is insufficient.
        let endpoint_rule = process_network_pcap_rule();
        for process in observations
            .iter()
            .copied()
            .filter(|observation| is_powershell(observation))
        {
            let Some(process_time) = observation_time(process) else {
                continue;
            };
            let Some(process_host) = host_of(process, &host_by_ip) else {
                continue;
            };
            for connection in observations
                .iter()
                .copied()
                .filter(|observation| observation.raw_event_type == "network_connection")
            {
                let Some(connection_host) = host_of(connection, &host_by_ip) else {
                    continue;
                };
                if connection_host != process_host
                    || !is_powershell(connection)
                    || !within_window(
                        process_time,
                        observation_time(connection),
                        endpoint_rule.temporal_window_seconds,
                    )
                {
                    continue;
                }
                let Some(pcap) = observations.iter().copied().find(|observation| {
                    matches!(
                        observation.raw_event_type.as_str(),
                        "network_socket" | "network_flow"
                    ) && within_window(
                        process_time,
                        observation_time(observation),
                        endpoint_rule.temporal_window_seconds,
                    ) && shares_endpoint(connection, observation)
                }) else {
                    continue;
                };
                let mut supporting = vec![
                    semantic_observation_id(process),
                    semantic_observation_id(connection),
                    semantic_observation_id(pcap),
                ];
                supporting.sort();
                let quality = merge_quality(
                    merge_quality(quality_of(process), quality_of(connection)),
                    quality_of(pcap),
                );
                let correlation_key = format!(
                    "{}\0{}\0{}\0{}",
                    endpoint_rule.id,
                    endpoint_rule.version,
                    process_host,
                    supporting.join("\0")
                );
                let correlation_id = format!(
                    "correlation://{}",
                    blake3::hash(correlation_key.as_bytes()).to_hex()
                );
                results.push(CorrelationResult {
                    correlation_id,
                    rule_id: endpoint_rule.id.clone(),
                    rule_version: endpoint_rule.version.clone(),
                    supporting_observations: supporting,
                    assertion_type: AssertionType::Inference,
                    verification_state: VerificationState::Candidate,
                    confidence: if quality == CorrelationQuality::Degraded {
                        50
                    } else {
                        75
                    },
                    provenance: CorrelationProvenance {
                        rule_id: endpoint_rule.id.clone(),
                        rule_version: endpoint_rule.version.clone(),
                        temporal_window_seconds: endpoint_rule.temporal_window_seconds,
                        matched_host: Some(process_host.clone()),
                        matched_domain: domain_of(pcap),
                        source_timestamps: vec![
                            process.source_timestamp,
                            connection.source_timestamp,
                            pcap.source_timestamp,
                        ],
                        quality,
                    },
                });
            }
        }
        let mut unique = BTreeMap::new();
        for result in results {
            unique.insert(result.correlation_id.clone(), result);
        }
        unique.into_values().collect()
    }
}

pub fn correlate_in_batches(
    observations: &[Observation],
    batch_size: usize,
) -> Result<Vec<CorrelationResult>, CorrelationError> {
    if batch_size == 0 {
        return Err(CorrelationError::EvaluationError(
            "batch size must be positive".into(),
        ));
    }
    let mut context = CorrelationContext::new();
    for batch in observations.chunks(batch_size) {
        context.ingest(batch.iter().cloned());
    }
    Ok(context.results())
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
                    let obs_time = obs.source_timestamp.unwrap_or(obs.ingest_timestamp);
                    if obs_time < fact.created_at {
                        fact.created_at = obs_time;
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
                        created_at: obs.source_timestamp.unwrap_or(obs.ingest_timestamp),
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
            source_timestamp: Some(chrono::Utc::now()),
            ingest_timestamp: chrono::Utc::now(),
            data,
            network_quality: None,
            network_provenance: None,
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

    fn make_phase4_obs(
        case_id: EntityId,
        event_type: &str,
        timestamp: chrono::DateTime<chrono::Utc>,
        data: serde_json::Value,
    ) -> Observation {
        Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: Some(EntityId::new_v7()),
            tool_run_id: None,
            source_tool: if event_type == "process_create" {
                "sysmon_parser".to_string()
            } else {
                "pcap_parser".to_string()
            },
            raw_event_type: event_type.to_string(),
            source_timestamp: Some(timestamp),
            ingest_timestamp: timestamp + chrono::Duration::seconds(1),
            data,
            network_quality: if event_type == "process_create" {
                None
            } else {
                Some(core_domain::NetworkObservationQuality {
                    capture: core_domain::CaptureQuality::Complete,
                    flow: Some(core_domain::FlowQuality::Complete),
                    protocol: Some(core_domain::ProtocolQuality::Complete),
                })
            },
            network_provenance: None,
        }
    }

    #[test]
    fn corr_h01_evtx_pcap_is_batch_independent() {
        let case_id = EntityId::new_v7();
        let base = chrono::Utc::now();
        let observations = vec![
            make_phase4_obs(
                case_id,
                "process_create",
                base,
                serde_json::json!({"host": "WS-01", "process_name": "powershell.exe"}),
            ),
            make_phase4_obs(
                case_id,
                "dns_message",
                base + chrono::Duration::seconds(10),
                serde_json::json!({"host": "WS-01", "qname": "example.test"}),
            ),
            make_phase4_obs(
                case_id,
                "tls_handshake",
                base + chrono::Duration::seconds(20),
                serde_json::json!({"host": "WS-01", "sni": "example.test"}),
            ),
            make_phase4_obs(
                case_id,
                "dns_message",
                base + chrono::Duration::seconds(30),
                serde_json::json!({"host": "WS-01", "qname": "noise.test"}),
            ),
        ];
        let results_128 = correlate_in_batches(&observations, 128).unwrap();
        let results_512 = correlate_in_batches(&observations, 512).unwrap();
        let results_2048 = correlate_in_batches(&observations, 2048).unwrap();
        assert_eq!(results_128, results_512);
        assert_eq!(results_512, results_2048);
        assert_eq!(results_128.len(), 1);
        assert_eq!(results_128[0].rule_id, "CORR-H01-EVTX-PCAP");
        assert_eq!(
            results_128[0].provenance.matched_domain.as_deref(),
            Some("example.test")
        );
        assert_eq!(results_128[0].supporting_observations.len(), 3);
        assert_eq!(results_128[0].assertion_type, AssertionType::Inference);
        assert_eq!(
            results_128[0].verification_state,
            VerificationState::Candidate
        );
    }

    #[test]
    fn corr_h01_quality_is_conservative() {
        let case_id = EntityId::new_v7();
        let base = chrono::Utc::now();
        let mut process = make_phase4_obs(
            case_id,
            "process_create",
            base,
            serde_json::json!({"host": "WS-01", "process_name": "powershell.exe"}),
        );
        process.network_quality = Some(core_domain::NetworkObservationQuality {
            capture: core_domain::CaptureQuality::Complete,
            flow: None,
            protocol: Some(core_domain::ProtocolQuality::Degraded),
        });
        let observations = vec![
            process,
            make_phase4_obs(
                case_id,
                "dns_message",
                base + chrono::Duration::seconds(1),
                serde_json::json!({"host": "WS-01", "qname": "example.test"}),
            ),
            make_phase4_obs(
                case_id,
                "tls_handshake",
                base + chrono::Duration::seconds(2),
                serde_json::json!({"host": "WS-01", "sni": "example.test"}),
            ),
        ];
        let result = correlate_in_batches(&observations, 1).unwrap();
        assert_eq!(result[0].provenance.quality, CorrelationQuality::Degraded);
        assert_eq!(result[0].confidence, 50);
    }

    #[test]
    fn corr_h01_requires_explicit_host_attribution() {
        let case_id = EntityId::new_v7();
        let base = chrono::Utc::now();
        let mut observations = vec![
            make_phase4_obs(
                case_id,
                "process_create",
                base,
                serde_json::json!({"host": "WS-01", "process_name": "powershell.exe"}),
            ),
            make_phase4_obs(
                case_id,
                "dns_message",
                base + chrono::Duration::seconds(1),
                serde_json::json!({"qname": "example.test"}),
            ),
            make_phase4_obs(
                case_id,
                "tls_handshake",
                base + chrono::Duration::seconds(2),
                serde_json::json!({"sni": "example.test"}),
            ),
        ];
        assert!(correlate_in_batches(&observations, 128).unwrap().is_empty());

        observations[1]
            .data
            .as_object_mut()
            .unwrap()
            .insert("host".to_string(), serde_json::json!("WS-01"));
        observations[2]
            .data
            .as_object_mut()
            .unwrap()
            .insert("host".to_string(), serde_json::json!("WS-01"));
        assert_eq!(correlate_in_batches(&observations, 128).unwrap().len(), 1);
    }

    #[test]
    fn corr_h01_does_not_use_ingest_time_for_missing_source_time() {
        let case_id = EntityId::new_v7();
        let ingest_time = chrono::Utc::now();
        let mut process = make_phase4_obs(
            case_id,
            "process_create",
            ingest_time,
            serde_json::json!({"host": "WS-01", "process_name": "powershell.exe"}),
        );
        process.source_timestamp = None;
        process.ingest_timestamp = ingest_time;
        let observations = vec![
            process,
            make_phase4_obs(
                case_id,
                "dns_message",
                ingest_time,
                serde_json::json!({"host": "WS-01", "qname": "example.test"}),
            ),
            make_phase4_obs(
                case_id,
                "tls_handshake",
                ingest_time,
                serde_json::json!({"host": "WS-01", "sni": "example.test"}),
            ),
        ];
        assert!(correlate_in_batches(&observations, 128).unwrap().is_empty());
    }

    #[test]
    fn corr_h01_temporal_window_is_inclusive_and_deterministic() {
        let case_id = EntityId::new_v7();
        let base = chrono::Utc::now();
        let process = make_phase4_obs(
            case_id,
            "process_create",
            base,
            serde_json::json!({"host": "WS-01", "process_name": "powershell.exe"}),
        );
        let dns = make_phase4_obs(
            case_id,
            "dns_message",
            base + chrono::Duration::seconds(300),
            serde_json::json!({"host": "WS-01", "qname": "example.test"}),
        );
        let tls = make_phase4_obs(
            case_id,
            "tls_handshake",
            base + chrono::Duration::seconds(300),
            serde_json::json!({"host": "WS-01", "sni": "example.test"}),
        );
        assert_eq!(
            correlate_in_batches(&[process.clone(), dns, tls], 128)
                .unwrap()
                .len(),
            1
        );

        let late_tls = make_phase4_obs(
            case_id,
            "tls_handshake",
            base + chrono::Duration::seconds(302),
            serde_json::json!({"host": "WS-01", "sni": "example.test"}),
        );
        let late_dns = make_phase4_obs(
            case_id,
            "dns_message",
            base + chrono::Duration::seconds(301),
            serde_json::json!({"host": "WS-01", "qname": "example.test"}),
        );
        assert!(correlate_in_batches(&[process, late_dns, late_tls], 128)
            .unwrap()
            .is_empty());
    }
}
