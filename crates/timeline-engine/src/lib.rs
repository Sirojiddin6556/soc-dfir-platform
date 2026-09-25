#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use core_domain::fact::Fact;
use core_domain::id::EntityId;
use core_domain::observation::{
    CaptureQuality, FlowQuality, NetworkDiagnosticProvenance, Observation, ProtocolQuality,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineLane {
    pub lane_id: String,
    pub title: String,
    pub host_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub fact_id: EntityId,
    pub timestamp: DateTime<Utc>,
    pub lane_id: String,
    pub label: String,
    pub severity: core_domain::Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineSourceKind {
    Evtx,
    Sysmon,
    PcapPacket,
    NetworkFlow,
    PcapDns,
    PcapHttp,
    PcapTls,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineQuality {
    Unknown,
    Complete,
    Partial,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIdentity {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdentity {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub image: Option<String>,
    pub pid: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIdentity {
    pub source: Option<String>,
    pub destination: Option<String>,
    pub domain: Option<String>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineProvenance {
    pub artifact_id: Option<EntityId>,
    pub observation_id: EntityId,
    pub source_tool: String,
    pub parser_name: Option<String>,
    pub parser_version: Option<String>,
    pub packet_locator: Option<String>,
    pub packet_index: Option<u64>,
    pub flow_instance_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_id: String,
    pub case_id: EntityId,
    pub source_timestamp: Option<DateTime<Utc>>,
    pub ingest_timestamp: DateTime<Utc>,
    pub normalized_timestamp: Option<DateTime<Utc>>,
    pub source_kind: TimelineSourceKind,
    pub artifact_id: Option<EntityId>,
    pub observation_id: EntityId,
    pub host: Option<HostIdentity>,
    pub user: Option<UserIdentity>,
    pub process: Option<ProcessIdentity>,
    pub network: Option<NetworkIdentity>,
    pub quality: TimelineQuality,
    pub provenance: TimelineProvenance,
}

fn string_field(data: &serde_json::Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        data.get(*name)
            .and_then(|value| value.as_str())
            .map(ToString::to_string)
    })
}

fn source_kind(observation: &Observation) -> TimelineSourceKind {
    match observation.raw_event_type.as_str() {
        "network_flow" => TimelineSourceKind::NetworkFlow,
        "dns_message" => TimelineSourceKind::PcapDns,
        "http_message" => TimelineSourceKind::PcapHttp,
        "tls_handshake" => TimelineSourceKind::PcapTls,
        "network_socket" => TimelineSourceKind::PcapPacket,
        _ if observation
            .source_tool
            .to_ascii_lowercase()
            .contains("sysmon") =>
        {
            TimelineSourceKind::Sysmon
        }
        _ if observation
            .source_tool
            .to_ascii_lowercase()
            .contains("evtx")
            || observation.raw_event_type.contains("event")
            || observation.raw_event_type.contains("log") =>
        {
            TimelineSourceKind::Evtx
        }
        _ => TimelineSourceKind::Other,
    }
}

fn quality_from_observation(observation: &Observation) -> TimelineQuality {
    let Some(network_quality) = &observation.network_quality else {
        return TimelineQuality::Unknown;
    };
    if matches!(
        network_quality.capture,
        CaptureQuality::Failed | CaptureQuality::Degraded
    ) || matches!(network_quality.protocol, Some(ProtocolQuality::Degraded))
    {
        return TimelineQuality::Degraded;
    }
    if matches!(network_quality.capture, CaptureQuality::Partial)
        || matches!(
            network_quality.flow,
            Some(FlowQuality::Partial | FlowQuality::Truncated)
        )
        || matches!(network_quality.protocol, Some(ProtocolQuality::Partial))
    {
        return TimelineQuality::Partial;
    }
    TimelineQuality::Complete
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(object) => {
            let mut fields: Vec<_> = object.iter().collect();
            fields.sort_by(|left, right| left.0.cmp(right.0));
            let body = fields
                .into_iter()
                .map(|(key, value)| format!("{key}:{}", canonical_json(value)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => value.to_string(),
    }
}

fn semantic_event_id(observation: &Observation) -> String {
    let mut identity = String::new();
    identity.push_str("timeline-event-v1\0");
    identity.push_str(&observation.case_id.to_string());
    identity.push('\0');
    identity.push_str(
        &observation
            .artifact_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    );
    identity.push('\0');
    identity.push_str(&observation.source_tool);
    identity.push('\0');
    identity.push_str(&observation.raw_event_type);
    identity.push('\0');
    identity.push_str(
        &observation
            .source_timestamp
            .map(|time| time.to_rfc3339())
            .unwrap_or_default(),
    );
    identity.push('\0');
    identity.push_str(&canonical_json(&observation.data));
    format!("timeline://{}", blake3::hash(identity.as_bytes()).to_hex())
}

fn network_provenance(observation: &Observation) -> Option<&NetworkDiagnosticProvenance> {
    observation.network_provenance.as_ref()
}

pub fn project_observation(observation: &Observation) -> TimelineEvent {
    let data = &observation.data;
    let provenance = network_provenance(observation);
    TimelineEvent {
        event_id: semantic_event_id(observation),
        case_id: observation.case_id,
        source_timestamp: observation.source_timestamp,
        ingest_timestamp: observation.ingest_timestamp,
        normalized_timestamp: observation.source_timestamp,
        source_kind: source_kind(observation),
        artifact_id: observation.artifact_id,
        observation_id: observation.id,
        host: string_field(data, &["host", "host_ip", "computer"])
            .map(|value| HostIdentity { value }),
        user: string_field(data, &["username", "user", "account"])
            .map(|value| UserIdentity { value }),
        process: string_field(data, &["process_name", "Image", "image"]).map(|image| {
            ProcessIdentity {
                image: Some(image),
                pid: data.get("pid").and_then(|value| value.as_u64()),
            }
        }),
        network: Some(NetworkIdentity {
            source: string_field(data, &["source_ip", "src_ip", "local_address"]),
            destination: string_field(data, &["destination_ip", "dst_ip", "remote_address"]),
            domain: string_field(data, &["qname", "sni", "host"]),
            protocol: string_field(data, &["protocol"]),
        })
        .filter(|network| {
            network.source.is_some()
                || network.destination.is_some()
                || network.domain.is_some()
                || network.protocol.is_some()
        }),
        quality: quality_from_observation(observation),
        provenance: TimelineProvenance {
            artifact_id: observation.artifact_id,
            observation_id: observation.id,
            source_tool: observation.source_tool.clone(),
            parser_name: data
                .get("parser_name")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
            parser_version: data
                .get("parser_version")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
            packet_locator: provenance.and_then(|value| value.packet_locator.clone()),
            packet_index: provenance.and_then(|value| value.packet_index),
            flow_instance_id: provenance.and_then(|value| value.flow_instance_id.clone()),
        },
    }
}

pub fn project_observations(observations: &[Observation]) -> Vec<TimelineEvent> {
    let mut events: Vec<_> = observations.iter().map(project_observation).collect();
    events.sort_by(|left, right| {
        left.normalized_timestamp
            .is_none()
            .cmp(&right.normalized_timestamp.is_none())
            .then_with(|| left.normalized_timestamp.cmp(&right.normalized_timestamp))
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    events
}

pub struct TimelineEngine;

impl TimelineEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn build_timeline(&self, facts: &[Fact]) -> Vec<TimelineEntry> {
        let mut entries: Vec<TimelineEntry> = facts
            .iter()
            .map(|f| {
                let lane_id = f
                    .data
                    .get("host_ip")
                    .and_then(|h| h.as_str())
                    .unwrap_or("General")
                    .to_string();

                TimelineEntry {
                    fact_id: f.id,
                    timestamp: f.created_at,
                    lane_id,
                    label: format!("{}: {}", f.fact_type, f.entity_key),
                    severity: f.severity,
                }
            })
            .collect();

        entries.sort_by_key(|e| e.timestamp);
        entries
    }
}

impl Default for TimelineEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::epistemic::{AssertionType, Confidence, Severity, VerificationState};
    use core_domain::fact::EntityType;

    #[test]
    fn test_timeline_sorting_and_lanes() {
        let engine = TimelineEngine::new();
        let case_id = EntityId::new_v7();
        let now = Utc::now();

        let facts = vec![
            Fact {
                id: EntityId::new_v7(),
                case_id,
                evidence_ids: vec![EntityId::new_v7()],
                assertion_type: AssertionType::Fact,
                verification_state: VerificationState::Confirmed,
                entity_type: EntityType::Process,
                entity_key: "proc2".to_string(),
                fact_type: "Exec".to_string(),
                confidence: Confidence::new(1.0),
                severity: Severity::High,
                risk_score: 50.0,
                evidence_strength: 1.0,
                pain_level: None,
                data: serde_json::json!({"host_ip": "10.0.0.1"}),
                created_at: now + chrono::Duration::seconds(10),
            },
            Fact {
                id: EntityId::new_v7(),
                case_id,
                evidence_ids: vec![EntityId::new_v7()],
                assertion_type: AssertionType::Fact,
                verification_state: VerificationState::Confirmed,
                entity_type: EntityType::Process,
                entity_key: "proc1".to_string(),
                fact_type: "Exec".to_string(),
                confidence: Confidence::new(1.0),
                severity: Severity::Low,
                risk_score: 10.0,
                evidence_strength: 1.0,
                pain_level: None,
                data: serde_json::json!({"host_ip": "10.0.0.1"}),
                created_at: now,
            },
        ];

        let entries = engine.build_timeline(&facts);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].label, "Exec: proc1");
        assert_eq!(entries[1].label, "Exec: proc2");
        assert_eq!(entries[0].lane_id, "10.0.0.1");
    }

    #[test]
    fn time_001_projects_observations_without_fabricating_source_time() {
        let case_id = EntityId::new_v7();
        let observation = Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: "evtx_normalizer".to_string(),
            raw_event_type: "process_create".to_string(),
            source_timestamp: None,
            ingest_timestamp: Utc::now(),
            data: serde_json::json!({
                "host": "WS-01",
                "process_name": "powershell.exe"
            }),
            network_quality: None,
            network_provenance: None,
        };

        let event = project_observation(&observation);
        assert_eq!(event.source_kind, TimelineSourceKind::Evtx);
        assert_eq!(event.source_timestamp, None);
        assert_eq!(event.normalized_timestamp, None);
        assert_eq!(event.ingest_timestamp, observation.ingest_timestamp);
        assert_eq!(event.host.unwrap().value, "WS-01");
        assert_eq!(event.quality, TimelineQuality::Unknown);
        assert_eq!(event.provenance.observation_id, observation.id);
    }

    #[test]
    fn time_001_order_and_event_ids_are_semantic_and_deterministic() {
        let case_id = EntityId::new_v7();
        let artifact_id = EntityId::new_v7();
        let source_time = Utc::now();
        let make = |id, ingest_timestamp| Observation {
            id,
            case_id,
            artifact_id: Some(artifact_id),
            tool_run_id: None,
            source_tool: "pcap_parser".to_string(),
            raw_event_type: "tls_handshake".to_string(),
            source_timestamp: Some(source_time),
            ingest_timestamp,
            data: serde_json::json!({
                "sni": "example.test",
                "protocol": "TCP",
                "parser_version": "pcap-phase3/socdfir-1.0"
            }),
            network_quality: Some(core_domain::NetworkObservationQuality {
                capture: CaptureQuality::Complete,
                flow: Some(FlowQuality::Complete),
                protocol: Some(ProtocolQuality::Complete),
            }),
            network_provenance: Some(NetworkDiagnosticProvenance {
                artifact_digest: "sha256:fixture".to_string(),
                packet_index: Some(3),
                packet_locator: Some("pcap://packet/3".to_string()),
                flow_instance_id: Some("flow-instance://fixture".to_string()),
                direction: None,
            }),
        };
        let first = project_observation(&make(EntityId::new_v7(), source_time));
        let second = project_observation(&make(
            EntityId::new_v7(),
            source_time + chrono::Duration::seconds(10),
        ));
        assert_eq!(first.event_id, second.event_id);
        assert_eq!(first.quality, TimelineQuality::Complete);
        assert_eq!(first.source_kind, TimelineSourceKind::PcapTls);
        assert_eq!(
            first.provenance.packet_locator.as_deref(),
            Some("pcap://packet/3")
        );

        let later = make(EntityId::new_v7(), source_time);
        let mut observations = vec![later, make(EntityId::new_v7(), source_time)];
        observations[0].source_timestamp = Some(source_time + chrono::Duration::seconds(5));
        let events = project_observations(&observations);
        assert!(events[0].source_timestamp <= events[1].source_timestamp);
    }

    #[test]
    fn time_001_quality_projection_is_conservative() {
        let mut observation = Observation {
            id: EntityId::new_v7(),
            case_id: EntityId::new_v7(),
            artifact_id: None,
            tool_run_id: None,
            source_tool: "pcap_parser".to_string(),
            raw_event_type: "network_flow".to_string(),
            source_timestamp: Some(Utc::now()),
            ingest_timestamp: Utc::now(),
            data: serde_json::json!({}),
            network_quality: Some(core_domain::NetworkObservationQuality {
                capture: CaptureQuality::Complete,
                flow: Some(FlowQuality::Partial),
                protocol: Some(ProtocolQuality::Complete),
            }),
            network_provenance: None,
        };
        assert_eq!(
            project_observation(&observation).quality,
            TimelineQuality::Partial
        );
        observation.network_quality.as_mut().unwrap().protocol = Some(ProtocolQuality::Degraded);
        assert_eq!(
            project_observation(&observation).quality,
            TimelineQuality::Degraded
        );
    }
}
