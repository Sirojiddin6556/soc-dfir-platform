#![forbid(unsafe_code)]
// ProblemDetails is the RPC error type across engine-server; see the same
// allow on the other handlers (auth.rs, membership.rs, investigation.rs).
#![allow(clippy::result_large_err)]

pub mod data_plane;
pub mod rpc;
pub mod session;
pub mod staging;
pub mod token;

pub use data_plane::handle_binary_upload_chunk;
pub use rpc::*;
pub use session::{
    BeginIngestResult, CompleteIngestResult, IngestSessionManager, SessionStatusResult,
};
pub use staging::StagingManager;
pub use token::TokenManager;

use base64::Engine as _;
use chrono::Utc;
use core_domain::artifact::{Artifact, CustodyEvent, CustodyEventType};
use core_domain::id::EntityId;
use core_domain::observation::{Observation, RawToolResult};
use correlation_engine::DeterministicCorrelationEngine;
use ipc_protocol::ProblemDetails;
use serde_json::json;
use storage_cas::ContentAddressedStorage;
use storage_sqlite::SqliteStorage;
use tool_adapters::{
    evtx::ParsedEvtxRecord,
    pcap::{phase3, ParsedPacket},
    EvtxAdapter, PcapAdapter, ToolAdapter,
};

const MAX_INGEST_BYTES: usize = 256 * 1024 * 1024;
const MAX_PRODUCTION_PACKET_OBSERVATIONS: usize = 25_000;
const MAX_PRODUCTION_FLOWS: usize = 5_000;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ParserStatus {
    NotApplicable,
    Succeeded,
    Partial,
    Failed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactProcessingResult {
    pub parser_status: ParserStatus,
    pub observations_created: u64,
    pub facts_created: u64,
    pub diagnostics_created: u64,
    pub parser_name: Option<String>,
    pub parser_version: Option<String>,
}

fn bad_request(detail: &str, field: &str) -> ProblemDetails {
    ProblemDetails::bad_request(detail, vec![field.to_string()])
}

/// Canonical post-CAS network processing entry point. Both legacy and
/// streaming ingestion must call this function after the immutable artifact
/// has been committed to CAS and registered in SQLite.
pub async fn process_committed_artifact(
    case_id: EntityId,
    artifact: &Artifact,
    stored_path: &std::path::Path,
    storage: &SqliteStorage,
    correlator: &DeterministicCorrelationEngine,
) -> Result<ArtifactProcessingResult, ProblemDetails> {
    let extension = std::path::Path::new(&artifact.original_name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if extension == "evtx" {
        let parse_result = EvtxAdapter
            .parse_artifact(stored_path)
            .await
            .map_err(|error| bad_request(&format!("parse failed: {error}"), "artifact"))?;
        let observations: Vec<Observation> = if let Ok(result) =
            serde_json::from_slice::<tool_adapters::evtx::EvtxParseResult>(
                &parse_result.stdout_bytes,
            ) {
            result
                .records
                .iter()
                .map(|record| {
                    tool_adapters::evtx::EvtxNormalizer::normalize_record(
                        case_id,
                        Some(artifact.id),
                        None,
                        record,
                    )
                })
                .collect()
        } else {
            serde_json::from_slice::<Vec<ParsedEvtxRecord>>(&parse_result.stdout_bytes)
                .map_err(|error| bad_request(&error.to_string(), "artifact"))?
                .into_iter()
                .map(|record| Observation {
                    id: EntityId::new_v7(),
                    case_id,
                    artifact_id: Some(artifact.id),
                    tool_run_id: None,
                    source_tool: parse_result.tool_name.clone(),
                    raw_event_type: "evtx_record".to_string(),
                    source_timestamp: record.timestamp,
                    ingest_timestamp: Utc::now(),
                    data: json!({
                        "event_id": record.event_id,
                        "provider": record.provider,
                        "channel": record.channel,
                        "host": record.computer,
                        "process_name": record.data.get("Image").and_then(|v| v.as_str()),
                        "command_line": record.data.get("CommandLine").and_then(|v| v.as_str()),
                        "parent_name": record.data.get("ParentImage").and_then(|v| v.as_str()),
                        "executable_path": record.data.get("Image").and_then(|v| v.as_str()),
                        "event_data": record.data
                    }),
                    network_quality: None,
                    network_provenance: None,
                })
                .collect()
        };

        for observation in &observations {
            storage
                .insert_observation(observation)
                .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
        }
        crate::analysis::process_persisted_observations(storage, case_id)
            .map_err(|error| bad_request(&error.to_string(), "analysis"))?;
        let facts = correlator
            .correlate(&observations)
            .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
        for fact in &facts {
            storage
                .insert_fact(fact)
                .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
        }

        return Ok(ArtifactProcessingResult {
            parser_status: ParserStatus::Succeeded,
            observations_created: observations.len() as u64,
            facts_created: facts.len() as u64,
            diagnostics_created: 0,
            parser_name: Some(parse_result.tool_name),
            parser_version: Some(parse_result.tool_version),
        });
    }

    if !matches!(extension.as_str(), "pcap" | "pcapng" | "cap") {
        return Ok(ArtifactProcessingResult {
            parser_status: ParserStatus::NotApplicable,
            observations_created: 0,
            facts_created: 0,
            diagnostics_created: 0,
            parser_name: None,
            parser_version: None,
        });
    }

    let parser_version = phase3::PARSER_VERSION;
    let ingest_timestamp = Utc::now();
    let mut packets = Vec::<ParsedPacket>::new();
    let mut packet_observations = Vec::new();
    let mut udp_protocol_observations = Vec::new();
    let mut resource_limited = false;
    let summary = PcapAdapter::parse_capture_with_sink(stored_path, |packet| {
        if packets.len() < MAX_PRODUCTION_PACKET_OBSERVATIONS {
            packets.push(packet.clone());
        }
        if packet_observations.len() >= MAX_PRODUCTION_PACKET_OBSERVATIONS {
            resource_limited = true;
            return Ok(());
        }
        if packet.dst_ip.is_none() {
            return Ok(());
        }
        let quality = match packet.parse_quality.as_str() {
            "FAILED" => core_domain::CaptureQuality::Failed,
            "PARTIAL" => core_domain::CaptureQuality::Partial,
            "DEGRADED" => core_domain::CaptureQuality::Degraded,
            _ => core_domain::CaptureQuality::Complete,
        };
        let source_timestamp = packet
            .capture_timestamp
            .as_ref()
            .map(|timestamp| timestamp.normalized_utc)
            .or_else(|| {
                chrono::DateTime::from_timestamp(
                    packet.timestamp_epoch_sec as i64,
                    packet.timestamp_epoch_usec * 1000,
                )
            });
        packet_observations.push(Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: Some(artifact.id),
            tool_run_id: None,
            source_tool: "pcap_parser".to_string(),
            raw_event_type: "network_socket".to_string(),
            source_timestamp,
            ingest_timestamp,
            data: json!({
                "destination_ip": packet.dst_ip,
                "destination_port": packet.dst_port,
                "source_ip": packet.src_ip,
                "source_port": packet.src_port,
                "protocol": packet.protocol,
                "tcp_flags": packet.tcp_flags,
                "packet_index": packet.packet_index,
                "interface_id": packet.interface_id,
                "physical_offset": packet.physical_offset,
                "packet_hash": packet.packet_hash,
                "packet_locator": packet.packet_locator,
                "capture_timestamp": packet.capture_timestamp,
                "artifact_blake3": artifact.hash_blake3,
                "artifact_sha256": artifact.hash_sha256,
                "captured_len": packet.captured_len,
                "original_len": packet.original_len,
                "parse_quality": packet.parse_quality,
                "parser_name": "PcapAdapter",
                "parser_version": parser_version,
            }),
            network_quality: Some(core_domain::NetworkObservationQuality {
                capture: quality,
                flow: None,
                protocol: None,
            }),
            network_provenance: Some(core_domain::NetworkDiagnosticProvenance {
                artifact_digest: artifact.hash_sha256.clone(),
                packet_index: Some(packet.packet_index as u64),
                packet_locator: Some(packet.packet_locator.clone()),
                flow_instance_id: None,
                direction: None,
            }),
        });
        if packet.protocol.as_deref() == Some("UDP")
            && (packet.src_port == Some(53) || packet.dst_port == Some(53))
        {
            let parsed_dns = phase3::extract_dns_detailed(&packet.payload);
            let (data, protocol_quality) = match parsed_dns {
                Ok(message) => {
                    let mut data = serde_json::to_value(message).unwrap_or_else(|_| json!({}));
                    if let Some(object) = data.as_object_mut() {
                        object.insert("source_ip".to_string(), json!(packet.src_ip));
                        object.insert("destination_ip".to_string(), json!(packet.dst_ip));
                        object.insert("source_port".to_string(), json!(packet.src_port));
                        object.insert("destination_port".to_string(), json!(packet.dst_port));
                        object.insert("packet_index".to_string(), json!(packet.packet_index));
                    }
                    (data, core_domain::ProtocolQuality::Complete)
                }
                Err(issue) => (
                    json!({
                        "parse_error": format!("{:?}", issue.kind),
                        "offset": issue.byte_offset,
                        "source_ip": packet.src_ip,
                        "destination_ip": packet.dst_ip,
                        "packet_index": packet.packet_index,
                    }),
                    core_domain::ProtocolQuality::Degraded,
                ),
            };
            udp_protocol_observations.push(Observation {
                id: EntityId::new_v7(),
                case_id,
                artifact_id: Some(artifact.id),
                tool_run_id: None,
                source_tool: "pcap_parser".to_string(),
                raw_event_type: "dns_message".to_string(),
                source_timestamp,
                ingest_timestamp,
                data,
                network_quality: Some(core_domain::NetworkObservationQuality {
                    capture: quality,
                    flow: None,
                    protocol: Some(protocol_quality),
                }),
                network_provenance: Some(core_domain::NetworkDiagnosticProvenance {
                    artifact_digest: artifact.hash_sha256.clone(),
                    packet_index: Some(packet.packet_index as u64),
                    packet_locator: Some(packet.packet_locator.clone()),
                    flow_instance_id: None,
                    direction: None,
                }),
            });
        }
        Ok(())
    })
    .map_err(|error| bad_request(&format!("parse failed: {error}"), "artifact"))?;

    for observation in &packet_observations {
        storage
            .insert_observation(observation)
            .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
    }
    for observation in &udp_protocol_observations {
        storage
            .insert_observation(observation)
            .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
    }
    let mut facts = correlator
        .correlate(&packet_observations)
        .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
    let facts_created = facts.len() as u64;
    for fact in facts.drain(..) {
        storage
            .insert_fact(&fact)
            .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
    }

    let mut observations_created =
        (packet_observations.len() + udp_protocol_observations.len()) as u64;
    let flows = phase3::reconstruct_flows_with_artifact(&artifact.hash_sha256, &packets);
    if flows.len() > MAX_PRODUCTION_FLOWS {
        resource_limited = true;
    }
    for flow in flows.into_iter().take(MAX_PRODUCTION_FLOWS) {
        let flow_packets: Vec<ParsedPacket> = packets
            .iter()
            .filter(|packet| phase3::packet_flow_key(packet) == flow.key)
            .cloned()
            .collect();
        let first_packet = flow_packets.first();
        let source_timestamp = first_packet.and_then(|packet| {
            packet
                .capture_timestamp
                .as_ref()
                .map(|timestamp| timestamp.normalized_utc)
                .or_else(|| {
                    chrono::DateTime::from_timestamp(
                        packet.timestamp_epoch_sec as i64,
                        packet.timestamp_epoch_usec * 1000,
                    )
                })
        });
        let capture_quality: core_domain::CaptureQuality = summary.quality.into();
        let flow_quality: core_domain::FlowQuality = flow.flow_quality.into();
        let provenance = || core_domain::NetworkDiagnosticProvenance {
            artifact_digest: artifact.hash_sha256.clone(),
            packet_index: first_packet.map(|packet| packet.packet_index as u64),
            packet_locator: first_packet.map(|packet| packet.packet_locator.clone()),
            flow_instance_id: Some(flow.flow_instance_id.clone()),
            direction: None,
        };
        storage
            .insert_observation(&Observation {
                id: EntityId::new_v7(),
                case_id,
                artifact_id: Some(artifact.id),
                tool_run_id: None,
                source_tool: "pcap_parser".to_string(),
                raw_event_type: "network_flow".to_string(),
                source_timestamp,
                ingest_timestamp,
                data: json!({
                    "flow": flow,
                    "parser_name": "PcapAdapter",
                    "parser_version": parser_version,
                }),
                network_quality: Some(core_domain::NetworkObservationQuality {
                    capture: capture_quality,
                    flow: Some(flow_quality),
                    protocol: None,
                }),
                network_provenance: Some(provenance()),
            })
            .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
        observations_created += 1;

        if flow.key.protocol != "TCP" {
            continue;
        }
        let stream = phase3::reassemble_tcp(&flow_packets);
        let reassembly_quality = match stream.status {
            phase3::ReassemblyStatus::Complete => core_domain::ProtocolQuality::Complete,
            phase3::ReassemblyStatus::Partial
            | phase3::ReassemblyStatus::Gapped
            | phase3::ReassemblyStatus::Truncated => core_domain::ProtocolQuality::Partial,
        };
        let first_port = first_packet.and_then(|packet| packet.dst_port.or(packet.src_port));
        let protocol_observation = if matches!(first_port, Some(53)) {
            phase3::extract_dns_tcp_messages_detailed(&stream.bytes)
                .ok()
                .and_then(|messages| messages.into_iter().next())
                .and_then(|message| {
                    serde_json::to_value(message)
                        .ok()
                        .map(|data| ("dns_message", data))
                })
        } else if matches!(first_port, Some(80) | Some(8080) | Some(8000)) {
            phase3::extract_http(&stream.bytes)
                .and_then(|message| serde_json::to_value(message).ok())
                .map(|data| ("http_message", data))
        } else if matches!(first_port, Some(443) | Some(8443)) {
            match phase3::parse_tls_handshake_observation(&stream.bytes) {
                Ok(message) => Some((
                    "tls_handshake",
                    serde_json::to_value(message).unwrap_or_else(|_| json!({})),
                )),
                Err(issue) => Some((
                    "tls_handshake",
                    json!({ "parse_error": format!("{:?}", issue.kind), "offset": issue.offset }),
                )),
            }
        } else {
            None
        };
        if let Some((event_type, data)) = protocol_observation {
            let protocol_quality = if event_type == "tls_handshake" {
                if data.get("parse_error").is_some() {
                    core_domain::ProtocolQuality::Degraded
                } else {
                    core_domain::ProtocolQuality::Complete
                }
            } else {
                reassembly_quality
            };
            storage
                .insert_observation(&Observation {
                    id: EntityId::new_v7(),
                    case_id,
                    artifact_id: Some(artifact.id),
                    tool_run_id: None,
                    source_tool: "pcap_parser".to_string(),
                    raw_event_type: event_type.to_string(),
                    source_timestamp,
                    ingest_timestamp,
                    data,
                    network_quality: Some(core_domain::NetworkObservationQuality {
                        capture: capture_quality,
                        flow: Some(flow_quality),
                        protocol: Some(protocol_quality),
                    }),
                    network_provenance: Some(provenance()),
                })
                .map_err(|error| bad_request(&error.to_string(), "artifact"))?;
            observations_created += 1;
        }
    }

    let parser_status = match (summary.quality, resource_limited) {
        (_, true) => ParserStatus::Partial,
        (phase3::PcapQuality::Complete, false) => ParserStatus::Succeeded,
        (phase3::PcapQuality::Degraded | phase3::PcapQuality::Partial, false) => {
            ParserStatus::Partial
        }
        (phase3::PcapQuality::Failed, false) => ParserStatus::Failed,
    };
    crate::analysis::process_persisted_observations(storage, case_id)
        .map_err(|error| bad_request(&error.to_string(), "analysis"))?;
    Ok(ArtifactProcessingResult {
        parser_status,
        observations_created,
        facts_created,
        diagnostics_created: summary.diagnostics.len() as u64 + u64::from(resource_limited),
        parser_name: Some("PcapAdapter".to_string()),
        parser_version: Some(parser_version.to_string()),
    })
}

/// Legacy helper for base64 ingest preserved for backward compatibility
pub async fn handle_evidence_ingest(
    params: serde_json::Value,
    storage: &SqliteStorage,
    cas: &ContentAddressedStorage,
    correlator: &DeterministicCorrelationEngine,
) -> Result<serde_json::Value, ProblemDetails> {
    let case_id = params
        .get("case_id")
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::parse(s).ok())
        .ok_or_else(|| {
            bad_request(
                "Missing or invalid case_id -- create or select a case first",
                "case_id",
            )
        })?;

    storage
        .get_case(case_id)
        .map_err(|e| bad_request(&e.to_string(), "case_id"))?
        .ok_or_else(|| bad_request("Case not found", "case_id"))?;

    let filename = params
        .get("filename")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("Missing filename", "filename"))?
        .to_string();

    let content_b64 = params
        .get("content_base64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("Missing content_base64", "content_base64"))?;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(content_b64)
        .map_err(|e| bad_request(&format!("Invalid base64: {e}"), "content_base64"))?;

    if bytes.is_empty() {
        return Err(bad_request("Empty file", "content_base64"));
    }
    if bytes.len() > MAX_INGEST_BYTES {
        return Err(bad_request(
            "File too large for legacy ingest (max 256 MB, use streaming ingest instead)",
            "content_base64",
        ));
    }

    let ext = std::path::Path::new(&filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if !matches!(ext.as_str(), "evtx" | "pcap" | "pcapng" | "cap") {
        return Err(bad_request(
            &format!("Unsupported evidence file type: .{ext}"),
            "filename",
        ));
    }

    let stored = cas
        .store_bytes(&bytes)
        .await
        .map_err(|e| bad_request(&e.to_string(), "content_base64"))?;
    let stored_path = cas.get_path_for_blake3(&stored.blake3);

    let now = Utc::now();
    let artifact = Artifact {
        id: EntityId::new_v7(),
        case_id,
        hash_blake3: stored.blake3.clone(),
        hash_sha256: stored.sha256.clone(),
        original_name: filename.clone(),
        file_size: stored.size_bytes,
        mime_type: if ext == "evtx" {
            "application/x-evtx+json-stream".to_string()
        } else {
            "application/vnd.tcpdump.pcap".to_string()
        },
        acquisition_method: "ui_upload".to_string(),
        acquired_at: now,
        ingested_at: now,
    };
    storage
        .insert_artifact(&artifact)
        .map_err(|e| bad_request(&e.to_string(), "filename"))?;

    let genesis_hash = blake3::hash(b"GENESIS").to_hex().to_string();
    let acquired_details =
        json!({"original_name": filename, "size_bytes": stored.size_bytes}).to_string();
    let acquired_event = CustodyEvent {
        id: EntityId::new_v7(),
        case_id,
        actor_id: "ui_upload".to_string(),
        event_type: CustodyEventType::ArtifactAcquired,
        artifact_hash: Some(stored.blake3.clone()),
        details_json: acquired_details.clone(),
        previous_state_hash: genesis_hash,
        timestamp: now,
    };
    let _ = storage.append_custody_event(&acquired_event);

    if ext != "evtx" {
        let processing =
            process_committed_artifact(case_id, &artifact, &stored_path, storage, correlator)
                .await?;
        let parsed_event = CustodyEvent {
            id: EntityId::new_v7(),
            case_id,
            actor_id: "pcap_parser".to_string(),
            event_type: CustodyEventType::ArtifactParsed,
            artifact_hash: Some(stored.blake3.clone()),
            details_json: serde_json::to_string(&processing).unwrap_or_else(|_| "{}".to_string()),
            previous_state_hash: blake3::hash(acquired_details.as_bytes())
                .to_hex()
                .to_string(),
            timestamp: Utc::now(),
        };
        let _ = storage.append_custody_event(&parsed_event);
        return Ok(json!({
            "artifact_id": artifact.id.to_string(),
            "hash_blake3": stored.blake3,
            "hash_sha256": stored.sha256,
            "file_size": stored.size_bytes,
            "tool": processing.parser_name,
            "events_extracted": processing.observations_created,
            "facts_derived": processing.facts_created,
            "parser_status": processing.parser_status,
            "observations_created": processing.observations_created,
            "diagnostics_created": processing.diagnostics_created,
        }));
    }

    let pcap_summary: Option<phase3::PcapParseResult> = None;
    let streamed_pcap_observations = 0usize;
    let streamed_pcap_facts = 0usize;
    let parse_result: RawToolResult = if ext == "evtx" {
        let adapter: Box<dyn ToolAdapter> = Box::new(EvtxAdapter);
        adapter
            .parse_artifact(&stored_path)
            .await
            .map_err(|e| bad_request(&format!("Не удалось разобрать файл: {e}"), "filename"))?
    } else {
        let summary =
            pcap_summary.ok_or_else(|| bad_request("PCAP summary is unavailable", "filename"))?;
        let serialized =
            serde_json::to_vec(&summary).map_err(|e| bad_request(&e.to_string(), "filename"))?;
        RawToolResult {
            tool_name: "pcap_parser".to_string(),
            tool_version: tool_adapters::pcap::phase3::PARSER_VERSION.to_string(),
            exit_code: 0,
            stdout_bytes: serialized.clone(),
            stderr_bytes: Vec::new(),
            execution_duration_ms: 25,
            output_hash: blake3::hash(&serialized).to_hex().to_string(),
        }
    };
    let observations: Vec<Observation> = if ext == "evtx" {
        if let Ok(res) = serde_json::from_slice::<tool_adapters::evtx::EvtxParseResult>(
            &parse_result.stdout_bytes,
        ) {
            res.records
                .iter()
                .map(|rec| {
                    tool_adapters::evtx::EvtxNormalizer::normalize_record(
                        case_id,
                        Some(artifact.id),
                        None,
                        rec,
                    )
                })
                .collect()
        } else {
            let records: Vec<ParsedEvtxRecord> = serde_json::from_slice(&parse_result.stdout_bytes)
                .map_err(|e| bad_request(&e.to_string(), "filename"))?;
            records
                .into_iter()
                .map(|rec| Observation {
                    id: EntityId::new_v7(),
                    case_id,
                    artifact_id: Some(artifact.id),
                    tool_run_id: None,
                    source_tool: parse_result.tool_name.clone(),
                    raw_event_type: "evtx_record".to_string(),
                    source_timestamp: rec.timestamp,
                    ingest_timestamp: now,
                    data: json!({
                        "event_id": rec.event_id,
                        "provider": rec.provider,
                        "channel": rec.channel,
                        "host": rec.computer,
                        "process_name": rec.data.get("Image").and_then(|v| v.as_str()),
                        "command_line": rec.data.get("CommandLine").and_then(|v| v.as_str()),
                        "parent_name": rec.data.get("ParentImage").and_then(|v| v.as_str()),
                        "executable_path": rec.data.get("Image").and_then(|v| v.as_str()),
                        "event_data": rec.data
                    }),
                    network_quality: None,
                    network_provenance: None,
                })
                .collect()
        }
    } else {
        // Packets were consumed by the bounded callback above. The adapter
        // result is a summary and must never be decoded as a packet list.
        Vec::new()
    };

    for obs in &observations {
        let _ = storage.insert_observation(obs);
    }

    crate::analysis::process_persisted_observations(storage, case_id)
        .map_err(|error| bad_request(&error.to_string(), "analysis"))?;

    let facts = correlator.correlate(&observations).unwrap_or_default();
    for f in &facts {
        let _ = storage.insert_fact(f);
    }

    let parsed_event = CustodyEvent {
        id: EntityId::new_v7(),
        case_id,
        actor_id: parse_result.tool_name.clone(),
        event_type: CustodyEventType::ArtifactParsed,
        artifact_hash: Some(stored.blake3.clone()),
        details_json: json!({
            "events_extracted": observations.len() + streamed_pcap_observations,
            "facts_derived": facts.len() + streamed_pcap_facts
        })
        .to_string(),
        previous_state_hash: blake3::hash(acquired_details.as_bytes())
            .to_hex()
            .to_string(),
        timestamp: Utc::now(),
    };
    let _ = storage.append_custody_event(&parsed_event);

    Ok(json!({
        "artifact_id": artifact.id.to_string(),
        "hash_blake3": stored.blake3,
        "hash_sha256": stored.sha256,
        "file_size": stored.size_bytes,
        "tool": parse_result.tool_name,
        "events_extracted": observations.len() + streamed_pcap_observations,
        "facts_derived": facts.len() + streamed_pcap_facts
    }))
}
