#![forbid(unsafe_code)]

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
    evtx::ParsedEvtxRecord, pcap::ParsedPacket, EvtxAdapter, PcapAdapter, ToolAdapter,
};

/// Files larger than this are refused: the file travels as base64 inside a
/// single JSON-RPC request, so this is not a path for multi-gigabyte captures.
const MAX_INGEST_BYTES: usize = 256 * 1024 * 1024;

fn bad_request(detail: &str, field: &str) -> ProblemDetails {
    ProblemDetails::bad_request(detail, vec![field.to_string()])
}

/// Ingests a user-supplied evidence file (.evtx JSON-stream or .pcap) into the
/// case: stores it in CAS, records an Artifact + chain-of-custody events,
/// parses it with the matching real adapter, stores the resulting
/// Observations, and runs correlation to derive Facts.
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
            "File too large for ingest (max 256 MB)",
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
            &format!(
                "Unsupported evidence file type: .{ext} (поддерживаются .evtx как построчный JSON, .pcap/.pcapng/.cap)"
            ),
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

    let adapter: Box<dyn ToolAdapter> = if ext == "evtx" {
        Box::new(EvtxAdapter)
    } else {
        Box::new(PcapAdapter)
    };

    let parse_result: RawToolResult = adapter
        .parse_artifact(&stored_path)
        .await
        .map_err(|e| bad_request(&format!("Не удалось разобрать файл: {e}"), "filename"))?;

    let tool_run_id = EntityId::new_v7();
    let observations: Vec<Observation> = if ext == "evtx" {
        let records: Vec<ParsedEvtxRecord> = serde_json::from_slice(&parse_result.stdout_bytes)
            .map_err(|e| bad_request(&e.to_string(), "filename"))?;
        records
            .into_iter()
            .map(|rec| Observation {
                id: EntityId::new_v7(),
                case_id,
                artifact_id: Some(artifact.id),
                tool_run_id: Some(tool_run_id),
                source_tool: parse_result.tool_name.clone(),
                raw_event_type: "evtx_record".to_string(),
                source_timestamp: rec.timestamp,
                ingest_timestamp: now,
                data: json!({
                    "event_id": rec.event_id,
                    "provider": rec.provider,
                    "channel": rec.channel,
                    "host": rec.computer,
                    // Best-effort field aliases so existing process-based
                    // correlation rules can match common Sysmon/Security
                    // EventData shapes (Image/CommandLine/ParentImage).
                    "process_name": rec.data.get("Image").and_then(|v| v.as_str()),
                    "command_line": rec.data.get("CommandLine").and_then(|v| v.as_str()),
                    "parent_name": rec.data.get("ParentImage").and_then(|v| v.as_str()),
                    "executable_path": rec.data.get("Image").and_then(|v| v.as_str()),
                    "event_data": rec.data
                }),
            })
            .collect()
    } else {
        let packets: Vec<ParsedPacket> = serde_json::from_slice(&parse_result.stdout_bytes)
            .map_err(|e| bad_request(&e.to_string(), "filename"))?;
        packets
            .into_iter()
            .filter(|p| p.dst_ip.is_some())
            .map(|p| Observation {
                id: EntityId::new_v7(),
                case_id,
                artifact_id: Some(artifact.id),
                tool_run_id: Some(tool_run_id),
                source_tool: parse_result.tool_name.clone(),
                raw_event_type: "network_socket".to_string(),
                source_timestamp: now,
                ingest_timestamp: now,
                data: json!({
                    "destination_ip": p.dst_ip,
                    "destination_port": p.dst_port,
                    "source_ip": p.src_ip,
                    "source_port": p.src_port,
                    "protocol": p.protocol,
                    "tcp_flags": p.tcp_flags
                }),
            })
            .collect()
    };

    for obs in &observations {
        let _ = storage.insert_observation(obs);
    }

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
            "events_extracted": observations.len(),
            "facts_derived": facts.len()
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
        "events_extracted": observations.len(),
        "facts_derived": facts.len()
    }))
}
