#![forbid(unsafe_code)]

use super::session::IngestSessionManager;
use core_domain::id::EntityId;
use ipc_protocol::ProblemDetails;
use serde_json::{json, Value};
use storage_cas::ContentAddressedStorage;
use storage_sqlite::SqliteStorage;

pub async fn handle_ingest_begin(
    params: Value,
    session_mgr: &IngestSessionManager,
    storage: &SqliteStorage,
) -> Result<Value, ProblemDetails> {
    let case_id = params
        .get("case_id")
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::parse(s).ok())
        .ok_or_else(|| {
            ProblemDetails::bad_request("Missing or invalid case_id", vec!["case_id".to_string()])
        })?;

    let filename = params
        .get("filename")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProblemDetails::bad_request("Missing filename", vec!["filename".to_string()])
        })?;

    let declared_size = params
        .get("declared_size_bytes")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            ProblemDetails::bad_request(
                "Missing declared_size_bytes",
                vec!["declared_size_bytes".to_string()],
            )
        })?;

    let actor_id = params
        .get("actor_id")
        .and_then(|v| v.as_str())
        .unwrap_or("forensic_analyst");

    let res = session_mgr
        .begin_ingest(case_id, filename, declared_size, actor_id, storage)
        .await?;

    Ok(json!(res))
}

pub async fn handle_ingest_complete(
    params: Value,
    session_mgr: &IngestSessionManager,
    storage: &SqliteStorage,
    cas: &ContentAddressedStorage,
) -> Result<Value, ProblemDetails> {
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::parse(s).ok())
        .ok_or_else(|| {
            ProblemDetails::bad_request(
                "Missing or invalid session_id",
                vec!["session_id".to_string()],
            )
        })?;

    let res = session_mgr
        .complete_ingest(session_id, storage, cas)
        .await?;

    Ok(json!(res))
}

pub async fn handle_ingest_status(
    params: Value,
    session_mgr: &IngestSessionManager,
    storage: &SqliteStorage,
) -> Result<Value, ProblemDetails> {
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::parse(s).ok())
        .ok_or_else(|| {
            ProblemDetails::bad_request(
                "Missing or invalid session_id",
                vec!["session_id".to_string()],
            )
        })?;

    let res = session_mgr.get_status(session_id, storage).await?;
    Ok(json!(res))
}

pub async fn handle_ingest_cancel(
    params: Value,
    session_mgr: &IngestSessionManager,
    storage: &SqliteStorage,
) -> Result<Value, ProblemDetails> {
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .and_then(|s| EntityId::parse(s).ok())
        .ok_or_else(|| {
            ProblemDetails::bad_request(
                "Missing or invalid session_id",
                vec!["session_id".to_string()],
            )
        })?;

    session_mgr.cancel_ingest(session_id, storage).await
}

pub async fn handle_custody_verify(
    params: Value,
    storage: &SqliteStorage,
) -> Result<Value, ProblemDetails> {
    if let Some(art_id_str) = params.get("artifact_id").and_then(|v| v.as_str()) {
        let art_id = EntityId::parse(art_id_str)
            .map_err(|_| ProblemDetails::bad_request("Invalid artifact_id", vec![]))?;
        let events = storage
            .list_custody_events_for_artifact(art_id)
            .unwrap_or_default();
        match storage.verify_custody_chain(art_id) {
            Ok(valid) => Ok(json!({
                "artifact_id": art_id,
                "chain_valid": valid,
                "valid": valid,
                "event_count": events.len(),
                "events": events
            })),
            Err(e) => Ok(json!({
                "artifact_id": art_id,
                "chain_valid": false,
                "valid": false,
                "error": e.to_string(),
                "event_count": events.len()
            })),
        }
    } else if let Some(sess_id_str) = params.get("session_id").and_then(|v| v.as_str()) {
        let sess_id = EntityId::parse(sess_id_str)
            .map_err(|_| ProblemDetails::bad_request("Invalid session_id", vec![]))?;
        let events = storage
            .list_custody_events_for_session(sess_id)
            .unwrap_or_default();
        match storage.verify_session_custody_chain(sess_id) {
            Ok(valid) => Ok(json!({
                "session_id": sess_id,
                "chain_valid": valid,
                "valid": valid,
                "event_count": events.len(),
                "events": events
            })),
            Err(e) => Ok(json!({
                "session_id": sess_id,
                "chain_valid": false,
                "valid": false,
                "error": e.to_string(),
                "event_count": events.len()
            })),
        }
    } else {
        Err(ProblemDetails::bad_request(
            "Missing artifact_id or session_id",
            vec!["target".to_string()],
        ))
    }
}
