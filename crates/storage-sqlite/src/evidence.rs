#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use core_domain::id::EntityId;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MIGRATION_006_SQL: &str = r#"
-- 37. Streaming Evidence Ingest Sessions
CREATE TABLE IF NOT EXISTS evidence_ingest_sessions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    filename TEXT NOT NULL,
    declared_size_bytes INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    staging_path TEXT NOT NULL,
    status TEXT NOT NULL,
    sha256 TEXT,
    blake3 TEXT,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    actor_id TEXT NOT NULL,
    upload_token_hash TEXT NOT NULL,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingest_case ON evidence_ingest_sessions(case_id);
CREATE INDEX IF NOT EXISTS idx_ingest_status ON evidence_ingest_sessions(status);

-- 38. Tamper-Evident Forensic Custody Events (Append-Only)
CREATE TABLE IF NOT EXISTS evidence_custody_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES evidence_ingest_sessions(id) ON DELETE RESTRICT,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    blake3 TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    details_hash TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custody_artifact_seq ON evidence_custody_events(artifact_id, sequence_no);
CREATE INDEX IF NOT EXISTS idx_custody_session_seq ON evidence_custody_events(session_id, sequence_no);

-- Prevent any UPDATE or DELETE on evidence_custody_events to enforce append-only invariant
CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_update
BEFORE UPDATE ON evidence_custody_events
BEGIN
    SELECT RAISE(ABORT, 'Forensic Invariant Violation: evidence_custody_events is append-only; updates are strictly forbidden.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_delete
BEFORE DELETE ON evidence_custody_events
BEGIN
    SELECT RAISE(ABORT, 'Forensic Invariant Violation: evidence_custody_events is append-only; deletions are strictly forbidden.');
END;
"#;

#[derive(Error, Debug)]
pub enum CustodyError {
    #[error("Database error: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error("Custody chain empty for target")]
    EmptyChain,

    #[error("Chain sequence broken at sequence {0}: expected {1}, got {2}")]
    SequenceBreak(u64, u64, u64),

    #[error("Genesis link broken at sequence {0}: expected 'GENESIS', got '{1}'")]
    GenesisBreak(u64, String),

    #[error("Previous hash mismatch at sequence {0}: expected '{1}', got '{2}'")]
    PreviousHashMismatch(u64, String, String),

    #[error("Calculated event hash mismatch at sequence {0}: stored '{1}', recomputed '{2}'")]
    EventHashMismatch(u64, String, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestSessionRecord {
    pub id: EntityId,
    pub case_id: EntityId,
    pub filename: String,
    pub declared_size_bytes: u64,
    pub bytes_received: u64,
    pub staging_path: String,
    pub status: String,
    pub sha256: Option<String>,
    pub blake3: Option<String>,
    pub artifact_id: Option<EntityId>,
    pub actor_id: String,
    pub upload_token_hash: String,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicCustodyEvent {
    pub event_id: EntityId,
    pub session_id: EntityId,
    pub artifact_id: Option<EntityId>,
    pub case_id: EntityId,
    pub sequence_no: u64,
    pub action: String,
    pub actor_id: String,
    pub timestamp_utc: DateTime<Utc>,
    pub sha256: String,
    pub blake3: String,
    pub previous_event_hash: String,
    pub event_hash: String,
    pub details_hash: String,
    pub details_json: String,
}

/// Length-prefixed canonical event hash computation
#[allow(clippy::too_many_arguments)]
pub fn compute_custody_event_hash(
    previous_event_hash: &str,
    sequence_no: u64,
    event_id: &str,
    session_id: &str,
    artifact_id: Option<&str>,
    case_id: &str,
    action: &str,
    actor_id: &str,
    timestamp_utc: &str,
    sha256: &str,
    blake3: &str,
    details_hash: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SOCDFIR-CUSTODY-V1\0");

    fn append_field(hasher: &mut blake3::Hasher, field: &[u8]) {
        let len = (field.len() as u32).to_be_bytes();
        hasher.update(&len);
        hasher.update(field);
    }

    append_field(&mut hasher, previous_event_hash.as_bytes());
    hasher.update(&sequence_no.to_be_bytes());
    append_field(&mut hasher, event_id.as_bytes());
    append_field(&mut hasher, session_id.as_bytes());
    append_field(&mut hasher, artifact_id.unwrap_or("").as_bytes());
    append_field(&mut hasher, case_id.as_bytes());
    append_field(&mut hasher, action.as_bytes());
    append_field(&mut hasher, actor_id.as_bytes());
    append_field(&mut hasher, timestamp_utc.as_bytes());
    append_field(&mut hasher, sha256.as_bytes());
    append_field(&mut hasher, blake3.as_bytes());
    append_field(&mut hasher, details_hash.as_bytes());

    hasher.finalize().to_hex().to_string()
}

pub fn insert_ingest_session(
    conn: &Connection,
    s: &IngestSessionRecord,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO evidence_ingest_sessions (
            id, case_id, filename, declared_size_bytes, bytes_received,
            staging_path, status, sha256, blake3, artifact_id, actor_id,
            upload_token_hash, error_message, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            s.id.to_string(),
            s.case_id.to_string(),
            s.filename,
            s.declared_size_bytes as i64,
            s.bytes_received as i64,
            s.staging_path,
            s.status,
            s.sha256,
            s.blake3,
            s.artifact_id.map(|id| id.to_string()),
            s.actor_id,
            s.upload_token_hash,
            s.error_message,
            s.created_at.to_rfc3339(),
            s.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn update_ingest_session(
    conn: &Connection,
    s: &IngestSessionRecord,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE evidence_ingest_sessions SET
            bytes_received = ?1,
            status = ?2,
            sha256 = ?3,
            blake3 = ?4,
            artifact_id = ?5,
            error_message = ?6,
            updated_at = ?7
        WHERE id = ?8",
        params![
            s.bytes_received as i64,
            s.status,
            s.sha256,
            s.blake3,
            s.artifact_id.map(|id| id.to_string()),
            s.error_message,
            s.updated_at.to_rfc3339(),
            s.id.to_string(),
        ],
    )?;
    Ok(())
}

pub fn get_ingest_session(
    conn: &Connection,
    session_id: EntityId,
) -> Result<Option<IngestSessionRecord>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, case_id, filename, declared_size_bytes, bytes_received,
                staging_path, status, sha256, blake3, artifact_id, actor_id,
                upload_token_hash, error_message, created_at, updated_at
         FROM evidence_ingest_sessions WHERE id = ?1",
    )?;

    let res = stmt
        .query_row(params![session_id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let case_id_str: String = row.get(1)?;
            let filename: String = row.get(2)?;
            let declared_size: i64 = row.get(3)?;
            let bytes_rec: i64 = row.get(4)?;
            let staging_path: String = row.get(5)?;
            let status: String = row.get(6)?;
            let sha256: Option<String> = row.get(7)?;
            let blake3: Option<String> = row.get(8)?;
            let art_id_str: Option<String> = row.get(9)?;
            let actor_id: String = row.get(10)?;
            let upload_token_hash: String = row.get(11)?;
            let error_message: Option<String> = row.get(12)?;
            let created_at_str: String = row.get(13)?;
            let updated_at_str: String = row.get(14)?;

            Ok(IngestSessionRecord {
                id: EntityId::parse(&id_str).unwrap_or_default(),
                case_id: EntityId::parse(&case_id_str).unwrap_or_default(),
                filename,
                declared_size_bytes: declared_size as u64,
                bytes_received: bytes_rec as u64,
                staging_path,
                status,
                sha256,
                blake3,
                artifact_id: art_id_str.and_then(|s| EntityId::parse(&s).ok()),
                actor_id,
                upload_token_hash,
                error_message,
                created_at: DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated_at_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })
        .optional()?;

    Ok(res)
}

pub fn insert_custody_event(
    conn: &Connection,
    e: &ForensicCustodyEvent,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO evidence_custody_events (
            event_id, session_id, artifact_id, case_id, sequence_no,
            action, actor_id, timestamp_utc, sha256, blake3,
            previous_event_hash, event_hash, details_hash, details_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            e.event_id.to_string(),
            e.session_id.to_string(),
            e.artifact_id.map(|id| id.to_string()),
            e.case_id.to_string(),
            e.sequence_no as i64,
            e.action,
            e.actor_id,
            e.timestamp_utc.to_rfc3339(),
            e.sha256,
            e.blake3,
            e.previous_event_hash,
            e.event_hash,
            e.details_hash,
            e.details_json,
        ],
    )?;
    Ok(())
}

pub fn list_custody_events_for_session(
    conn: &Connection,
    session_id: EntityId,
) -> Result<Vec<ForensicCustodyEvent>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT event_id, session_id, artifact_id, case_id, sequence_no,
                action, actor_id, timestamp_utc, sha256, blake3,
                previous_event_hash, event_hash, details_hash, details_json
         FROM evidence_custody_events WHERE session_id = ?1 ORDER BY sequence_no ASC",
    )?;

    let rows = stmt.query_map(params![session_id.to_string()], map_custody_row)?;
    let mut events = Vec::new();
    for r in rows {
        events.push(r?);
    }
    Ok(events)
}

pub fn list_custody_events_for_artifact(
    conn: &Connection,
    artifact_id: EntityId,
) -> Result<Vec<ForensicCustodyEvent>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT event_id, session_id, artifact_id, case_id, sequence_no,
                action, actor_id, timestamp_utc, sha256, blake3,
                previous_event_hash, event_hash, details_hash, details_json
         FROM evidence_custody_events
         WHERE session_id = (SELECT id FROM evidence_ingest_sessions WHERE artifact_id = ?1)
            OR artifact_id = ?1
         ORDER BY sequence_no ASC",
    )?;

    let rows = stmt.query_map(params![artifact_id.to_string()], map_custody_row)?;
    let mut events = Vec::new();
    for r in rows {
        events.push(r?);
    }
    Ok(events)
}

fn map_custody_row(row: &rusqlite::Row) -> Result<ForensicCustodyEvent, rusqlite::Error> {
    let event_id_str: String = row.get(0)?;
    let session_id_str: String = row.get(1)?;
    let art_id_str: Option<String> = row.get(2)?;
    let case_id_str: String = row.get(3)?;
    let seq_no: i64 = row.get(4)?;
    let action: String = row.get(5)?;
    let actor_id: String = row.get(6)?;
    let ts_str: String = row.get(7)?;
    let sha256: String = row.get(8)?;
    let blake3: String = row.get(9)?;
    let prev_hash: String = row.get(10)?;
    let event_hash: String = row.get(11)?;
    let details_hash: String = row.get(12)?;
    let details_json: String = row.get(13)?;

    Ok(ForensicCustodyEvent {
        event_id: EntityId::parse(&event_id_str).unwrap_or_default(),
        session_id: EntityId::parse(&session_id_str).unwrap_or_default(),
        artifact_id: art_id_str.and_then(|s| EntityId::parse(&s).ok()),
        case_id: EntityId::parse(&case_id_str).unwrap_or_default(),
        sequence_no: seq_no as u64,
        action,
        actor_id,
        timestamp_utc: DateTime::parse_from_rfc3339(&ts_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        sha256,
        blake3,
        previous_event_hash: prev_hash,
        event_hash,
        details_hash,
        details_json,
    })
}

/// Verifies cryptographic integrity of a custody event sequence.
pub fn verify_custody_event_sequence(
    events: &[ForensicCustodyEvent],
) -> Result<bool, CustodyError> {
    if events.is_empty() {
        return Err(CustodyError::EmptyChain);
    }

    for (idx, event) in events.iter().enumerate() {
        let expected_seq = (idx as u64) + 1;
        if event.sequence_no != expected_seq {
            return Err(CustodyError::SequenceBreak(
                event.sequence_no,
                expected_seq,
                event.sequence_no,
            ));
        }

        if idx == 0 {
            if event.previous_event_hash != "GENESIS" {
                return Err(CustodyError::GenesisBreak(
                    event.sequence_no,
                    event.previous_event_hash.clone(),
                ));
            }
        } else {
            let prev_event = &events[idx - 1];
            if event.previous_event_hash != prev_event.event_hash {
                return Err(CustodyError::PreviousHashMismatch(
                    event.sequence_no,
                    prev_event.event_hash.clone(),
                    event.previous_event_hash.clone(),
                ));
            }
        }

        let recomputed_hash = compute_custody_event_hash(
            &event.previous_event_hash,
            event.sequence_no,
            &event.event_id.to_string(),
            &event.session_id.to_string(),
            event.artifact_id.map(|id| id.to_string()).as_deref(),
            &event.case_id.to_string(),
            &event.action,
            &event.actor_id,
            &event.timestamp_utc.to_rfc3339(),
            &event.sha256,
            &event.blake3,
            &event.details_hash,
        );

        if recomputed_hash != event.event_hash {
            return Err(CustodyError::EventHashMismatch(
                event.sequence_no,
                event.event_hash.clone(),
                recomputed_hash,
            ));
        }
    }

    Ok(true)
}
