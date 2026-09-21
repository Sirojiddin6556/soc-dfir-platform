#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use core_domain::artifact::Artifact;
use core_domain::case::Case;
use core_domain::id::EntityId;
use rusqlite::{params, Connection};

pub fn insert_case(
    conn: &Connection,
    id: EntityId,
    title: &str,
    description: Option<&str>,
) -> Result<(), rusqlite::Error> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO cases (id, title, description, status, created_at, updated_at) VALUES (?1, ?2, ?3, 'Active', ?4, ?4)",
        params![id.to_string(), title, description, now],
    )?;
    Ok(())
}

pub fn list_cases(conn: &Connection) -> Result<Vec<Case>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, title, description, status, created_at, updated_at FROM cases ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        let id_str: String = row.get(0)?;
        let title: String = row.get(1)?;
        let description: Option<String> = row.get(2)?;
        let status: String = row.get(3)?;
        let created_at_str: String = row.get(4)?;
        let updated_at_str: String = row.get(5)?;

        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(Case {
            id: EntityId::parse(&id_str).unwrap_or_default(),
            title,
            description,
            status,
            created_at,
            updated_at,
        })
    })?;

    let mut cases = Vec::new();
    for case_res in rows {
        cases.push(case_res?);
    }
    Ok(cases)
}

pub fn get_case(conn: &Connection, id: EntityId) -> Result<Option<Case>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, title, description, status, created_at, updated_at FROM cases WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![id.to_string()], |row| {
        let id_str: String = row.get(0)?;
        let title: String = row.get(1)?;
        let description: Option<String> = row.get(2)?;
        let status: String = row.get(3)?;
        let created_at_str: String = row.get(4)?;
        let updated_at_str: String = row.get(5)?;

        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(Case {
            id: EntityId::parse(&id_str).unwrap_or_default(),
            title,
            description,
            status,
            created_at,
            updated_at,
        })
    })?;

    if let Some(res) = rows.next() {
        Ok(Some(res?))
    } else {
        Ok(None)
    }
}

pub fn insert_artifact(conn: &Connection, art: &Artifact) -> Result<(), rusqlite::Error> {
    conn.execute(
        r#"INSERT INTO artifacts (
            id, case_id, hash_blake3, hash_sha256, original_name,
            file_size, mime_type, acquisition_method, acquired_at, ingested_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
        params![
            art.id.to_string(),
            art.case_id.to_string(),
            art.hash_blake3,
            art.hash_sha256,
            art.original_name,
            art.file_size as i64,
            art.mime_type,
            art.acquisition_method,
            art.acquired_at.to_rfc3339(),
            art.ingested_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn get_artifact(conn: &Connection, id: EntityId) -> Result<Option<Artifact>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, case_id, hash_blake3, hash_sha256, original_name, \
         file_size, mime_type, acquisition_method, acquired_at, ingested_at \
         FROM artifacts WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![id.to_string()], map_artifact_row)?;
    if let Some(res) = rows.next() {
        Ok(Some(res?))
    } else {
        Ok(None)
    }
}

pub fn get_artifact_by_blake3(
    conn: &Connection,
    blake3_hex: &str,
) -> Result<Option<Artifact>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, case_id, hash_blake3, hash_sha256, original_name, \
         file_size, mime_type, acquisition_method, acquired_at, ingested_at \
         FROM artifacts WHERE hash_blake3 = ?1 LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![blake3_hex], map_artifact_row)?;
    if let Some(res) = rows.next() {
        Ok(Some(res?))
    } else {
        Ok(None)
    }
}

pub fn list_artifacts_for_case(
    conn: &Connection,
    case_id: EntityId,
) -> Result<Vec<Artifact>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, case_id, hash_blake3, hash_sha256, original_name, \
         file_size, mime_type, acquisition_method, acquired_at, ingested_at \
         FROM artifacts WHERE case_id = ?1 ORDER BY ingested_at DESC",
    )?;
    let rows = stmt.query_map(params![case_id.to_string()], map_artifact_row)?;
    let mut artifacts = Vec::new();
    for r in rows {
        artifacts.push(r?);
    }
    Ok(artifacts)
}

pub fn delete_artifact(
    conn: &Connection,
    artifact_id: EntityId,
    case_id: EntityId,
) -> Result<bool, rusqlite::Error> {
    let deleted = conn.execute(
        "DELETE FROM artifacts WHERE id = ?1 AND case_id = ?2",
        params![artifact_id.to_string(), case_id.to_string()],
    )?;
    Ok(deleted > 0)
}

pub fn list_artifacts_for_case_json(
    conn: &Connection,
    case_id: EntityId,
) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, hash_blake3, hash_sha256, original_name, file_size, mime_type, \
         acquisition_method, acquired_at FROM artifacts WHERE case_id = ?1 ORDER BY ingested_at DESC",
    )?;
    let rows = stmt.query_map(params![case_id.to_string()], |row| {
        Ok(serde_json::json!({
            "id":          row.get::<_, String>(0)?,
            "hash_blake3": row.get::<_, String>(1)?,
            "hash_sha256": row.get::<_, String>(2)?,
            "name":        row.get::<_, String>(3)?,
            "size":        row.get::<_, i64>(4)?,
            "mime_type":   row.get::<_, String>(5)?,
            "method":      row.get::<_, String>(6)?,
            "acquired_at": row.get::<_, String>(7)?,
        }))
    })?;
    let mut results = Vec::new();
    for r in rows {
        results.push(r?);
    }
    Ok(results)
}

pub fn list_observations_for_artifact_json(
    conn: &Connection,
    artifact_id: EntityId,
) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, source_tool, raw_event_type, source_timestamp, data_json \
         FROM observations WHERE artifact_id = ?1 ORDER BY source_timestamp ASC LIMIT 500",
    )?;
    let rows = stmt.query_map(params![artifact_id.to_string()], |row| {
        let data_str: String = row.get(4)?;
        let data: serde_json::Value =
            serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null);
        Ok(serde_json::json!({
            "id":          row.get::<_, String>(0)?,
            "tool":        row.get::<_, String>(1)?,
            "event_type":  row.get::<_, String>(2)?,
            "timestamp":   row.get::<_, String>(3)?,
            "data":        data,
        }))
    })?;
    let mut results = Vec::new();
    for r in rows {
        results.push(r?);
    }
    Ok(results)
}

pub fn list_custody_chain_json(
    conn: &Connection,
    artifact_hash: &str,
) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, actor_id, event_type, details_json, previous_state_hash, timestamp \
         FROM custody_events WHERE artifact_hash = ?1 ORDER BY timestamp ASC",
    )?;
    let rows = stmt.query_map(params![artifact_hash], |row| {
        let details_str: String = row.get(3)?;
        let details: serde_json::Value =
            serde_json::from_str(&details_str).unwrap_or(serde_json::Value::Null);
        Ok(serde_json::json!({
            "id":         row.get::<_, String>(0)?,
            "actor":      row.get::<_, String>(1)?,
            "event_type": row.get::<_, String>(2)?,
            "details":    details,
            "prev_hash":  row.get::<_, String>(4)?,
            "timestamp":  row.get::<_, String>(5)?,
        }))
    })?;
    let mut results = Vec::new();
    for r in rows {
        results.push(r?);
    }
    Ok(results)
}

fn map_artifact_row(row: &rusqlite::Row) -> Result<Artifact, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let case_id_str: String = row.get(1)?;
    let hash_blake3: String = row.get(2)?;
    let hash_sha256: String = row.get(3)?;
    let original_name: String = row.get(4)?;
    let file_size: i64 = row.get(5)?;
    let mime_type: String = row.get(6)?;
    let acquisition_method: String = row.get(7)?;
    let acquired_at_str: String = row.get(8)?;
    let ingested_at_str: String = row.get(9)?;

    let acquired_at = DateTime::parse_from_rfc3339(&acquired_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let ingested_at = DateTime::parse_from_rfc3339(&ingested_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(Artifact {
        id: EntityId::parse(&id_str).unwrap_or_default(),
        case_id: EntityId::parse(&case_id_str).unwrap_or_default(),
        hash_blake3,
        hash_sha256,
        original_name,
        file_size: file_size as u64,
        mime_type,
        acquisition_method,
        acquired_at,
        ingested_at,
    })
}
