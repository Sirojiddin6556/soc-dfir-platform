use crate::SqliteStorageError;
use core_domain::audit::AuditEvent;
use core_domain::id::EntityId;
use rusqlite::{params, Connection};

pub fn insert_audit_event(conn: &Connection, event: &AuditEvent) -> Result<(), SqliteStorageError> {
    conn.execute(
        r#"INSERT INTO audit_events (
            id, case_id, actor_id, action, resource_type, resource_id,
            outcome, details_json, timestamp
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
        params![
            event.id.to_string(),
            event.case_id.map(|id| id.to_string()),
            event.actor_id,
            event.action,
            event.resource_type,
            event.resource_id,
            event.outcome,
            serde_json::to_string(&event.details_json)?,
            event.timestamp.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn list_audit_events(
    conn: &Connection,
    case_id: Option<EntityId>,
) -> Result<Vec<AuditEvent>, SqliteStorageError> {
    let mut events = Vec::new();

    if let Some(cid) = case_id {
        let mut stmt = conn.prepare(
            "SELECT id, case_id, actor_id, action, resource_type, resource_id, outcome, details_json, timestamp
             FROM audit_events WHERE case_id = ?1 ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map([cid.to_string()], map_row)?;
        for r in rows {
            events.push(r?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, case_id, actor_id, action, resource_type, resource_id, outcome, details_json, timestamp
             FROM audit_events ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map([], map_row)?;
        for r in rows {
            events.push(r?);
        }
    }

    Ok(events)
}

fn map_row(row: &rusqlite::Row) -> rusqlite::Result<AuditEvent> {
    let id_str: String = row.get(0)?;
    let case_id_str: Option<String> = row.get(1)?;
    let actor_id: String = row.get(2)?;
    let action: String = row.get(3)?;
    let resource_type: String = row.get(4)?;
    let resource_id: Option<String> = row.get(5)?;
    let outcome: String = row.get(6)?;
    let details_json_str: String = row.get(7)?;
    let timestamp_str: String = row.get(8)?;

    let id = EntityId::parse(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let case_id = case_id_str.and_then(|s| EntityId::parse(&s).ok());
    let details_json = serde_json::from_str(&details_json_str).unwrap_or(serde_json::Value::Null);
    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    Ok(AuditEvent {
        id,
        case_id,
        actor_id,
        action,
        resource_type,
        resource_id,
        outcome,
        details_json,
        timestamp,
    })
}
