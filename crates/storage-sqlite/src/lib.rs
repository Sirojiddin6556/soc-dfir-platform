#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use core_domain::fact::Fact;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SqliteStorageError {
    #[error("Database error: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct SqliteStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SqliteStorageError> {
        let conn = Connection::open(path)?;
        
        // Enforce WAL mode and foreign key constraints
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.migrate()?;
        Ok(storage)
    }

    pub fn open_in_memory() -> Result<Self, SqliteStorageError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.migrate()?;
        Ok(storage)
    }

    pub fn migrate(&self) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'Active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                hash_blake3 TEXT NOT NULL,
                hash_sha256 TEXT NOT NULL,
                original_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                acquisition_method TEXT NOT NULL,
                acquired_at TEXT NOT NULL,
                ingested_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS facts (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                observation_id TEXT,
                assertion_type TEXT NOT NULL,
                verification_state TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                fact_type TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                severity TEXT NOT NULL DEFAULT 'Info',
                risk_score REAL NOT NULL DEFAULT 0.0,
                evidence_strength REAL NOT NULL DEFAULT 1.0,
                pain_level TEXT,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attack_nodes (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                node_type TEXT NOT NULL,
                label TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attack_edges (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                source_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
                target_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
                relation_type TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                supported_by_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS custody_events (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                actor_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                artifact_hash TEXT,
                details_json TEXT NOT NULL,
                previous_state_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            "#
        )?;
        Ok(())
    }

    pub fn insert_case(&self, id: EntityId, title: &str, description: Option<&str>) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO cases (id, title, description, status, created_at, updated_at) VALUES (?1, ?2, ?3, 'Active', ?4, ?4)",
            params![id.to_string(), title, description, now],
        )?;
        Ok(())
    }

    pub fn insert_fact(&self, fact: &Fact) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO facts (
                id, case_id, observation_id, assertion_type, verification_state,
                entity_type, entity_key, fact_type, confidence, severity,
                risk_score, evidence_strength, pain_level, data_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
            params![
                fact.id.to_string(),
                fact.case_id.to_string(),
                fact.observation_id.map(|id| id.to_string()),
                format!("{:?}", fact.assertion_type),
                format!("{:?}", fact.verification_state),
                format!("{:?}", fact.entity_type),
                fact.entity_key,
                fact.fact_type,
                fact.confidence.value(),
                format!("{:?}", fact.severity),
                fact.risk_score,
                fact.evidence_strength,
                fact.pain_level.map(|p| format!("{:?}", p)),
                serde_json::to_string(&fact.data)?,
                fact.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_case_creation_and_fact_insert() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let case_id = EntityId::new_v7();
        storage.insert_case(case_id, "CTF Scenario 01", Some("Initial compromise")).unwrap();

        let fact = Fact {
            id: EntityId::new_v7(),
            case_id,
            observation_id: None,
            assertion_type: core_domain::AssertionType::Fact,
            verification_state: core_domain::VerificationState::Confirmed,
            entity_type: core_domain::EntityType::Host,
            entity_key: "192.168.1.50".to_string(),
            fact_type: "DiscoveredHost".to_string(),
            confidence: core_domain::Confidence::new(1.0),
            severity: core_domain::Severity::Info,
            risk_score: 10.0,
            evidence_strength: 1.0,
            pain_level: Some(core_domain::PainLevel::IpAddresses),
            data: serde_json::json!({"hostname": "WIN-SRV01"}),
            created_at: chrono::Utc::now(),
        };

        storage.insert_fact(&fact).unwrap();
    }
}
