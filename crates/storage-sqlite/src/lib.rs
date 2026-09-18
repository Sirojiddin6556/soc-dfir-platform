#![forbid(unsafe_code)]

pub mod audit;
pub mod collaboration;
pub mod schema;

use core_domain::artifact::{Artifact, CustodyEvent};
use core_domain::audit::AuditEvent;
use core_domain::case::Case;
use core_domain::epistemic::{AssertionType, Confidence, PainLevel, Severity, VerificationState};
use core_domain::fact::{EntityType, Fact};
use core_domain::id::EntityId;
use core_domain::observation::Observation;
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

    #[error("Entity not found: {0}")]
    NotFound(String),
}

#[derive(Clone)]
pub struct SqliteStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SqliteStorageError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.migrate()?;
        storage
            .init_collaboration_data(core_domain::collaboration::OperationMode::Live)
            .ok();
        Ok(storage)
    }

    pub fn open_in_memory() -> Result<Self, SqliteStorageError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.migrate()?;
        storage
            .init_collaboration_data(core_domain::collaboration::OperationMode::Live)
            .ok();
        Ok(storage)
    }

    pub fn migrate(&self) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(schema::MIGRATION_001_SQL)?;
        conn.execute_batch(schema::MIGRATION_002_SQL)?;
        Ok(())
    }

    pub fn insert_case(
        &self,
        id: EntityId,
        title: &str,
        description: Option<&str>,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO cases (id, title, description, status, created_at, updated_at) VALUES (?1, ?2, ?3, 'Active', ?4, ?4)",
            params![id.to_string(), title, description, now],
        )?;
        Ok(())
    }

    pub fn list_cases(&self) -> Result<Vec<Case>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, title, description, status, created_at, updated_at FROM cases ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let title: String = row.get(1)?;
            let description: Option<String> = row.get(2)?;
            let status: String = row.get(3)?;
            let created_at_str: String = row.get(4)?;
            let updated_at_str: String = row.get(5)?;

            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());

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

    pub fn get_case(&self, id: EntityId) -> Result<Option<Case>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, title, description, status, created_at, updated_at FROM cases WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let title: String = row.get(1)?;
            let description: Option<String> = row.get(2)?;
            let status: String = row.get(3)?;
            let created_at_str: String = row.get(4)?;
            let updated_at_str: String = row.get(5)?;

            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());

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

    pub fn insert_artifact(&self, art: &Artifact) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
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

    pub fn insert_observation(&self, obs: &Observation) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO observations (
                id, case_id, artifact_id, tool_run_id, source_tool,
                raw_event_type, source_timestamp, ingest_timestamp, data_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            params![
                obs.id.to_string(),
                obs.case_id.to_string(),
                obs.artifact_id.map(|id| id.to_string()),
                obs.tool_run_id.map(|id| id.to_string()),
                obs.source_tool,
                obs.raw_event_type,
                obs.source_timestamp.to_rfc3339(),
                obs.ingest_timestamp.to_rfc3339(),
                serde_json::to_string(&obs.data)?,
            ],
        )?;
        Ok(())
    }

    pub fn insert_fact(&self, fact: &Fact) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let ev_ids_json = serde_json::to_string(
            &fact
                .evidence_ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
        )?;
        conn.execute(
            r#"INSERT INTO facts (
                id, case_id, evidence_ids, assertion_type, verification_state,
                entity_type, entity_key, fact_type, confidence, severity,
                risk_score, evidence_strength, pain_level, data_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
            params![
                fact.id.to_string(),
                fact.case_id.to_string(),
                ev_ids_json,
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

    pub fn get_facts_for_case(&self, case_id: EntityId) -> Result<Vec<Fact>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, case_id, evidence_ids, assertion_type, verification_state,
                      entity_type, entity_key, fact_type, confidence, severity,
                      risk_score, evidence_strength, pain_level, data_json, created_at
               FROM facts WHERE case_id = ?1 ORDER BY created_at ASC"#,
        )?;

        let rows = stmt.query_map(params![case_id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let case_id_str: String = row.get(1)?;
            let ev_ids_str: String = row.get(2)?;
            let assert_type_str: String = row.get(3)?;
            let verif_state_str: String = row.get(4)?;
            let ent_type_str: String = row.get(5)?;
            let ent_key: String = row.get(6)?;
            let fact_type: String = row.get(7)?;
            let conf_val: f32 = row.get(8)?;
            let sev_str: String = row.get(9)?;
            let risk_score: f32 = row.get(10)?;
            let ev_strength: f32 = row.get(11)?;
            let pain_str: Option<String> = row.get(12)?;
            let data_str: String = row.get(13)?;
            let created_at_str: String = row.get(14)?;

            let assertion_type = match assert_type_str.as_str() {
                "Inference" => AssertionType::Inference,
                "Hypothesis" => AssertionType::Hypothesis,
                _ => AssertionType::Fact,
            };

            let verification_state = match verif_state_str.as_str() {
                "Candidate" => VerificationState::Candidate,
                "Corroborated" => VerificationState::Corroborated,
                "Disproved" => VerificationState::Disproved,
                _ => VerificationState::Confirmed,
            };

            let entity_type = match ent_type_str.as_str() {
                "Process" => EntityType::Process,
                "NetworkSocket" => EntityType::NetworkSocket,
                "Identity" => EntityType::Identity,
                "File" => EntityType::File,
                "MemoryRegion" => EntityType::MemoryRegion,
                "Vulnerability" => EntityType::Vulnerability,
                "ThreatActor" => EntityType::ThreatActor,
                _ => EntityType::Host,
            };

            let severity = match sev_str.as_str() {
                "Low" => Severity::Low,
                "Medium" => Severity::Medium,
                "High" => Severity::High,
                "Critical" => Severity::Critical,
                _ => Severity::Info,
            };

            let pain_level = match pain_str.as_deref() {
                Some("HashValues") => Some(PainLevel::HashValues),
                Some("IpAddresses") => Some(PainLevel::IpAddresses),
                Some("DomainNames") => Some(PainLevel::DomainNames),
                Some("NetworkArtifacts") => Some(PainLevel::NetworkArtifacts),
                Some("Tools") => Some(PainLevel::Tools),
                Some("TTPs") => Some(PainLevel::TTPs),
                _ => None,
            };

            let data = serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null);
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());

            let evidence_ids: Vec<EntityId> = serde_json::from_str::<Vec<String>>(&ev_ids_str)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| EntityId::parse(&s).ok())
                .collect();

            Ok(Fact {
                id: EntityId::parse(&id_str).unwrap_or_default(),
                case_id: EntityId::parse(&case_id_str).unwrap_or_default(),
                evidence_ids,
                assertion_type,
                verification_state,
                entity_type,
                entity_key: ent_key,
                fact_type,
                confidence: Confidence::new(conf_val),
                severity,
                risk_score,
                evidence_strength: ev_strength,
                pain_level,
                data,
                created_at,
            })
        })?;

        let mut facts = Vec::new();
        for fact_res in rows {
            facts.push(fact_res?);
        }
        Ok(facts)
    }

    pub fn append_custody_event(&self, event: &CustodyEvent) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO custody_events (
                id, case_id, actor_id, event_type, artifact_hash,
                details_json, previous_state_hash, timestamp
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                event.id.to_string(),
                event.case_id.to_string(),
                event.actor_id,
                format!("{:?}", event.event_type),
                event.artifact_hash,
                event.details_json,
                event.previous_state_hash,
                event.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn insert_audit_event(&self, event: &AuditEvent) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        audit::insert_audit_event(&conn, event)
    }

    pub fn list_audit_events(
        &self,
        case_id: Option<EntityId>,
    ) -> Result<Vec<AuditEvent>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        audit::list_audit_events(&conn, case_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_full_crud_and_query() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let case_id = EntityId::new_v7();
        storage
            .insert_case(case_id, "CTF Scenario 01", Some("Initial compromise"))
            .unwrap();

        let fact = Fact {
            id: EntityId::new_v7(),
            case_id,
            evidence_ids: vec![EntityId::new_v7(), EntityId::new_v7()],
            assertion_type: AssertionType::Fact,
            verification_state: VerificationState::Confirmed,
            entity_type: EntityType::Host,
            entity_key: "192.168.1.50".to_string(),
            fact_type: "DiscoveredHost".to_string(),
            confidence: Confidence::new(1.0),
            severity: Severity::Info,
            risk_score: 10.0,
            evidence_strength: 1.0,
            pain_level: Some(PainLevel::IpAddresses),
            data: serde_json::json!({"hostname": "WIN-SRV01"}),
            created_at: chrono::Utc::now(),
        };

        storage.insert_fact(&fact).unwrap();

        let facts = storage.get_facts_for_case(case_id).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].entity_key, "192.168.1.50");
        assert_eq!(facts[0].assertion_type, AssertionType::Fact);
    }

    #[test]
    fn test_all_19_schema_tables_exist() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let conn = storage.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        let expected = [
            "cases",
            "artifacts",
            "tool_runs",
            "observations",
            "facts",
            "evidence",
            "evidence_members",
            "attack_nodes",
            "attack_edges",
            "taxonomy_versions",
            "taxonomy_mappings",
            "diagram_snapshots",
            "custody_events",
            "workflow_tasks",
            "findings",
            "hypotheses",
            "entities",
            "software",
            "vulnerabilities",
            "software_vulnerabilities",
            "audit_events",
        ];
        for exp in expected {
            assert!(
                tables.iter().any(|t| t == exp),
                "Missing expected table in schema: {}",
                exp
            );
        }
    }

    #[test]
    fn test_audit_event_logging() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let case_id = EntityId::new_v7();
        storage.insert_case(case_id, "Audit Case", None).unwrap();

        let event = AuditEvent::new(
            Some(case_id),
            "analyst_alice",
            "PrivilegedPortScan",
            "Network",
            Some("192.168.1.1".to_string()),
            "Success",
            serde_json::json!({"ports": [80, 443]}),
        );
        storage.insert_audit_event(&event).unwrap();

        let events = storage.list_audit_events(Some(case_id)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor_id, "analyst_alice");
        assert_eq!(events[0].action, "PrivilegedPortScan");
    }
}
