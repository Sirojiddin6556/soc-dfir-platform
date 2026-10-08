#![forbid(unsafe_code)]

pub mod audit;
pub mod cases;
pub mod collaboration;
pub mod ctf_artifacts_jobs;
pub mod ctf_flags;
pub mod ctf_workspace;
pub mod evidence;
pub mod membership;
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

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Validation(String),
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
        conn.pragma_update(None, "cache_size", -64000)?;
        conn.pragma_update(None, "mmap_size", 268435456)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "busy_timeout", 10000)?;
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
        conn.execute_batch(schema::MIGRATION_003_SQL)?;
        conn.execute_batch(schema::MIGRATION_004_SQL)?;
        conn.execute_batch(schema::MIGRATION_005_SQL)?;
        conn.execute_batch(evidence::MIGRATION_006_SQL)?;
        conn.execute_batch(schema::MIGRATION_007_SQL)?;
        Self::apply_ctf_v002(&conn)?;
        Self::apply_ctf_v003(&conn)?;
        Ok(())
    }

    fn apply_ctf_v003(conn: &Connection) -> Result<(), SqliteStorageError> {
        conn.execute_batch(include_str!("../migrations/V003_ctf_flag_answers.sql"))?;
        Ok(())
    }

    fn apply_ctf_v002(conn: &Connection) -> Result<(), SqliteStorageError> {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='competitions'",
                [],
                |row| row.get(0),
            )
            .map(|count: i64| count > 0)
            .unwrap_or(false);

        if !exists {
            conn.execute_batch(schema::MIGRATION_V002_CTF_CORE_SQL)?;
        }
        Ok(())
    }

    pub fn insert_case(
        &self,
        id: EntityId,
        title: &str,
        description: Option<&str>,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::insert_case(&conn, id, title, description).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_cases(&self) -> Result<Vec<Case>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::list_cases(&conn).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn get_case(&self, id: EntityId) -> Result<Option<Case>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::get_case(&conn, id).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn insert_artifact(&self, art: &Artifact) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::insert_artifact(&conn, art).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn insert_observation(&self, obs: &Observation) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut data = obs.data.clone();
        if let Some(object) = data.as_object_mut() {
            if let Some(quality) = &obs.network_quality {
                object.insert(
                    "_network_quality".to_string(),
                    serde_json::to_value(quality)?,
                );
            }
            if let Some(provenance) = &obs.network_provenance {
                object.insert(
                    "_network_provenance".to_string(),
                    serde_json::to_value(provenance)?,
                );
            }
        }
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
                obs.source_timestamp.as_ref().map(|t| t.to_rfc3339()),
                obs.ingest_timestamp.to_rfc3339(),
                serde_json::to_string(&data)?,
            ],
        )?;
        Ok(())
    }

    pub fn list_observations_for_case(
        &self,
        case_id: EntityId,
    ) -> Result<Vec<Observation>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, artifact_id, tool_run_id, source_tool, raw_event_type, \
             source_timestamp, ingest_timestamp, data_json \
             FROM observations WHERE case_id = ?1 \
             ORDER BY source_timestamp IS NULL, source_timestamp, id",
        )?;
        let rows = stmt.query_map(params![case_id.to_string()], |row| {
            let id: String = row.get(0)?;
            let artifact_id: Option<String> = row.get(1)?;
            let tool_run_id: Option<String> = row.get(2)?;
            let source_timestamp: Option<String> = row.get(5)?;
            let ingest_timestamp: String = row.get(6)?;
            let mut data: serde_json::Value = serde_json::from_str(&row.get::<_, String>(7)?)
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            let network_quality = data
                .get("_network_quality")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            let network_provenance = data
                .get("_network_provenance")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            if let Some(object) = data.as_object_mut() {
                object.remove("_network_quality");
                object.remove("_network_provenance");
            }
            Ok(Observation {
                id: EntityId::parse(&id).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                case_id,
                artifact_id: artifact_id
                    .as_deref()
                    .map(EntityId::parse)
                    .transpose()
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                tool_run_id: tool_run_id
                    .as_deref()
                    .map(EntityId::parse)
                    .transpose()
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                source_tool: row.get(3)?,
                raw_event_type: row.get(4)?,
                source_timestamp: source_timestamp
                    .as_deref()
                    .map(chrono::DateTime::parse_from_rfc3339)
                    .transpose()
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?
                    .map(|value| value.with_timezone(&chrono::Utc)),
                ingest_timestamp: chrono::DateTime::parse_from_rfc3339(&ingest_timestamp)
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?
                    .with_timezone(&chrono::Utc),
                data,
                network_quality,
                network_provenance,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SqliteStorageError::Rusqlite)
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

    /// Stores a fact unless the case already holds the same finding (same
    /// fact type about the same entity). Live correlation re-runs every time
    /// the workspace loads; without this each run added a duplicate copy.
    /// Returns the id and creation time of the stored fact, which for a
    /// repeat finding are those of the first sighting.
    pub fn insert_fact_dedup(
        &self,
        fact: &Fact,
    ) -> Result<(EntityId, chrono::DateTime<chrono::Utc>), SqliteStorageError> {
        {
            let conn = self.conn.lock().unwrap();
            let existing = conn.query_row(
                "SELECT id, created_at FROM facts
                 WHERE case_id = ?1 AND entity_key = ?2 AND fact_type = ?3
                 ORDER BY created_at LIMIT 1",
                params![fact.case_id.to_string(), fact.entity_key, fact.fact_type],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            );
            match existing {
                Ok((id, created)) => {
                    let id = EntityId::parse(&id).unwrap_or(fact.id);
                    let created = chrono::DateTime::parse_from_rfc3339(&created)
                        .map(|d| d.with_timezone(&chrono::Utc))
                        .unwrap_or(fact.created_at);
                    return Ok((id, created));
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.insert_fact(fact)?;
        Ok((fact.id, fact.created_at))
    }

    pub fn insert_timeline_event(
        &self,
        event: &timeline_engine::TimelineEvent,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO timeline_events (
                event_id, case_id, source_timestamp, ingest_timestamp,
                normalized_timestamp, source_kind, artifact_id, observation_id,
                quality, provenance_json, data_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.event_id,
                event.case_id.to_string(),
                event.source_timestamp.map(|value| value.to_rfc3339()),
                event.ingest_timestamp.to_rfc3339(),
                event.normalized_timestamp.map(|value| value.to_rfc3339()),
                serde_json::to_string(&event.source_kind)?,
                event.artifact_id.map(|value| value.to_string()),
                event.observation_id.to_string(),
                serde_json::to_string(&event.quality)?,
                serde_json::to_string(&event.provenance)?,
                serde_json::to_string(event)?,
            ],
        )?;
        Ok(())
    }

    pub fn list_timeline_events_for_case(
        &self,
        case_id: EntityId,
    ) -> Result<Vec<timeline_engine::TimelineEvent>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT data_json FROM timeline_events
             WHERE case_id = ?1
             ORDER BY normalized_timestamp IS NULL, normalized_timestamp, event_id",
        )?;
        let rows = statement.query_map(params![case_id.to_string()], |row| {
            let data: String = row.get(0)?;
            serde_json::from_str(&data).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn insert_correlation(
        &self,
        result: &correlation_engine::CorrelationResult,
        case_id: EntityId,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO correlations (
                correlation_id, case_id, rule_id, rule_version,
                supporting_observations_json, assertion_type,
                verification_state, confidence, provenance_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                result.correlation_id,
                case_id.to_string(),
                result.rule_id,
                result.rule_version,
                serde_json::to_string(&result.supporting_observations)?,
                serde_json::to_string(&result.assertion_type)?,
                serde_json::to_string(&result.verification_state)?,
                result.confidence,
                serde_json::to_string(&result.provenance)?,
            ],
        )?;
        Ok(())
    }

    pub fn clear_correlations_for_case(&self, case_id: EntityId) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM correlations WHERE case_id = ?1",
            params![case_id.to_string()],
        )?;
        Ok(())
    }

    pub fn list_correlations_for_case(
        &self,
        case_id: EntityId,
    ) -> Result<Vec<correlation_engine::CorrelationResult>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT correlation_id, rule_id, rule_version,
                    supporting_observations_json, assertion_type,
                    verification_state, confidence, provenance_json
             FROM correlations WHERE case_id = ?1 ORDER BY correlation_id",
        )?;
        let rows = statement.query_map(params![case_id.to_string()], |row| {
            let correlation_id: String = row.get(0)?;
            let rule_id: String = row.get(1)?;
            let rule_version: String = row.get(2)?;
            let supporting: String = row.get(3)?;
            let assertion: String = row.get(4)?;
            let verification: String = row.get(5)?;
            let confidence: u8 = row.get(6)?;
            let provenance: String = row.get(7)?;
            Ok(correlation_engine::CorrelationResult {
                correlation_id,
                rule_id,
                rule_version,
                supporting_observations: serde_json::from_str(&supporting).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                assertion_type: serde_json::from_str(&assertion).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                verification_state: serde_json::from_str(&verification).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                confidence,
                provenance: serde_json::from_str(&provenance).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_cve_entry(
        &self,
        cve_id: &str,
        cpe_vendor: &str,
        cpe_product: &str,
        cvss_v3: f64,
        epss_score: f64,
        cisa_kev: bool,
        severity: &str,
        cwe_ids_json: &str,
        description: &str,
        source: &str,
        published_at: Option<&str>,
        updated_at: &str,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cve_entries (cve_id, cpe_vendor, cpe_product, cvss_v3, epss_score, \
             cisa_kev, severity, cwe_ids, description, source, published_at, updated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) \
             ON CONFLICT(cve_id) DO UPDATE SET \
             cpe_vendor=excluded.cpe_vendor, cpe_product=excluded.cpe_product, \
             cvss_v3=excluded.cvss_v3, epss_score=excluded.epss_score, \
             cisa_kev=excluded.cisa_kev, severity=excluded.severity, \
             cwe_ids=excluded.cwe_ids, description=excluded.description, \
             source=excluded.source, published_at=excluded.published_at, \
             updated_at=excluded.updated_at",
            params![
                cve_id,
                cpe_vendor,
                cpe_product,
                cvss_v3,
                epss_score,
                cisa_kev as i64,
                severity,
                cwe_ids_json,
                description,
                source,
                published_at,
                updated_at
            ],
        )?;
        Ok(())
    }

    pub fn query_cves_for_product(
        &self,
        vendor: &str,
        product: &str,
    ) -> Result<Vec<serde_json::Value>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cve_id, cvss_v3, epss_score, cisa_kev, severity, description \
             FROM cve_entries WHERE cpe_vendor = ?1 AND cpe_product LIKE ?2",
        )?;
        let rows = stmt.query_map(params![vendor, format!("%{}%", product)], |row| {
            Ok(serde_json::json!({
                "cve_id":      row.get::<_, String>(0)?,
                "cvss_v3":     row.get::<_, f64>(1)?,
                "epss_score":  row.get::<_, f64>(2)?,
                "cisa_kev":    row.get::<_, i64>(3)? != 0,
                "severity":    row.get::<_, String>(4)?,
                "description": row.get::<_, String>(5)?,
            }))
        })?;
        let mut results = Vec::new();
        for r in rows {
            results.push(r.map_err(SqliteStorageError::Rusqlite)?);
        }
        Ok(results)
    }

    pub fn cve_entry_count(&self) -> Result<i64, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM cve_entries", [], |r| r.get(0))?;
        Ok(count)
    }

    pub fn list_artifacts_for_case(
        &self,
        case_id: EntityId,
    ) -> Result<Vec<serde_json::Value>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::list_artifacts_for_case_json(&conn, case_id).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_observations_for_artifact(
        &self,
        artifact_id: EntityId,
    ) -> Result<Vec<serde_json::Value>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::list_observations_for_artifact_json(&conn, artifact_id)
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_custody_chain(
        &self,
        artifact_hash: &str,
    ) -> Result<Vec<serde_json::Value>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::list_custody_chain_json(&conn, artifact_hash).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn delete_artifact(
        &self,
        artifact_id: EntityId,
        case_id: EntityId,
    ) -> Result<bool, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::delete_artifact(&conn, artifact_id, case_id).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn get_artifact(&self, id: EntityId) -> Result<Option<Artifact>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::get_artifact(&conn, id).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn get_artifact_by_blake3(
        &self,
        blake3_hex: &str,
    ) -> Result<Option<Artifact>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        cases::get_artifact_by_blake3(&conn, blake3_hex).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn conn(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    pub fn create_ingest_session(
        &self,
        s: &evidence::IngestSessionRecord,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        evidence::insert_ingest_session(&conn, s).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn update_ingest_session(
        &self,
        s: &evidence::IngestSessionRecord,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        evidence::update_ingest_session(&conn, s).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn get_ingest_session(
        &self,
        session_id: EntityId,
    ) -> Result<Option<evidence::IngestSessionRecord>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        evidence::get_ingest_session(&conn, session_id).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn record_custody_event(
        &self,
        e: &evidence::ForensicCustodyEvent,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        evidence::insert_custody_event(&conn, e).map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_custody_events_for_session(
        &self,
        session_id: EntityId,
    ) -> Result<Vec<evidence::ForensicCustodyEvent>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        evidence::list_custody_events_for_session(&conn, session_id)
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_custody_events_for_artifact(
        &self,
        artifact_id: EntityId,
    ) -> Result<Vec<evidence::ForensicCustodyEvent>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        evidence::list_custody_events_for_artifact(&conn, artifact_id)
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn verify_custody_chain(
        &self,
        artifact_id: EntityId,
    ) -> Result<bool, evidence::CustodyError> {
        let events = self
            .list_custody_events_for_artifact(artifact_id)
            .map_err(|e| match e {
                SqliteStorageError::Rusqlite(re) => evidence::CustodyError::Rusqlite(re),
                _ => evidence::CustodyError::EmptyChain,
            })?;
        evidence::verify_custody_event_sequence(&events)
    }

    pub fn verify_session_custody_chain(
        &self,
        session_id: EntityId,
    ) -> Result<bool, evidence::CustodyError> {
        let events = self
            .list_custody_events_for_session(session_id)
            .map_err(|e| match e {
                SqliteStorageError::Rusqlite(re) => evidence::CustodyError::Rusqlite(re),
                _ => evidence::CustodyError::EmptyChain,
            })?;
        evidence::verify_custody_event_sequence(&events)
    }
}
