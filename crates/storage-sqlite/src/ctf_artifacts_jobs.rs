use crate::SqliteStorage;
use core_domain::ctf::*;
use core_domain::error::DomainError;
use rusqlite::params;
use std::str::FromStr;

impl SqliteStorage {
    pub fn register_artifact(
        &self,
        artifact_id: &str,
        original_name: &str,
        blake3: &str,
        sha256: &str,
        size: u64,
        mime_type: Option<&str>,
    ) -> Result<(), DomainError> {
        let conn = self.conn.lock().unwrap();
        let mime = mime_type.unwrap_or("application/octet-stream");
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            r#"INSERT INTO artifacts (
                id, blake3, sha256, size, detected_type, storage_state, original_name, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 'stored', ?6, ?7)
            ON CONFLICT(id) DO UPDATE SET
                blake3 = COALESCE(excluded.blake3, artifacts.blake3),
                sha256 = COALESCE(excluded.sha256, artifacts.sha256),
                size = COALESCE(excluded.size, artifacts.size)"#,
            params![
                artifact_id,
                blake3,
                sha256,
                size as i64,
                mime,
                original_name,
                now
            ],
        )
        .map_err(|e| DomainError::Storage(format!("Failed to register artifact: {}", e)))?;
        Ok(())
    }

    pub fn add_challenge_artifact(
        &self,
        challenge_id: &str,
        artifact_id: &str,
        role: ArtifactRole,
        alias: Option<&str>,
    ) -> Result<String, DomainError> {
        let conn = self.conn.lock().unwrap();
        let id = format!("ca-{}", uuid::Uuid::now_v7());
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            r#"INSERT INTO challenge_artifacts (id, challenge_id, artifact_id, role, alias, added_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(challenge_id, artifact_id, role) DO UPDATE SET alias = excluded.alias"#,
            params![id, challenge_id, artifact_id, role.to_string(), alias, now],
        ).map_err(|e| DomainError::Storage(format!("Failed to add challenge artifact: {}", e)))?;

        Ok(id)
    }

    pub fn list_challenge_artifacts(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<ChallengeArtifact>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                r#"SELECT id, challenge_id, artifact_id, role, alias, added_at
               FROM challenge_artifacts WHERE challenge_id = ?1 ORDER BY added_at ASC"#,
            )
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![challenge_id], |row| {
                let role_str: String = row.get(3)?;
                let added_at_str: String = row.get(5)?;
                Ok(ChallengeArtifact {
                    id: row.get(0)?,
                    challenge_id: row.get(1)?,
                    artifact_id: row.get(2)?,
                    role: ArtifactRole::from_str(&role_str).unwrap_or_default(),
                    alias: row.get(4)?,
                    added_at: chrono::DateTime::parse_from_rfc3339(&added_at_str)
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc),
                })
            })
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(|e| DomainError::Storage(e.to_string()))?);
        }
        Ok(list)
    }

    pub fn insert_job(&self, job: &Job) -> Result<(), DomainError> {
        let conn = self.conn.lock().unwrap();
        let argv_json = serde_json::to_string(&job.argv)?;
        let input_refs_json = serde_json::to_string(&job.input_refs)?;
        let started_at_str = job.started_at.map(|t| t.to_rfc3339());
        let completed_at_str = job.completed_at.map(|t| t.to_rfc3339());
        let created_at_str = job.created_at.to_rfc3339();

        conn.execute(
            r#"INSERT INTO jobs (
                id, challenge_id, tool_id, adapter, runtime, state, argv_json, input_refs_json,
                exit_code, timeout_ms, timeout_triggered, started_at, completed_at, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"#,
            params![
                job.id,
                job.challenge_id,
                job.tool_id,
                job.adapter,
                job.runtime.to_string(),
                job.state.to_string(),
                argv_json,
                input_refs_json,
                job.exit_code,
                job.timeout_ms as i64,
                if job.timeout_triggered { 1 } else { 0 },
                started_at_str,
                completed_at_str,
                created_at_str
            ],
        )
        .map_err(|e| DomainError::Storage(format!("Failed to insert job: {}", e)))?;

        Ok(())
    }

    pub fn update_job_state(
        &self,
        job_id: &str,
        state: JobStatus,
        exit_code: Option<i32>,
    ) -> Result<(), DomainError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let is_timeout = state == JobStatus::TimedOut;

        let query = if state.is_terminal() {
            "UPDATE jobs SET state = ?1, exit_code = ?2, timeout_triggered = ?3, completed_at = ?4 WHERE id = ?5"
        } else {
            "UPDATE jobs SET state = ?1, exit_code = ?2, timeout_triggered = ?3, started_at = COALESCE(started_at, ?4) WHERE id = ?5"
        };

        conn.execute(
            query,
            params![
                state.to_string(),
                exit_code,
                if is_timeout { 1 } else { 0 },
                now,
                job_id
            ],
        )
        .map_err(|e| DomainError::Storage(format!("Failed to update job state: {}", e)))?;

        Ok(())
    }

    pub fn insert_transform_step(&self, step: &TransformStep) -> Result<(), DomainError> {
        let conn = self.conn.lock().unwrap();
        let created_at_str = step.created_at.to_rfc3339();

        conn.execute(
            r#"INSERT INTO transform_steps (
                id, challenge_id, recipe_id, step_order, operation, parameters_json,
                input_artifact_id, output_artifact_id, input_hash, output_hash, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
            params![
                step.id,
                step.challenge_id,
                step.recipe_id,
                step.step_order,
                step.operation,
                step.parameters_json,
                step.input_artifact_id,
                step.output_artifact_id,
                step.input_hash,
                step.output_hash,
                created_at_str
            ],
        )
        .map_err(|e| DomainError::Storage(format!("Failed to insert transform step: {}", e)))?;

        Ok(())
    }

    pub fn list_transform_steps(
        &self,
        challenge_id: &str,
        recipe_id: Option<&str>,
    ) -> Result<Vec<TransformStep>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let (query, has_recipe) = match recipe_id {
            Some(_) => (
                r#"SELECT id, challenge_id, recipe_id, step_order, operation, parameters_json,
                          input_artifact_id, output_artifact_id, input_hash, output_hash, created_at
                   FROM transform_steps WHERE challenge_id = ?1 AND recipe_id = ?2 ORDER BY step_order ASC"#,
                true,
            ),
            None => (
                r#"SELECT id, challenge_id, recipe_id, step_order, operation, parameters_json,
                          input_artifact_id, output_artifact_id, input_hash, output_hash, created_at
                   FROM transform_steps WHERE challenge_id = ?1 ORDER BY step_order ASC"#,
                false,
            ),
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| DomainError::Storage(e.to_string()))?;
        let rows = if has_recipe {
            stmt.query_map(params![challenge_id, recipe_id.unwrap()], map_step)
        } else {
            stmt.query_map(params![challenge_id], map_step)
        }
        .map_err(|e| DomainError::Storage(e.to_string()))?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(|e| DomainError::Storage(e.to_string()))?);
        }
        Ok(list)
    }
}

fn map_step(row: &rusqlite::Row) -> Result<TransformStep, rusqlite::Error> {
    let created_at_str: String = row.get(10)?;
    Ok(TransformStep {
        id: row.get(0)?,
        challenge_id: row.get(1)?,
        recipe_id: row.get(2)?,
        step_order: row.get(3)?,
        operation: row.get(4)?,
        parameters_json: row.get(5)?,
        input_artifact_id: row.get(6)?,
        output_artifact_id: row.get(7)?,
        input_hash: row.get(8)?,
        output_hash: row.get(9)?,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .unwrap_or_else(|_| chrono::Utc::now().into())
            .with_timezone(&chrono::Utc),
    })
}
