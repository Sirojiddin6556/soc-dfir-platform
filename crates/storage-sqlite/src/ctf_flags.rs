use crate::SqliteStorage;
use async_trait::async_trait;
use core_domain::ctf::traits::{FlagService, WriteupService};
use core_domain::ctf::writeup::{
    export_markdown_file, generate_markdown_writeup, update_markdown_section, WriteupDraftContext,
};
use core_domain::ctf::*;
use core_domain::error::DomainError;
use rusqlite::params;
use std::path::Path;
use std::str::FromStr;

#[async_trait]
impl FlagService for SqliteStorage {
    async fn register_candidate(
        &self,
        chal_id: &ChallengeId,
        value: String,
        source_ref: String,
    ) -> Result<CandidateId, DomainError> {
        let clean_val = value.trim();
        if clean_val.is_empty() {
            return Err(DomainError::Validation(
                "Flag candidate value cannot be empty".into(),
            ));
        }

        let conn = self.conn.lock().unwrap();

        // Check if already registered
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM flag_candidates WHERE challenge_id = ?1 AND value = ?2",
                params![chal_id, clean_val],
                |r| r.get(0),
            )
            .ok();

        if let Some(id) = existing {
            return Ok(id);
        }

        let cand_id = format!("flag-{}", uuid::Uuid::now_v7());
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            r#"INSERT INTO flag_candidates (
                id, challenge_id, value, pattern_match, verification_status, created_at
            ) VALUES (?1, ?2, ?3, ?4, 'candidate', ?5)"#,
            params![cand_id, chal_id, clean_val, source_ref, now],
        )
        .map_err(|e| DomainError::Storage(format!("Failed to register flag candidate: {}", e)))?;

        Ok(cand_id)
    }

    async fn accept_flag(&self, candidate_id: &CandidateId) -> Result<bool, DomainError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        let chal_id: String = conn
            .query_row(
                "SELECT challenge_id FROM flag_candidates WHERE id = ?1",
                params![candidate_id],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    DomainError::not_found("FlagCandidate", candidate_id)
                }
                other => DomainError::Storage(other.to_string()),
            })?;

        let rows_affected = conn.execute(
            "UPDATE flag_candidates SET verification_status = 'accepted', verified_at = ?1 WHERE id = ?2",
            params![now, candidate_id],
        ).map_err(|e| DomainError::Storage(format!("Failed to accept flag: {}", e)))?;

        if rows_affected > 0 {
            // Update challenge status to Solved
            let _ = conn.execute(
                "UPDATE challenges SET status = 'solved', updated_at = ?1 WHERE id = ?2 AND status != 'solved'",
                params![now, chal_id],
            );
        }

        Ok(rows_affected > 0)
    }

    async fn reject_flag(
        &self,
        candidate_id: &CandidateId,
        reason: Option<String>,
    ) -> Result<(), DomainError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        let rows_affected = conn.execute(
            "UPDATE flag_candidates SET verification_status = 'rejected', rejection_reason = ?1, verified_at = ?2 WHERE id = ?3",
            params![reason, now, candidate_id],
        ).map_err(|e| DomainError::Storage(format!("Failed to reject flag: {}", e)))?;

        if rows_affected == 0 {
            return Err(DomainError::not_found("FlagCandidate", candidate_id));
        }

        Ok(())
    }

    async fn list_flags(&self, chal_id: &ChallengeId) -> Result<Vec<FlagCandidate>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                r#"SELECT id, challenge_id, value, provenance_run_id, provenance_artifact_id,
                      provenance_step_id, pattern_match, verification_status, rejection_reason,
                      verified_at, submitted_to_platform, created_at
               FROM flag_candidates WHERE challenge_id = ?1 ORDER BY created_at ASC"#,
            )
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![chal_id], |row| {
                let status_str: String = row.get(7)?;
                let verified_at_str: Option<String> = row.get(9)?;
                let submitted_int: i32 = row.get(10)?;
                let created_at_str: String = row.get(11)?;

                Ok(FlagCandidate {
                    id: row.get(0)?,
                    challenge_id: row.get(1)?,
                    value: row.get(2)?,
                    provenance_run_id: row.get(3)?,
                    provenance_artifact_id: row.get(4)?,
                    provenance_step_id: row.get(5)?,
                    pattern_match: row.get(6)?,
                    verification_status: VerificationStatus::from_str(&status_str)
                        .unwrap_or_default(),
                    rejection_reason: row.get(8)?,
                    verified_at: verified_at_str.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    }),
                    submitted_to_platform: submitted_int != 0,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
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
}

#[async_trait]
impl WriteupService for SqliteStorage {
    async fn generate_draft(
        &self,
        chal_id: &ChallengeId,
        include_timeline: bool,
    ) -> Result<String, DomainError> {
        let details = self.get_challenge_internal(chal_id)?;
        let flags = self.list_flags(chal_id).await?;
        let accepted_flags = flags
            .into_iter()
            .filter(|f| f.verification_status == VerificationStatus::Accepted)
            .collect();
        let steps = self.list_transform_steps_internal(chal_id)?;
        let jobs = self.list_jobs_internal(chal_id)?;

        let ctx = WriteupDraftContext {
            challenge: details.challenge,
            accepted_flags,
            transform_steps: steps,
            jobs,
            artifacts: details.artifacts,
        };

        let markdown = generate_markdown_writeup(&ctx, include_timeline);

        // Upsert into writeups
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let writeup_id = format!("wu-{}", uuid::Uuid::now_v7());

        conn.execute(
            r#"INSERT INTO writeups (id, challenge_id, markdown_content, exported_version, created_at, updated_at)
               VALUES (?1, ?2, ?3, 1, ?4, ?4)
               ON CONFLICT(challenge_id) DO UPDATE SET
                   markdown_content = excluded.markdown_content,
                   updated_at = excluded.updated_at"#,
            params![writeup_id, chal_id, markdown, now],
        ).map_err(|e| DomainError::Storage(format!("Failed to save writeup: {}", e)))?;

        Ok(markdown)
    }

    async fn export_markdown(
        &self,
        chal_id: &ChallengeId,
        dest_path: &Path,
    ) -> Result<u64, DomainError> {
        let markdown = {
            let conn = self.conn.lock().unwrap();
            let saved_md: Option<String> = conn
                .query_row(
                    "SELECT markdown_content FROM writeups WHERE challenge_id = ?1",
                    params![chal_id],
                    |r| r.get(0),
                )
                .ok();
            saved_md
        };

        let content = match markdown {
            Some(m) => m,
            None => self.generate_draft(chal_id, true).await?,
        };

        export_markdown_file(&content, dest_path).await
    }

    async fn update_section(
        &self,
        chal_id: &ChallengeId,
        section: String,
        content: String,
    ) -> Result<(), DomainError> {
        let current_md = {
            let conn = self.conn.lock().unwrap();
            let content: String = conn
                .query_row(
                    "SELECT markdown_content FROM writeups WHERE challenge_id = ?1",
                    params![chal_id],
                    |r| r.get(0),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        DomainError::not_found("Writeup", chal_id)
                    }
                    other => DomainError::Storage(other.to_string()),
                })?;
            content
        };

        let updated_md = update_markdown_section(&current_md, &section, &content);
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE writeups SET markdown_content = ?1, updated_at = ?2 WHERE challenge_id = ?3",
            params![updated_md, now, chal_id],
        )
        .map_err(|e| DomainError::Storage(format!("Failed to update writeup section: {}", e)))?;

        Ok(())
    }
}

impl SqliteStorage {
    fn get_challenge_internal(&self, id: &ChallengeId) -> Result<ChallengeDetails, DomainError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                r#"SELECT id, competition_id, name, category, points, status, blocked_reason,
                      target_host, target_port, target_proto, case_id, created_at, updated_at
               FROM challenges WHERE id = ?1"#,
            )
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let challenge = stmt
            .query_row(params![id], |row| {
                let status_str: String = row.get(5)?;
                let blocked_reason_str: Option<String> = row.get(6)?;
                let host: Option<String> = row.get(7)?;
                let port: Option<u16> = row.get(8)?;
                let proto: Option<String> = row.get(9)?;
                let created_at_str: String = row.get(11)?;
                let updated_at_str: String = row.get(12)?;

                let target_scope = host.map(|h| TargetScope {
                    host: h,
                    port,
                    protocol: proto.unwrap_or_else(|| "tcp".into()),
                });

                Ok(Challenge {
                    id: row.get(0)?,
                    competition_id: row.get(1)?,
                    name: row.get(2)?,
                    category: row.get(3)?,
                    points: row.get(4)?,
                    status: ChallengeStatus::from_str(&status_str).unwrap_or_default(),
                    blocked_reason: blocked_reason_str.map(BlockedReason),
                    target_scope,
                    case_id: row.get(10)?,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc),
                })
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("Challenge", id),
                other => DomainError::Storage(other.to_string()),
            })?;

        Ok(ChallengeDetails {
            challenge,
            artifacts: vec![],
            active_jobs: 0,
            candidate_flags_count: 0,
            accepted_flag: None,
        })
    }

    fn list_transform_steps_internal(
        &self,
        chal_id: &ChallengeId,
    ) -> Result<Vec<TransformStep>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                r#"SELECT id, challenge_id, recipe_id, step_order, operation, parameters_json,
                      input_artifact_id, output_artifact_id, input_hash, output_hash, created_at
               FROM transform_steps WHERE challenge_id = ?1 ORDER BY step_order ASC"#,
            )
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![chal_id], |row| {
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
            })
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(|e| DomainError::Storage(e.to_string()))?);
        }
        Ok(list)
    }

    fn list_jobs_internal(&self, chal_id: &ChallengeId) -> Result<Vec<Job>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                r#"SELECT id, challenge_id, tool_id, adapter, runtime, state, argv_json,
                      input_refs_json, exit_code, timeout_ms, timeout_triggered,
                      started_at, completed_at, created_at
               FROM jobs WHERE challenge_id = ?1 ORDER BY created_at ASC"#,
            )
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![chal_id], |row| {
                let runtime_str: String = row.get(4)?;
                let state_str: String = row.get(5)?;
                let argv_json: String = row.get(6)?;
                let input_refs_json: String = row.get(7)?;
                let timeout_triggered_int: i32 = row.get(10)?;
                let started_at_str: Option<String> = row.get(11)?;
                let completed_at_str: Option<String> = row.get(12)?;
                let created_at_str: String = row.get(13)?;

                let argv: Vec<String> = serde_json::from_str(&argv_json).unwrap_or_default();
                let input_refs: Vec<String> =
                    serde_json::from_str(&input_refs_json).unwrap_or_default();

                Ok(Job {
                    id: row.get(0)?,
                    challenge_id: row.get(1)?,
                    tool_id: row.get(2)?,
                    adapter: row.get(3)?,
                    runtime: JobRuntime::from_str(&runtime_str).unwrap_or_default(),
                    state: JobStatus::from_str(&state_str).unwrap_or_default(),
                    argv,
                    input_refs,
                    exit_code: row.get(8)?,
                    timeout_ms: row.get(9)?,
                    timeout_triggered: timeout_triggered_int != 0,
                    started_at: started_at_str.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    }),
                    completed_at: completed_at_str.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    }),
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
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
}
