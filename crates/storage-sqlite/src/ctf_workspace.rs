use crate::{SqliteStorage, SqliteStorageError};
use async_trait::async_trait;
use core_domain::ctf::state_machine::transition_challenge;
use core_domain::ctf::traits::WorkspaceService;
use core_domain::ctf::*;
use core_domain::error::DomainError;
use rusqlite::params;
use std::str::FromStr;

impl From<SqliteStorageError> for DomainError {
    fn from(err: SqliteStorageError) -> Self {
        match err {
            SqliteStorageError::NotFound(id) => DomainError::not_found("Entity", id),
            SqliteStorageError::Rusqlite(e) => {
                DomainError::Storage(format!("Database error: {}", e))
            }
            SqliteStorageError::Json(e) => DomainError::Storage(format!("JSON error: {}", e)),
            SqliteStorageError::Io(e) => DomainError::Storage(format!("IO error: {}", e)),
        }
    }
}

#[async_trait]
impl WorkspaceService for SqliteStorage {
    async fn create_competition(
        &self,
        cmd: CreateCompetitionCmd,
    ) -> Result<CompetitionId, DomainError> {
        let name = cmd.name.trim();
        if name.is_empty() || name.len() > 120 {
            return Err(DomainError::Validation(
                "Competition name must be between 1 and 120 characters".into(),
            ));
        }

        let comp_id = format!("comp-{}", uuid::Uuid::now_v7());
        let now = chrono::Utc::now().to_rfc3339();
        let format_str = cmd.format.unwrap_or_default().to_string();
        let status_str = CompetitionStatus::Active.to_string();
        let start_at_str = cmd.start_at.map(|t| t.to_rfc3339());
        let end_at_str = cmd.end_at.map(|t| t.to_rfc3339());

        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO competitions (
                id, name, description, format, flag_format_regex, start_at, end_at, status, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                comp_id,
                name,
                cmd.description,
                format_str,
                cmd.flag_format_regex,
                start_at_str,
                end_at_str,
                status_str,
                now,
                now
            ],
        ).map_err(|e| DomainError::Storage(format!("Failed to insert competition: {}", e)))?;

        Ok(comp_id)
    }

    async fn get_competition(&self, id: &CompetitionId) -> Result<Competition, DomainError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, name, description, format, flag_format_regex, start_at, end_at, status, created_at, updated_at
               FROM competitions WHERE id = ?1"#
        ).map_err(|e| DomainError::Storage(e.to_string()))?;

        let comp = stmt
            .query_row(params![id], |row| {
                let format_str: String = row.get(3)?;
                let status_str: String = row.get(7)?;
                let created_at_str: String = row.get(8)?;
                let updated_at_str: String = row.get(9)?;

                let start_at: Option<String> = row.get(5)?;
                let end_at: Option<String> = row.get(6)?;

                Ok(Competition {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    format: CompetitionFormat::from_str(&format_str).unwrap_or_default(),
                    flag_format_regex: row.get(4)?,
                    start_at: start_at.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    }),
                    end_at: end_at.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    }),
                    status: CompetitionStatus::from_str(&status_str).unwrap_or_default(),
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc),
                })
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("Competition", id),
                other => DomainError::Storage(other.to_string()),
            })?;

        Ok(comp)
    }

    async fn list_competitions(
        &self,
        filter: Option<CompetitionStatus>,
    ) -> Result<Vec<CompetitionSummary>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let (query, filter_param) = match filter {
            Some(status) => (
                r#"SELECT c.id, c.name, c.format, c.status,
                          (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS chal_count,
                          (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id AND ch.status = 'solved') AS solved_count
                   FROM competitions c WHERE c.status = ?1 ORDER BY c.created_at DESC"#,
                Some(status.to_string()),
            ),
            None => (
                r#"SELECT c.id, c.name, c.format, c.status,
                          (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS chal_count,
                          (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id AND ch.status = 'solved') AS solved_count
                   FROM competitions c ORDER BY c.created_at DESC"#,
                None,
            ),
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| DomainError::Storage(e.to_string()))?;
        let rows = if let Some(ref s) = filter_param {
            stmt.query_map(params![s], map_comp_summary)
        } else {
            stmt.query_map([], map_comp_summary)
        }
        .map_err(|e| DomainError::Storage(e.to_string()))?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(|e| DomainError::Storage(e.to_string()))?);
        }
        Ok(list)
    }

    async fn create_challenge(&self, cmd: CreateChallengeCmd) -> Result<ChallengeId, DomainError> {
        let name = cmd.name.trim();
        if name.is_empty() || name.len() > 120 {
            return Err(DomainError::Validation(
                "Challenge name must be between 1 and 120 characters".into(),
            ));
        }

        // Validate category
        let _ = ChallengeCategory::from_str(&cmd.category).map_err(|_| {
            DomainError::Validation(format!("Invalid challenge category: {}", cmd.category))
        })?;

        let chal_id = format!("chal-{}", uuid::Uuid::now_v7());
        let now = chrono::Utc::now().to_rfc3339();
        let status_str = ChallengeStatus::New.to_string();
        let points = cmd.points.unwrap_or(0);

        let (target_host, target_port, target_proto) = match cmd.target {
            Some(ref t) => (Some(t.host.clone()), t.port, Some(t.protocol.clone())),
            None => (None, None, None),
        };

        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO challenges (
                id, competition_id, name, category, points, status, target_host, target_port, target_proto, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
            params![
                chal_id,
                cmd.competition_id,
                name,
                cmd.category,
                points,
                status_str,
                target_host,
                target_port,
                target_proto,
                now,
                now
            ],
        ).map_err(|e| DomainError::Storage(format!("Failed to insert challenge: {}", e)))?;

        Ok(chal_id)
    }

    async fn get_challenge(&self, id: &ChallengeId) -> Result<ChallengeDetails, DomainError> {
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

        // Challenge artifacts
        let mut art_stmt = conn
            .prepare(
                r#"SELECT id, challenge_id, artifact_id, role, alias, added_at
               FROM challenge_artifacts WHERE challenge_id = ?1"#,
            )
            .map_err(|e| DomainError::Storage(e.to_string()))?;

        let art_rows = art_stmt
            .query_map(params![id], |row| {
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

        let mut artifacts = Vec::new();
        for a in art_rows {
            artifacts.push(a.map_err(|e| DomainError::Storage(e.to_string()))?);
        }

        let active_jobs: usize = conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE challenge_id = ?1 AND state IN ('queued', 'preparing', 'running')",
            params![id],
            |r| r.get(0),
        ).unwrap_or(0);

        let candidate_flags_count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM flag_candidates WHERE challenge_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let accepted_flag: Option<String> = conn.query_row(
            "SELECT value FROM flag_candidates WHERE challenge_id = ?1 AND verification_status = 'accepted' LIMIT 1",
            params![id],
            |r| r.get(0),
        ).ok();

        Ok(ChallengeDetails {
            challenge,
            artifacts,
            active_jobs,
            candidate_flags_count,
            accepted_flag,
        })
    }

    async fn list_challenges(
        &self,
        comp_id: &CompetitionId,
        cat: Option<String>,
    ) -> Result<Vec<ChallengeSummary>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let (query, has_cat) = match cat {
            Some(ref _c) => (
                r#"SELECT id, competition_id, name, category, points, status, (target_host IS NOT NULL) AS has_target
                   FROM challenges WHERE competition_id = ?1 AND category = ?2 ORDER BY points ASC, created_at ASC"#,
                true,
            ),
            None => (
                r#"SELECT id, competition_id, name, category, points, status, (target_host IS NOT NULL) AS has_target
                   FROM challenges WHERE competition_id = ?1 ORDER BY points ASC, created_at ASC"#,
                false,
            ),
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| DomainError::Storage(e.to_string()))?;
        let rows = if has_cat {
            stmt.query_map(params![comp_id, cat.unwrap()], map_chal_summary)
        } else {
            stmt.query_map(params![comp_id], map_chal_summary)
        }
        .map_err(|e| DomainError::Storage(e.to_string()))?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(|e| DomainError::Storage(e.to_string()))?);
        }
        Ok(list)
    }

    async fn update_challenge_status(
        &self,
        id: &ChallengeId,
        status: ChallengeStatus,
        reason: Option<BlockedReason>,
    ) -> Result<(), DomainError> {
        let mut details = self.get_challenge(id).await?;
        transition_challenge(&mut details.challenge, status, reason.clone())?;

        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let reason_str = reason.map(|r| r.0);

        conn.execute(
            "UPDATE challenges SET status = ?1, blocked_reason = ?2, updated_at = ?3 WHERE id = ?4",
            params![status.to_string(), reason_str, now, id],
        )
        .map_err(|e| DomainError::Storage(format!("Failed to update challenge status: {}", e)))?;

        Ok(())
    }

    async fn update_challenge_target(
        &self,
        id: &ChallengeId,
        target: TargetScope,
    ) -> Result<(), DomainError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE challenges SET target_host = ?1, target_port = ?2, target_proto = ?3, updated_at = ?4 WHERE id = ?5",
            params![target.host, target.port, target.protocol, now, id],
        ).map_err(|e| DomainError::Storage(format!("Failed to update challenge target: {}", e)))?;

        Ok(())
    }
}

fn map_comp_summary(row: &rusqlite::Row) -> Result<CompetitionSummary, rusqlite::Error> {
    let format_str: String = row.get(2)?;
    let status_str: String = row.get(3)?;
    Ok(CompetitionSummary {
        id: row.get(0)?,
        name: row.get(1)?,
        format: CompetitionFormat::from_str(&format_str).unwrap_or_default(),
        status: CompetitionStatus::from_str(&status_str).unwrap_or_default(),
        challenge_count: row.get(4)?,
        solved_count: row.get(5)?,
    })
}

fn map_chal_summary(row: &rusqlite::Row) -> Result<ChallengeSummary, rusqlite::Error> {
    let status_str: String = row.get(5)?;
    let has_target_int: i32 = row.get(6)?;
    Ok(ChallengeSummary {
        id: row.get(0)?,
        competition_id: row.get(1)?,
        name: row.get(2)?,
        category: row.get(3)?,
        points: row.get(4)?,
        status: ChallengeStatus::from_str(&status_str).unwrap_or_default(),
        has_target: has_target_int != 0,
    })
}
