use super::{SqliteStorage, SqliteStorageError};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use core_domain::collaboration::{
    Channel, ChannelType, ChatMessage, EntityRef, OperationMode, Role, Team, TeamMember, User,
    UserPresence, UserSession,
};
use core_domain::id::EntityId;
use rand_core::OsRng;
use rusqlite::params;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_else(|_| "argon2_error".to_string())
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        // Not a valid Argon2 hash -> never authenticate. In particular this
        // refuses plaintext-equality and any placeholder/mock hash value.
        Err(_) => false,
    }
}

fn map_user_row(row: &rusqlite::Row) -> Result<User, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let role_str: String = row.get(4)?;
    let created_str: String = row.get(9)?;
    Ok(User {
        id: EntityId::parse(&id_str).unwrap_or_else(|_| EntityId::new_v7()),
        username: row.get(1)?,
        display_name: row.get(2)?,
        email: row.get(3)?,
        role: Role::from_str(&role_str),
        department: row.get(5)?,
        timezone: row.get(6)?,
        language: row.get(7)?,
        avatar_url: row.get(8)?,
        created_at: parse_dt(&created_str),
    })
}

fn parse_dt(s: &str) -> chrono::DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

impl SqliteStorage {
    /// Initializes collaboration structures according to the selected OperationMode
    pub fn init_collaboration_data(&self, mode: OperationMode) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        // 1. Purge legacy synthetic artifacts if in Live mode
        if mode.is_live() {
            let _ = conn.execute(
                "DELETE FROM messages WHERE author_name IN ('Азиз', 'Алишер') OR body LIKE '%Word%'",
                [],
            );
            let _ = conn.execute(
                "DELETE FROM users WHERE username IN ('aziz', 'alisher', 'bekzod')",
                [],
            );
            let _ = conn.execute(
                "DELETE FROM user_presence WHERE user_id NOT IN (SELECT id FROM users)",
                [],
            );
            let _ = conn.execute(
                "DELETE FROM team_members WHERE user_id NOT IN (SELECT id FROM users)",
                [],
            );
        }

        let count: i64 = conn.query_row("SELECT count(*) FROM workspaces", [], |r| r.get(0))?;
        if count == 0 {
            let ws_id = EntityId::new_v7();
            conn.execute(
                "INSERT INTO workspaces (id, name, organization_name, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![ws_id.to_string(), "Blue Team Lab", "UZSOC", now],
            )?;

            // Real Primary SOC Owner with Argon2id hash (default password: admin)
            let u_siroj = EntityId::new_v7();
            let pass_hash = hash_password("admin");
            conn.execute(
                "INSERT INTO users (id, username, display_name, email, password_hash, role, department, timezone, language, created_at) VALUES
                (?1, 'sirojiddin', 'Сироҷиддин', 'sirojiddin@soc.local', ?2, 'Owner', 'SOC', 'Asia/Tashkent', 'ru', ?3)",
                params![u_siroj.to_string(), pass_hash, now],
            )?;

            // Real initial presence
            conn.execute(
                "INSERT INTO user_presence (user_id, is_online, status_text, last_seen) VALUES
                (?1, 1, 'В сети: Консоль SOC', ?2)",
                params![u_siroj.to_string(), now],
            )?;

            // Real Primary Team
            let t_soc = EntityId::new_v7();
            conn.execute(
                "INSERT INTO teams (id, workspace_id, name, description, created_at) VALUES
                (?1, ?2, 'SOC Team', 'Основная дежурная смена мониторинга L1/L2', ?3)",
                params![t_soc.to_string(), ws_id.to_string(), now],
            )?;

            conn.execute(
                "INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?1, ?2, 'Owner', ?3)",
                params![t_soc.to_string(), u_siroj.to_string(), now],
            )?;

            conn.execute(
                "INSERT OR IGNORE INTO workspace_members (workspace_id, user_id, role, status, joined_at) VALUES (?1, ?2, 'Owner', 'Active', ?3)",
                params![ws_id.to_string(), u_siroj.to_string(), now],
            )?;

            // Empty Real Channels (ZERO messages in Live mode)
            let ch_gen = EntityId::new_v7();
            let ch_case = EntityId::new_v7();
            conn.execute(
                "INSERT INTO channels (id, workspace_id, case_id, name, channel_type, created_at) VALUES
                (?1, ?3, NULL, '💬 Общий командный чат', 'General', ?4),
                (?2, ?3, NULL, '🎯 Чат расследования INC-LIVE-001', 'Case', ?4)",
                params![ch_gen.to_string(), ch_case.to_string(), ws_id.to_string(), now],
            )?;
        }
        Ok(())
    }

    pub fn verify_user_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, display_name, email, role, department, timezone, language, avatar_url, created_at, password_hash FROM users WHERE username = ?1"
        )?;
        let row = stmt.query_row(params![username], |r| {
            let u = map_user_row(r)?;
            let hash: String = r.get(10)?;
            Ok((u, hash))
        });
        match row {
            Ok((user, hash)) => {
                if verify_password(password, &hash) {
                    Ok(Some(user))
                } else {
                    Ok(None)
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteStorageError::Rusqlite(e)),
        }
    }

    pub fn delete_session(&self, token: &str) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM user_sessions WHERE token = ?1", params![token])?;
        Ok(())
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<User>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, display_name, email, role, department, timezone, language, avatar_url, created_at FROM users WHERE username = ?1"
        )?;
        match stmt.query_row(params![username], map_user_row) {
            Ok(u) => Ok(Some(u)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteStorageError::Rusqlite(e)),
        }
    }

    pub fn get_user_by_token(&self, token: &str) -> Result<Option<User>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username, u.display_name, u.email, u.role, u.department, u.timezone, u.language, u.avatar_url, u.created_at
             FROM users u JOIN user_sessions s ON u.id = s.user_id WHERE s.token = ?1"
        )?;
        match stmt.query_row(params![token], map_user_row) {
            Ok(u) => Ok(Some(u)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteStorageError::Rusqlite(e)),
        }
    }

    pub fn get_entity(
        &self,
        ent_type: &str,
        ent_id: &str,
    ) -> Result<serde_json::Value, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        match ent_type.to_lowercase().as_str() {
            "finding" => {
                let mut stmt = conn.prepare(
                    "SELECT id, assertion_type, verification_state, entity_type, entity_key, fact_type, confidence, severity, risk_score, data_json, created_at FROM facts WHERE id = ?1 OR entity_key LIKE ?2 OR fact_type LIKE ?2 LIMIT 1"
                )?;
                let pattern = format!("%{}%", ent_id);
                let res = stmt.query_row(params![ent_id, pattern], |r| {
                    Ok(serde_json::json!({
                        "found": true,
                        "type": "Finding",
                        "id": r.get::<_, String>(0)?,
                        "assertion_type": r.get::<_, String>(1)?,
                        "verification_state": r.get::<_, String>(2)?,
                        "entity_type": r.get::<_, String>(3)?,
                        "entity_key": r.get::<_, String>(4)?,
                        "fact_type": r.get::<_, String>(5)?,
                        "confidence": r.get::<_, f64>(6)?,
                        "severity": r.get::<_, String>(7)?,
                        "risk_score": r.get::<_, f64>(8)?,
                        "data": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(9)?).unwrap_or_default(),
                        "created_at": r.get::<_, String>(10)?,
                    }))
                });
                match res {
                    Ok(v) => Ok(v),
                    Err(_) => Ok(serde_json::json!({
                        "found": false,
                        "type": "Finding",
                        "id": ent_id,
                        "message": format!("Находка #{} не обнаружена в подтвержденных фактах кейса", ent_id)
                    })),
                }
            }
            "evidence" => {
                let mut stmt = conn.prepare(
                    "SELECT id, hash_blake3, hash_sha256, original_name, file_size, mime_type, acquisition_method, acquired_at FROM artifacts WHERE id = ?1 OR original_name LIKE ?2 LIMIT 1"
                )?;
                let pattern = format!("%{}%", ent_id);
                let res = stmt.query_row(params![ent_id, pattern], |r| {
                    Ok(serde_json::json!({
                        "found": true,
                        "type": "Evidence",
                        "id": r.get::<_, String>(0)?,
                        "hash_blake3": r.get::<_, String>(1)?,
                        "hash_sha256": r.get::<_, String>(2)?,
                        "original_name": r.get::<_, String>(3)?,
                        "file_size": r.get::<_, i64>(4)?,
                        "mime_type": r.get::<_, String>(5)?,
                        "acquisition_method": r.get::<_, String>(6)?,
                        "acquired_at": r.get::<_, String>(7)?,
                    }))
                });
                match res {
                    Ok(v) => Ok(v),
                    Err(_) => Ok(serde_json::json!({
                        "found": false,
                        "type": "Evidence",
                        "id": ent_id,
                        "message": format!("Улика #{} не зарегистрирована в хранилище CAS", ent_id)
                    })),
                }
            }
            _ => Ok(serde_json::json!({
                "found": false,
                "type": ent_type,
                "id": ent_id,
                "message": format!("Сущность {} #{} не зарегистрирована", ent_type, ent_id)
            })),
        }
    }

    pub fn create_session(
        &self,
        user_id: EntityId,
        username: &str,
    ) -> Result<UserSession, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let session_id = format!("sess_{}", EntityId::new_v7());
        let token = format!("tk_{}", EntityId::new_v7());
        let now = Utc::now();
        let expires = now + chrono::Duration::days(7);

        conn.execute(
            "INSERT INTO user_sessions (session_id, user_id, token, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session_id, user_id.to_string(), token, now.to_rfc3339(), expires.to_rfc3339()],
        )?;

        Ok(UserSession {
            session_id,
            user_id,
            username: username.to_string(),
            token,
            created_at: now,
            expires_at: expires,
        })
    }

    pub fn update_user_profile(
        &self,
        user_id: EntityId,
        display_name: &str,
        email: &str,
        department: &str,
        timezone: &str,
        language: &str,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE users SET display_name = ?1, email = ?2, department = ?3, timezone = ?4, language = ?5 WHERE id = ?6",
            params![display_name, email, department, timezone, language, user_id.to_string()],
        )?;
        Ok(())
    }

    pub fn list_teams(&self) -> Result<Vec<Team>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT t.id, t.workspace_id, t.name, COALESCE(t.description, ''), t.created_at,
                    (SELECT count(*) FROM team_members tm WHERE tm.team_id = t.id) as m_count
             FROM teams t",
        )?;
        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let ws_str: String = row.get(1)?;
            let cr_str: String = row.get(4)?;
            Ok(Team {
                id: EntityId::parse(&id_str).unwrap_or_else(|_| EntityId::new_v7()),
                workspace_id: EntityId::parse(&ws_str).unwrap_or_else(|_| EntityId::new_v7()),
                name: row.get(2)?,
                description: row.get(3)?,
                member_count: row.get::<_, i64>(5)? as usize,
                created_at: parse_dt(&cr_str),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_team_members(
        &self,
        team_id: EntityId,
    ) -> Result<Vec<TeamMember>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tm.team_id, tm.user_id, u.username, u.display_name, tm.role, COALESCE(p.is_online, 0), p.status_text, tm.joined_at
             FROM team_members tm JOIN users u ON tm.user_id = u.id LEFT JOIN user_presence p ON u.id = p.user_id
             WHERE tm.team_id = ?1",
        )?;
        let rows = stmt.query_map(params![team_id.to_string()], |row| {
            let t_str: String = row.get(0)?;
            let u_str: String = row.get(1)?;
            let role_str: String = row.get(4)?;
            let j_str: String = row.get(7)?;
            Ok(TeamMember {
                team_id: EntityId::parse(&t_str).unwrap_or_else(|_| EntityId::new_v7()),
                user_id: EntityId::parse(&u_str).unwrap_or_else(|_| EntityId::new_v7()),
                username: row.get(2)?,
                display_name: row.get(3)?,
                role: Role::from_str(&role_str),
                is_online: row.get::<_, i64>(5)? == 1,
                current_action: row.get(6)?,
                joined_at: parse_dt(&j_str),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_channels(&self) -> Result<Vec<Channel>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, case_id, name, channel_type, created_at FROM channels ORDER BY created_at ASC"
        )?;
        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let ws_str: String = row.get(1)?;
            let case_opt: Option<String> = row.get(2)?;
            let ch_type_str: String = row.get(4)?;
            let cr_str: String = row.get(5)?;
            Ok(Channel {
                id: EntityId::parse(&id_str).unwrap_or_else(|_| EntityId::new_v7()),
                workspace_id: EntityId::parse(&ws_str).unwrap_or_else(|_| EntityId::new_v7()),
                case_id: case_opt.and_then(|c| EntityId::parse(&c).ok()),
                name: row.get(3)?,
                channel_type: match ch_type_str.as_str() {
                    "Case" => ChannelType::Case,
                    "Team" => ChannelType::Team,
                    _ => ChannelType::General,
                },
                created_at: parse_dt(&cr_str),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn insert_message(&self, msg: &ChatMessage) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let refs_json = serde_json::to_string(&msg.references).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO messages (id, channel_id, author_id, author_name, author_role, body, reply_to_id, references_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                msg.id.to_string(), msg.channel_id.to_string(), msg.author_id.to_string(),
                msg.author_name, msg.author_role.as_str(), msg.body,
                msg.reply_to_id.map(|r| r.to_string()), refs_json, msg.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn list_messages(
        &self,
        channel_id: EntityId,
        limit: usize,
    ) -> Result<Vec<ChatMessage>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, channel_id, author_id, author_name, author_role, body, reply_to_id, references_json, created_at
             FROM messages WHERE channel_id = ?1 ORDER BY created_at ASC LIMIT ?2"
        )?;
        let rows = stmt.query_map(params![channel_id.to_string(), limit as i64], |row| {
            let id_str: String = row.get(0)?;
            let ch_str: String = row.get(1)?;
            let auth_str: String = row.get(2)?;
            let role_str: String = row.get(4)?;
            let rep_opt: Option<String> = row.get(6)?;
            let refs_str: String = row.get(7)?;
            let cr_str: String = row.get(8)?;
            let refs: Vec<EntityRef> = serde_json::from_str(&refs_str).unwrap_or_default();
            Ok(ChatMessage {
                id: EntityId::parse(&id_str).unwrap_or_else(|_| EntityId::new_v7()),
                channel_id: EntityId::parse(&ch_str).unwrap_or_else(|_| EntityId::new_v7()),
                author_id: EntityId::parse(&auth_str).unwrap_or_else(|_| EntityId::new_v7()),
                author_name: row.get(3)?,
                author_role: Role::from_str(&role_str),
                body: row.get(5)?,
                reply_to_id: rep_opt.and_then(|r| EntityId::parse(&r).ok()),
                references: refs,
                created_at: parse_dt(&cr_str),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn list_presences(&self) -> Result<Vec<UserPresence>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT p.user_id, u.username, u.display_name, p.is_online, p.active_case_id, p.status_text, p.last_seen
             FROM user_presence p JOIN users u ON p.user_id = u.id"
        )?;
        let rows = stmt.query_map([], |row| {
            let u_str: String = row.get(0)?;
            let ls_str: String = row.get(6)?;
            Ok(UserPresence {
                user_id: EntityId::parse(&u_str).unwrap_or_else(|_| EntityId::new_v7()),
                username: row.get(1)?,
                display_name: row.get(2)?,
                is_online: row.get::<_, i64>(3)? == 1,
                active_case_id: row.get(4)?,
                status_text: row.get(5)?,
                last_seen: parse_dt(&ls_str),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SqliteStorageError::Rusqlite)
    }

    pub fn update_presence(
        &self,
        user_id: EntityId,
        is_online: bool,
        active_case_id: Option<&str>,
        status_text: &str,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO user_presence (user_id, is_online, active_case_id, status_text, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id) DO UPDATE SET
             is_online = ?2, active_case_id = ?3, status_text = ?4, last_seen = ?5",
            params![
                user_id.to_string(),
                if is_online { 1 } else { 0 },
                active_case_id,
                status_text,
                now
            ],
        )?;
        Ok(())
    }
}
