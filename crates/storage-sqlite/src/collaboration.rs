use super::{SqliteStorage, SqliteStorageError};
use chrono::Utc;
use core_domain::collaboration::{
    Channel, ChannelType, ChatMessage, EntityRef, Role, Team, TeamMember, User, UserPresence,
    UserSession,
};
use core_domain::id::EntityId;
use rusqlite::params;

impl SqliteStorage {
    /// Seeds default organization, workspace, teams, users, and case channels if missing
    pub fn init_default_collaboration_data(&self) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        let count: i64 = conn.query_row("SELECT count(*) FROM workspaces", [], |r| r.get(0))?;
        if count == 0 {
            let ws_id = EntityId::new_v7();
            conn.execute(
                "INSERT INTO workspaces (id, name, organization_name, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![ws_id.to_string(), "Blue Team Lab", "UZSOC", now],
            )?;

            let u_siroj = EntityId::new_v7();
            let u_aziz = EntityId::new_v7();
            let u_alisher = EntityId::new_v7();
            let u_bekzod = EntityId::new_v7();

            conn.execute(
                "INSERT INTO users (id, username, display_name, email, password_hash, role, department, timezone, language, created_at) VALUES
                (?1, 'sirojiddin', 'Сироҷиддин', 'sirojiddin@soc.local', 'sha256_mock_hash', 'Owner', 'SOC', 'Asia/Tashkent', 'ru', ?5),
                (?2, 'aziz', 'Азиз', 'aziz@soc.local', 'sha256_mock_hash', 'Lead', 'SOC', 'Asia/Tashkent', 'ru', ?5),
                (?3, 'alisher', 'Алишер', 'alisher@soc.local', 'sha256_mock_hash', 'Analyst', 'DFIR', 'Asia/Tashkent', 'ru', ?5),
                (?4, 'bekzod', 'Бекзод', 'bekzod@soc.local', 'sha256_mock_hash', 'Viewer', 'SOC', 'Asia/Tashkent', 'ru', ?5)",
                params![u_siroj.to_string(), u_aziz.to_string(), u_alisher.to_string(), u_bekzod.to_string(), now],
            )?;

            // Presences
            conn.execute(
                "INSERT INTO user_presence (user_id, is_online, status_text, last_seen) VALUES
                (?1, 1, 'В сети: Рабочая станция PC-3002', ?5),
                (?2, 1, 'Изучает Finding #17 и процессы', ?5),
                (?3, 1, 'Анализ сетевых сокетов и C2', ?5),
                (?4, 0, 'Был в сети 20 минут назад', ?5)",
                params![
                    u_siroj.to_string(),
                    u_aziz.to_string(),
                    u_alisher.to_string(),
                    u_bekzod.to_string(),
                    now
                ],
            )?;

            // Teams
            let t_soc = EntityId::new_v7();
            let t_dfir = EntityId::new_v7();
            let t_ctf = EntityId::new_v7();

            conn.execute(
                "INSERT INTO teams (id, workspace_id, name, description, created_at) VALUES
                (?1, ?4, 'SOC Team', 'Основная дежурная смена мониторинга L1/L2', ?5),
                (?2, ?4, 'DFIR Team', 'Группа глубокого форензика и реагирования на инциденты', ?5),
                (?3, ?4, 'CTF Team', 'Учебно-боевая киберполигонная группа', ?5)",
                params![
                    t_soc.to_string(),
                    t_dfir.to_string(),
                    t_ctf.to_string(),
                    ws_id.to_string(),
                    now
                ],
            )?;

            // Team Members
            conn.execute(
                "INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES
                (?1, ?4, 'Owner', ?6), (?1, ?5, 'Lead', ?6),
                (?2, ?4, 'Owner', ?6), (?2, ?7, 'Analyst', ?6),
                (?3, ?4, 'Owner', ?6), (?3, ?5, 'Lead', ?6)",
                params![
                    t_soc.to_string(),
                    t_dfir.to_string(),
                    t_ctf.to_string(),
                    u_siroj.to_string(),
                    u_aziz.to_string(),
                    now,
                    u_alisher.to_string()
                ],
            )?;

            // Default Channels
            let ch_gen = EntityId::new_v7();
            let ch_case = EntityId::new_v7();
            conn.execute(
                "INSERT INTO channels (id, workspace_id, case_id, name, channel_type, created_at) VALUES
                (?1, ?3, NULL, '💬 Общий командный чат', 'General', ?4),
                (?2, ?3, NULL, '🎯 Чат расследования INC-LIVE-001', 'Case', ?4)",
                params![ch_gen.to_string(), ch_case.to_string(), ws_id.to_string(), now],
            )?;

            // Initial Investigation-Aware Messages
            let refs_sample = serde_json::json!([
                {
                    "ref_type": "Finding",
                    "ref_id": "CORR-WIN-001e",
                    "title": "Finding #CORR-WIN-001e: OfficeSpawnedShell (CRITICAL)",
                    "metadata": { "mitre": "T1059.001", "risk": 92.0 }
                },
                {
                    "ref_type": "Process",
                    "ref_id": "powershell.exe",
                    "title": "Process powershell.exe (Parent: WINWORD.EXE)",
                    "metadata": { "pid": 4872 }
                }
            ]);

            conn.execute(
                "INSERT INTO messages (id, channel_id, author_id, author_name, author_role, body, references_json, created_at) VALUES
                (?1, ?2, ?3, 'Азиз', 'Lead', 'Коллеги, зафиксирована активность в кейсе INC-LIVE-001. Проверьте процессы хоста PC-3002.', '[]', ?4),
                (?5, ?2, ?6, 'Сироҷиддин', 'Owner', 'Изучил телеметрию. Зафиксирован аномальный запуск оболочки из Word: #finding-CORR-WIN-001e и #process-4872', ?7, ?4),
                (?8, ?2, ?9, 'Алишер', 'Analyst', '@sirojiddin подтверждаю. Тактика T1059.001. Проверяю сетевой сокет на порт 4444.', '[]', ?4)",
                params![
                    EntityId::new_v7().to_string(), ch_case.to_string(), u_aziz.to_string(), now,
                    EntityId::new_v7().to_string(), u_siroj.to_string(), refs_sample.to_string(),
                    EntityId::new_v7().to_string(), u_alisher.to_string()
                ],
            )?;
        }
        Ok(())
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<User>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, username, display_name, email, role, department, timezone, language, avatar_url, created_at FROM users WHERE username = ?1"
        )?;
        let user = stmt.query_row(params![username], |row| {
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
                created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        });

        match user {
            Ok(u) => Ok(Some(u)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteStorageError::Rusqlite(e)),
        }
    }

    pub fn get_user_by_token(&self, token: &str) -> Result<Option<User>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username, u.display_name, u.email, u.role, u.department, u.timezone, u.language, u.avatar_url, u.created_at
             FROM users u
             JOIN user_sessions s ON u.id = s.user_id
             WHERE s.token = ?1"
        )?;
        let user = stmt.query_row(params![token], |row| {
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
                created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        });

        match user {
            Ok(u) => Ok(Some(u)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteStorageError::Rusqlite(e)),
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
                created_at: chrono::DateTime::parse_from_rfc3339(&cr_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn list_team_members(
        &self,
        team_id: EntityId,
    ) -> Result<Vec<TeamMember>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tm.team_id, tm.user_id, u.username, u.display_name, tm.role, COALESCE(p.is_online, 0), p.status_text, tm.joined_at
             FROM team_members tm
             JOIN users u ON tm.user_id = u.id
             LEFT JOIN user_presence p ON u.id = p.user_id
             WHERE tm.team_id = ?1"
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
                joined_at: chrono::DateTime::parse_from_rfc3339(&j_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
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
                created_at: chrono::DateTime::parse_from_rfc3339(&cr_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn insert_message(&self, msg: &ChatMessage) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let refs_json = serde_json::to_string(&msg.references).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO messages (id, channel_id, author_id, author_name, author_role, body, reply_to_id, references_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                msg.id.to_string(),
                msg.channel_id.to_string(),
                msg.author_id.to_string(),
                msg.author_name,
                msg.author_role.as_str(),
                msg.body,
                msg.reply_to_id.map(|r| r.to_string()),
                refs_json,
                msg.created_at.to_rfc3339()
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
             FROM messages
             WHERE channel_id = ?1
             ORDER BY created_at ASC
             LIMIT ?2"
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
                created_at: chrono::DateTime::parse_from_rfc3339(&cr_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn list_presences(&self) -> Result<Vec<UserPresence>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT p.user_id, u.username, u.display_name, p.is_online, p.active_case_id, p.status_text, p.last_seen
             FROM user_presence p
             JOIN users u ON p.user_id = u.id"
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
                last_seen: chrono::DateTime::parse_from_rfc3339(&ls_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
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
