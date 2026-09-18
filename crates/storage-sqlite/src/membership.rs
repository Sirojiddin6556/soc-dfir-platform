use super::{SqliteStorage, SqliteStorageError};
use chrono::Utc;
use core_domain::collaboration::{
    CaseMember, Invitation, InvitationStatus, MembershipAuditEntry, MembershipStatus, Role,
    TeamMember, WorkspaceMember,
};
use core_domain::id::EntityId;
use rand_core::{OsRng, RngCore};
use rusqlite::params;
use sha2::{Digest, Sha256};

fn parse_dt(s: &str) -> chrono::DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

pub fn generate_invite_code() -> String {
    let mut b = [0u8; 6];
    OsRng.fill_bytes(&mut b);
    const C: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let c = |idx: usize| C[(b[idx] as usize) % C.len()] as char;
    format!("{}{}{}{}-{}{}", c(0), c(1), c(2), c(3), c(4), c(5))
}

pub fn hash_invite_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn map_invitation(r: &rusqlite::Row) -> Result<Invitation, rusqlite::Error> {
    Ok(Invitation {
        id: EntityId::parse(&r.get::<_, String>(0)?).unwrap_or_default(),
        workspace_id: EntityId::parse(&r.get::<_, String>(1)?).unwrap_or_default(),
        team_id: r
            .get::<_, Option<String>>(2)?
            .and_then(|t| EntityId::parse(&t).ok()),
        code: r.get(3)?,
        token_hash: r.get(4)?,
        created_by: EntityId::parse(&r.get::<_, String>(5)?).unwrap_or_default(),
        email: r.get(6)?,
        role: Role::from_str(&r.get::<_, String>(7)?),
        expires_at: parse_dt(&r.get::<_, String>(8)?),
        max_uses: r.get::<_, i64>(9)? as usize,
        used_count: r.get::<_, i64>(10)? as usize,
        status: InvitationStatus::from_str(&r.get::<_, String>(11)?),
        created_at: parse_dt(&r.get::<_, String>(12)?),
    })
}

fn audit_log(
    conn: &rusqlite::Connection,
    ws: &str,
    user: &str,
    actor: &str,
    action: &str,
    det: &str,
) {
    let _ = conn.execute(
        "INSERT INTO membership_audit (id, workspace_id, user_id, actor_id, action, details, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![EntityId::new_v7().to_string(), ws, user, actor, action, det, Utc::now().to_rfc3339()],
    );
}

impl SqliteStorage {
    pub fn get_default_workspace_id(&self) -> Result<EntityId, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let ws: String = conn.query_row("SELECT id FROM workspaces LIMIT 1", [], |r| r.get(0))?;
        EntityId::parse(&ws).map_err(|e| SqliteStorageError::NotFound(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_invitation(
        &self,
        workspace_id: EntityId,
        team_id: Option<EntityId>,
        created_by: EntityId,
        email: Option<String>,
        role: Role,
        expires_hours: i64,
        max_uses: usize,
    ) -> Result<(Invitation, String), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let inv_id = EntityId::new_v7();
        let code = generate_invite_code();
        let token_hash = hash_invite_token(&code);
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(expires_hours.max(1));

        conn.execute(
            "INSERT INTO invitations (id, workspace_id, team_id, code, token_hash, created_by, email, role, expires_at, max_uses, used_count, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, 'Pending', ?11)",
            params![
                inv_id.to_string(), workspace_id.to_string(), team_id.map(|t| t.to_string()),
                code, token_hash, created_by.to_string(), email, role.as_str(), expires_at.to_rfc3339(), max_uses as i64, now.to_rfc3339()
            ],
        )?;
        audit_log(
            &conn,
            &workspace_id.to_string(),
            &created_by.to_string(),
            &created_by.to_string(),
            "invite.created",
            &format!("Роль {}, код {}", role.as_str(), code),
        );

        Ok((
            Invitation {
                id: inv_id,
                workspace_id,
                team_id,
                code: code.clone(),
                token_hash,
                created_by,
                email,
                role,
                expires_at,
                max_uses,
                used_count: 0,
                status: InvitationStatus::Pending,
                created_at: now,
            },
            code,
        ))
    }

    pub fn validate_invitation(&self, code: &str) -> Result<Invitation, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, team_id, code, token_hash, created_by, email, role, expires_at, max_uses, used_count, status, created_at FROM invitations WHERE code = ?1 OR token_hash = ?1",
        )?;
        let mut rows = stmt.query(params![code])?;
        if let Some(row) = rows.next()? {
            let inv = map_invitation(row)?;
            if inv.status != InvitationStatus::Pending {
                return Err(SqliteStorageError::NotFound(format!(
                    "Приглашение недействительно ({})",
                    inv.status.as_str()
                )));
            }
            if inv.expires_at < Utc::now() {
                return Err(SqliteStorageError::NotFound(
                    "Срок действия приглашения истёк".into(),
                ));
            }
            if inv.used_count >= inv.max_uses {
                return Err(SqliteStorageError::NotFound(
                    "Лимит использований исчерпан".into(),
                ));
            }
            Ok(inv)
        } else {
            Err(SqliteStorageError::NotFound(
                "Приглашение не найдено".into(),
            ))
        }
    }

    pub fn accept_invitation(
        &self,
        code: &str,
        user_id: EntityId,
    ) -> Result<(WorkspaceMember, Option<TeamMember>), SqliteStorageError> {
        let inv = self.validate_invitation(code)?;
        let conn = self.conn.lock().unwrap();
        let now = Utc::now();
        let now_s = now.to_rfc3339();
        let new_used = inv.used_count + 1;
        let new_status = if new_used >= inv.max_uses {
            "Accepted"
        } else {
            "Pending"
        };

        conn.execute(
            "UPDATE invitations SET used_count = ?1, status = ?2 WHERE id = ?3",
            params![new_used as i64, new_status, inv.id.to_string()],
        )?;
        conn.execute(
            "INSERT INTO workspace_members (workspace_id, user_id, role, status, joined_at) VALUES (?1, ?2, ?3, 'Active', ?4)
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = ?3, status = 'Active'",
            params![inv.workspace_id.to_string(), user_id.to_string(), inv.role.as_str(), now_s],
        )?;

        let mut tm = None;
        if let Some(tid) = inv.team_id {
            conn.execute(
                "INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(team_id, user_id) DO UPDATE SET role = ?3",
                params![tid.to_string(), user_id.to_string(), inv.role.as_str(), now_s],
            )?;
            let (un, dn): (String, String) = conn
                .query_row(
                    "SELECT username, display_name FROM users WHERE id = ?1",
                    params![user_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or_else(|_| ("analyst".into(), "Аналитик".into()));
            tm = Some(TeamMember {
                team_id: tid,
                user_id,
                username: un,
                display_name: dn,
                role: inv.role,
                is_online: true,
                current_action: None,
                joined_at: now,
            });
        }

        audit_log(
            &conn,
            &inv.workspace_id.to_string(),
            &user_id.to_string(),
            &user_id.to_string(),
            "invite.accepted",
            &format!("Принят {}, роль {}", inv.code, inv.role.as_str()),
        );
        Ok((
            WorkspaceMember {
                workspace_id: inv.workspace_id,
                user_id,
                role: inv.role,
                status: MembershipStatus::Active,
                joined_at: now,
            },
            tm,
        ))
    }

    pub fn revoke_invitation(
        &self,
        invite_id: EntityId,
        actor_id: EntityId,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let ws: String = conn.query_row(
            "SELECT workspace_id FROM invitations WHERE id = ?1",
            params![invite_id.to_string()],
            |r| r.get(0),
        )?;
        conn.execute(
            "UPDATE invitations SET status = 'Revoked' WHERE id = ?1",
            params![invite_id.to_string()],
        )?;
        audit_log(
            &conn,
            &ws,
            &actor_id.to_string(),
            &actor_id.to_string(),
            "invite.revoked",
            &format!("Отозвано {}", invite_id),
        );
        Ok(())
    }

    pub fn list_invitations(
        &self,
        workspace_id: EntityId,
    ) -> Result<Vec<Invitation>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, workspace_id, team_id, code, token_hash, created_by, email, role, expires_at, max_uses, used_count, status, created_at FROM invitations WHERE workspace_id = ?1 ORDER BY created_at DESC")?;
        let rows = stmt.query_map(params![workspace_id.to_string()], map_invitation)?;
        rows.map(|r| r.map_err(SqliteStorageError::Rusqlite))
            .collect()
    }

    pub fn list_workspace_members(
        &self,
        workspace_id: EntityId,
    ) -> Result<Vec<WorkspaceMember>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT workspace_id, user_id, role, status, joined_at FROM workspace_members WHERE workspace_id = ?1 ORDER BY joined_at ASC")?;
        let rows = stmt.query_map(params![workspace_id.to_string()], |r| {
            Ok(WorkspaceMember {
                workspace_id: EntityId::parse(&r.get::<_, String>(0)?).unwrap_or_default(),
                user_id: EntityId::parse(&r.get::<_, String>(1)?).unwrap_or_default(),
                role: Role::from_str(&r.get::<_, String>(2)?),
                status: MembershipStatus::from_str(&r.get::<_, String>(3)?),
                joined_at: parse_dt(&r.get::<_, String>(4)?),
            })
        })?;
        rows.map(|r| r.map_err(SqliteStorageError::Rusqlite))
            .collect()
    }

    pub fn remove_workspace_member(
        &self,
        workspace_id: EntityId,
        user_id: EntityId,
        actor_id: EntityId,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE workspace_members SET status = 'Removed' WHERE workspace_id = ?1 AND user_id = ?2", params![workspace_id.to_string(), user_id.to_string()])?;
        conn.execute("DELETE FROM team_members WHERE user_id = ?1 AND team_id IN (SELECT id FROM teams WHERE workspace_id = ?2)", params![user_id.to_string(), workspace_id.to_string()])?;
        audit_log(
            &conn,
            &workspace_id.to_string(),
            &user_id.to_string(),
            &actor_id.to_string(),
            "member.removed",
            "Исключен из пространства",
        );
        Ok(())
    }

    pub fn update_member_role(
        &self,
        workspace_id: EntityId,
        user_id: EntityId,
        new_role: Role,
        actor_id: EntityId,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE workspace_members SET role = ?1 WHERE workspace_id = ?2 AND user_id = ?3",
            params![
                new_role.as_str(),
                workspace_id.to_string(),
                user_id.to_string()
            ],
        )?;
        conn.execute(
            "UPDATE users SET role = ?1 WHERE id = ?2",
            params![new_role.as_str(), user_id.to_string()],
        )?;
        audit_log(
            &conn,
            &workspace_id.to_string(),
            &user_id.to_string(),
            &actor_id.to_string(),
            "role.updated",
            &format!("Новая роль: {}", new_role.as_str()),
        );
        Ok(())
    }

    pub fn add_case_member(
        &self,
        case_id: EntityId,
        user_id: EntityId,
        role: Role,
        assigned_by: EntityId,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO case_members (case_id, user_id, role, assigned_by, assigned_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(case_id, user_id) DO UPDATE SET role = ?3",
            params![case_id.to_string(), user_id.to_string(), role.as_str(), assigned_by.to_string(), Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn list_case_members(
        &self,
        case_id: EntityId,
    ) -> Result<Vec<CaseMember>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT case_id, user_id, role, assigned_by, assigned_at FROM case_members WHERE case_id = ?1 ORDER BY assigned_at ASC")?;
        let rows = stmt.query_map(params![case_id.to_string()], |r| {
            Ok(CaseMember {
                case_id: EntityId::parse(&r.get::<_, String>(0)?).unwrap_or_default(),
                user_id: EntityId::parse(&r.get::<_, String>(1)?).unwrap_or_default(),
                role: Role::from_str(&r.get::<_, String>(2)?),
                assigned_by: EntityId::parse(&r.get::<_, String>(3)?).unwrap_or_default(),
                assigned_at: parse_dt(&r.get::<_, String>(4)?),
            })
        })?;
        rows.map(|r| r.map_err(SqliteStorageError::Rusqlite))
            .collect()
    }

    pub fn has_case_access(
        &self,
        case_id: EntityId,
        user_id: EntityId,
    ) -> Result<bool, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let user_role: Result<String, _> = conn.query_row(
            "SELECT role FROM users WHERE id = ?1",
            params![user_id.to_string()],
            |r| r.get(0),
        );
        if let Ok(role_s) = user_role {
            let role = Role::from_str(&role_s);
            if role == Role::Owner || role == Role::Admin {
                return Ok(true);
            }
        }
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM case_members WHERE case_id = ?1 AND user_id = ?2",
            params![case_id.to_string(), user_id.to_string()],
            |r| r.get(0),
        )?;
        if count > 0 {
            return Ok(true);
        }
        let team_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM channels c JOIN team_members tm ON tm.team_id = c.workspace_id WHERE c.case_id = ?1 AND tm.user_id = ?2",
            params![case_id.to_string(), user_id.to_string()],
            |r| r.get(0),
        )?;
        Ok(team_count > 0)
    }

    pub fn transfer_ownership(
        &self,
        ws_id: EntityId,
        curr_owner: EntityId,
        new_owner: EntityId,
    ) -> Result<(), SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE workspace_members SET role = 'Admin' WHERE workspace_id = ?1 AND user_id = ?2",
            params![ws_id.to_string(), curr_owner.to_string()],
        )?;
        conn.execute(
            "UPDATE users SET role = 'Admin' WHERE id = ?1",
            params![curr_owner.to_string()],
        )?;
        conn.execute(
            "UPDATE workspace_members SET role = 'Owner' WHERE workspace_id = ?1 AND user_id = ?2",
            params![ws_id.to_string(), new_owner.to_string()],
        )?;
        conn.execute(
            "UPDATE users SET role = 'Owner' WHERE id = ?1",
            params![new_owner.to_string()],
        )?;
        audit_log(
            &conn,
            &ws_id.to_string(),
            &new_owner.to_string(),
            &curr_owner.to_string(),
            "ownership.transferred",
            "Владение передано",
        );
        Ok(())
    }

    pub fn list_membership_audit(
        &self,
        ws_id: EntityId,
        limit: usize,
    ) -> Result<Vec<MembershipAuditEntry>, SqliteStorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, workspace_id, user_id, actor_id, action, details, created_at FROM membership_audit WHERE workspace_id = ?1 ORDER BY created_at DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![ws_id.to_string(), limit as i64], |r| {
            Ok(MembershipAuditEntry {
                id: EntityId::parse(&r.get::<_, String>(0)?).unwrap_or_default(),
                workspace_id: EntityId::parse(&r.get::<_, String>(1)?).unwrap_or_default(),
                user_id: EntityId::parse(&r.get::<_, String>(2)?).unwrap_or_default(),
                actor_id: EntityId::parse(&r.get::<_, String>(3)?).unwrap_or_default(),
                action: r.get(4)?,
                details: r.get(5)?,
                created_at: parse_dt(&r.get::<_, String>(6)?),
            })
        })?;
        rows.map(|r| r.map_err(SqliteStorageError::Rusqlite))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_membership_lifecycle() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let (ws_id, owner_id, new_user_id) =
            (EntityId::new_v7(), EntityId::new_v7(), EntityId::new_v7());
        let now = chrono::Utc::now().to_rfc3339();
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO workspaces VALUES (?1, 'UZSOC', 'SOC', ?2)",
                params![ws_id.to_string(), now],
            )
            .unwrap();
            conn.execute("INSERT INTO users VALUES (?1, 'owner', 'O', 'o@s.l', 'h', 'Owner', 'S', 'UTC', 'ru', NULL, ?2)", params![owner_id.to_string(), now]).unwrap();
            conn.execute("INSERT INTO users VALUES (?1, 'analyst', 'A', 'a@s.l', 'h', 'Analyst', 'S', 'UTC', 'ru', NULL, ?2)", params![new_user_id.to_string(), now]).unwrap();
        }

        let (inv, code) = storage
            .create_invitation(ws_id, None, owner_id, None, Role::Analyst, 24, 1)
            .unwrap();
        assert_eq!(inv.status, InvitationStatus::Pending);
        assert_eq!(storage.validate_invitation(&code).unwrap().id, inv.id);

        let (m, _) = storage.accept_invitation(&code, new_user_id).unwrap();
        assert_eq!(m.user_id, new_user_id);
        assert!(storage.validate_invitation(&code).is_err());
        assert_eq!(storage.list_workspace_members(ws_id).unwrap().len(), 1);
        assert!(storage.list_membership_audit(ws_id, 10).unwrap().len() >= 2);
    }
}
