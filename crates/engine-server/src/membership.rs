use core_domain::collaboration::Role;
use core_domain::id::EntityId;
use ipc_protocol::ProblemDetails;
use storage_sqlite::SqliteStorage;

pub struct MembershipHandler<'a> {
    pub storage: &'a SqliteStorage,
}

#[allow(clippy::result_large_err)]
impl<'a> MembershipHandler<'a> {
    pub fn new(storage: &'a SqliteStorage) -> Self {
        Self { storage }
    }

    fn authenticate(&self, p: &serde_json::Value) -> Result<EntityId, ProblemDetails> {
        let token = p
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| ProblemDetails::unauthorized("Отсутствует токен сессии"))?;
        let user = self
            .storage
            .get_user_by_token(token)
            .map_err(|_| ProblemDetails::unauthorized("Ошибка проверки сессии"))?
            .ok_or_else(|| ProblemDetails::unauthorized("Недействительная сессия"))?;
        Ok(user.id)
    }

    fn get_ws_id(&self, p: &serde_json::Value) -> Result<EntityId, ProblemDetails> {
        p.get("workspace_id")
            .and_then(|v| v.as_str())
            .and_then(|s| EntityId::parse(s).ok())
            .or_else(|| self.storage.get_default_workspace_id().ok())
            .ok_or_else(|| {
                ProblemDetails::bad_request(
                    "Рабочее пространство не найдено",
                    vec!["workspace_id".to_string()],
                )
            })
    }

    pub fn handle(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        match method {
            "invite.create" => self.handle_invite_create(params),
            "invite.validate" => self.handle_invite_validate(params),
            "invite.accept" => self.handle_invite_accept(params),
            "invite.revoke" => self.handle_invite_revoke(params),
            "invite.list" => self.handle_invite_list(params),
            "workspace.members" => self.handle_workspace_members(params),
            "member.role.update" => self.handle_role_update(params),
            "member.remove" => self.handle_member_remove(params),
            "case.member.add" => self.handle_case_member_add(params),
            "case.members" => self.handle_case_members(params),
            "case.access.check" => self.handle_case_access_check(params),
            "ownership.transfer" => self.handle_ownership_transfer(params),
            "membership.audit" => self.handle_membership_audit(params),
            _ => Err(ProblemDetails::bad_request(
                &format!("Неизвестный метод онбординга: {}", method),
                vec!["method".to_string()],
            )),
        }
    }

    fn handle_invite_create(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let user_id = self.authenticate(&p)?;
        let ws_id = self.get_ws_id(&p)?;
        let team_id = p
            .get("team_id")
            .and_then(|v| v.as_str())
            .and_then(|s| EntityId::parse(s).ok());
        let email = p
            .get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let role = p
            .get("role")
            .and_then(|v| v.as_str())
            .map(Role::from_str)
            .unwrap_or(Role::Analyst);
        let expires_hours = p
            .get("expires_hours")
            .and_then(|v| v.as_i64())
            .unwrap_or(24);
        let max_uses = p.get("max_uses").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

        let (invitation, code) = self
            .storage
            .create_invitation(
                ws_id,
                team_id,
                user_id,
                email,
                role,
                expires_hours,
                max_uses,
            )
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::json!({ "invitation": invitation, "code": code }))
    }

    fn handle_invite_validate(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let code = p.get("code").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("Код обязателен", vec!["code".to_string()])
        })?;
        let inv = self
            .storage
            .validate_invitation(code)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec!["code".to_string()]))?;
        Ok(serde_json::json!({ "valid": true, "invitation": inv }))
    }

    fn handle_invite_accept(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let user_id = self.authenticate(&p)?;
        let code = p.get("code").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("Код обязателен", vec!["code".to_string()])
        })?;
        let (ws_member, team_member) = self
            .storage
            .accept_invitation(code, user_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(
            serde_json::json!({ "success": true, "workspace_member": ws_member, "team_member": team_member }),
        )
    }

    fn handle_invite_revoke(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let actor_id = self.authenticate(&p)?;
        let inv_id_str = p.get("invite_id").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("invite_id обязателен", vec!["invite_id".to_string()])
        })?;
        let inv_id = EntityId::parse(inv_id_str).map_err(|_| {
            ProblemDetails::bad_request("Неверный формат invite_id", vec!["invite_id".to_string()])
        })?;
        self.storage
            .revoke_invitation(inv_id, actor_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::json!({ "status": "revoked", "invite_id": inv_id_str }))
    }

    fn handle_invite_list(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let _ = self.authenticate(&p)?;
        let ws_id = self.get_ws_id(&p)?;
        let list = self
            .storage
            .list_invitations(ws_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(list).unwrap_or(serde_json::json!([])))
    }

    fn handle_workspace_members(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let _ = self.authenticate(&p)?;
        let ws_id = self.get_ws_id(&p)?;
        let members = self
            .storage
            .list_workspace_members(ws_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(members).unwrap_or(serde_json::json!([])))
    }

    fn handle_role_update(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let actor_id = self.authenticate(&p)?;
        let ws_id = self.get_ws_id(&p)?;
        let uid_str = p.get("user_id").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("user_id обязателен", vec!["user_id".to_string()])
        })?;
        let target_uid = EntityId::parse(uid_str).map_err(|_| {
            ProblemDetails::bad_request("Неверный формат user_id", vec!["user_id".to_string()])
        })?;
        let role_str = p.get("role").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("role обязателен", vec!["role".to_string()])
        })?;
        let new_role = Role::from_str(role_str);
        self.storage
            .update_member_role(ws_id, target_uid, new_role, actor_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(
            serde_json::json!({ "success": true, "user_id": uid_str, "new_role": new_role.as_str() }),
        )
    }

    fn handle_member_remove(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let actor_id = self.authenticate(&p)?;
        let ws_id = self.get_ws_id(&p)?;
        let uid_str = p.get("user_id").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("user_id обязателен", vec!["user_id".to_string()])
        })?;
        let target_uid = EntityId::parse(uid_str).map_err(|_| {
            ProblemDetails::bad_request("Неверный формат user_id", vec!["user_id".to_string()])
        })?;
        self.storage
            .remove_workspace_member(ws_id, target_uid, actor_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::json!({ "success": true, "removed_user_id": uid_str }))
    }

    fn handle_case_member_add(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let actor_id = self.authenticate(&p)?;
        let cid_str = p.get("case_id").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("case_id обязателен", vec!["case_id".to_string()])
        })?;
        let case_id = EntityId::parse(cid_str).map_err(|_| {
            ProblemDetails::bad_request("Неверный формат case_id", vec!["case_id".to_string()])
        })?;
        let uid_str = p.get("user_id").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("user_id обязателен", vec!["user_id".to_string()])
        })?;
        let target_uid = EntityId::parse(uid_str).map_err(|_| {
            ProblemDetails::bad_request("Неверный формат user_id", vec!["user_id".to_string()])
        })?;
        let role = p
            .get("role")
            .and_then(|v| v.as_str())
            .map(Role::from_str)
            .unwrap_or(Role::Analyst);
        self.storage
            .add_case_member(case_id, target_uid, role, actor_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::json!({ "success": true, "case_id": cid_str, "user_id": uid_str }))
    }

    fn handle_case_members(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let _ = self.authenticate(&p)?;
        let cid_str = p.get("case_id").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("case_id обязателен", vec!["case_id".to_string()])
        })?;
        let case_id = EntityId::parse(cid_str).map_err(|_| {
            ProblemDetails::bad_request("Неверный формат case_id", vec!["case_id".to_string()])
        })?;
        let members = self
            .storage
            .list_case_members(case_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(members).unwrap_or(serde_json::json!([])))
    }

    fn handle_case_access_check(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let user_id = self.authenticate(&p)?;
        let cid_str = p.get("case_id").and_then(|v| v.as_str()).ok_or_else(|| {
            ProblemDetails::bad_request("case_id обязателен", vec!["case_id".to_string()])
        })?;
        let case_id = EntityId::parse(cid_str).map_err(|_| {
            ProblemDetails::bad_request("Неверный формат case_id", vec!["case_id".to_string()])
        })?;
        let has_access = self
            .storage
            .has_case_access(case_id, user_id)
            .unwrap_or(false);
        Ok(serde_json::json!({ "has_access": has_access, "case_id": cid_str }))
    }

    fn handle_ownership_transfer(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let current_owner = self.authenticate(&p)?;
        let ws_id = self.get_ws_id(&p)?;
        let new_owner_str = p
            .get("new_owner_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProblemDetails::bad_request(
                    "new_owner_id обязателен",
                    vec!["new_owner_id".to_string()],
                )
            })?;
        let new_owner_id = EntityId::parse(new_owner_str).map_err(|_| {
            ProblemDetails::bad_request(
                "Неверный формат new_owner_id",
                vec!["new_owner_id".to_string()],
            )
        })?;
        self.storage
            .transfer_ownership(ws_id, current_owner, new_owner_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(
            serde_json::json!({ "success": true, "previous_owner_id": current_owner.to_string(), "new_owner_id": new_owner_str }),
        )
    }

    fn handle_membership_audit(
        &self,
        p: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let _ = self.authenticate(&p)?;
        let ws_id = self.get_ws_id(&p)?;
        let limit = p.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let logs = self
            .storage
            .list_membership_audit(ws_id, limit)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(logs).unwrap_or(serde_json::json!([])))
    }
}
