use core_domain::collaboration::{ChatMessage, EntityRef, ReferenceType, User};
use core_domain::id::EntityId;
use ipc_protocol::ProblemDetails;
use storage_sqlite::SqliteStorage;

pub struct CollabHandler<'a> {
    pub storage: &'a SqliteStorage,
}

#[allow(clippy::result_large_err)]
impl<'a> CollabHandler<'a> {
    pub fn new(storage: &'a SqliteStorage) -> Self {
        Self { storage }
    }

    /// The user owning the session token in `params`. Identity always comes
    /// from the session, never from client-supplied names or ids.
    fn session_user(&self, params: &serde_json::Value) -> Result<User, ProblemDetails> {
        let token = params.get("token").and_then(|t| t.as_str()).unwrap_or("");
        self.storage
            .get_user_by_token(token)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?
            .ok_or_else(|| ProblemDetails::unauthorized("Сессия не найдена или истекла"))
    }

    pub fn handle(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        match method {
            "auth.update_profile" => self.handle_update_profile(params),
            "entity.get" => self.handle_entity_get(params),
            "team.list" => self.handle_team_list(),
            "team.members" => self.handle_team_members(params),
            "chat.channels" => self.handle_chat_channels(),
            "chat.history" => self.handle_chat_history(params),
            "chat.send" => self.handle_chat_send(params),
            "presence.list" => self.handle_presence_list(),
            "presence.update" => self.handle_presence_update(params),
            m if m.starts_with("invite.")
                || m.starts_with("workspace.")
                || m.starts_with("member.")
                || m.starts_with("case.")
                || m == "ownership.transfer"
                || m == "membership.audit" =>
            {
                crate::membership::MembershipHandler::new(self.storage).handle(m, params)
            }
            _ => Err(ProblemDetails::bad_request(
                &format!("Неизвестный метод совместной работы: {}", method),
                vec!["method".to_string()],
            )),
        }
    }

    fn handle_entity_get(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let ent_type = params.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let ent_id = params.get("id").and_then(|i| i.as_str()).unwrap_or("");
        let res = self.storage.get_entity(ent_type, ent_id).map_err(|e| {
            ProblemDetails::bad_request(&format!("Ошибка поиска сущности: {}", e), vec![])
        })?;
        Ok(res)
    }

    fn handle_update_profile(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let user = self.session_user(&params)?;
        let field = |name: &str, current: &str| -> String {
            params
                .get(name)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .unwrap_or(current)
                .to_string()
        };
        let display_name = field("display_name", &user.display_name);
        let email = field("email", &user.email);
        let dept = field("department", &user.department);
        let tz = field("timezone", &user.timezone);
        let lang = field("language", &user.language);

        self.storage
            .update_user_profile(user.id, &display_name, &email, &dept, &tz, &lang)
            .map_err(|e| {
                ProblemDetails::bad_request(&format!("Ошибка обновления профиля: {}", e), vec![])
            })?;

        Ok(serde_json::json!({
            "status": "success",
            "message": "Профиль успешно обновлен"
        }))
    }

    fn handle_team_list(&self) -> Result<serde_json::Value, ProblemDetails> {
        let teams = self
            .storage
            .list_teams()
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(teams).unwrap_or_default())
    }

    fn handle_team_members(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let team_id_str = params.get("team_id").and_then(|t| t.as_str()).unwrap_or("");
        let team_id = match EntityId::parse(team_id_str) {
            Ok(id) => id,
            Err(_) => {
                let teams = self.storage.list_teams().unwrap_or_default();
                if let Some(t) = teams.first() {
                    t.id
                } else {
                    return Ok(serde_json::json!([]));
                }
            }
        };

        let members = self
            .storage
            .list_team_members(team_id)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(members).unwrap_or_default())
    }

    fn handle_chat_channels(&self) -> Result<serde_json::Value, ProblemDetails> {
        let channels = self
            .storage
            .list_channels()
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(channels).unwrap_or_default())
    }

    fn handle_chat_history(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let ch_id_str = params
            .get("channel_id")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        let limit = params.get("limit").and_then(|l| l.as_u64()).unwrap_or(50) as usize;

        let channel_id = match EntityId::parse(ch_id_str) {
            Ok(id) => id,
            Err(_) => {
                let channels = self.storage.list_channels().unwrap_or_default();
                if let Some(ch) = channels.last() {
                    ch.id
                } else {
                    return Ok(serde_json::json!([]));
                }
            }
        };

        let messages = self
            .storage
            .list_messages(channel_id, limit)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(messages).unwrap_or_default())
    }

    fn handle_chat_send(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let ch_id_str = params
            .get("channel_id")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        let channel_id = match EntityId::parse(ch_id_str) {
            Ok(id) => id,
            Err(_) => {
                let channels = self.storage.list_channels().unwrap_or_default();
                channels
                    .last()
                    .map(|c| c.id)
                    .unwrap_or_else(EntityId::new_v7)
            }
        };

        let user = self.session_user(&params)?;
        let body = params
            .get("body")
            .and_then(|b| b.as_str())
            .unwrap_or("")
            .trim();

        if body.is_empty() {
            return Err(ProblemDetails::bad_request(
                "Текст сообщения не может быть пустым",
                vec!["body".to_string()],
            ));
        }

        // Investigation-Aware Reference Extraction
        let mut references = Vec::new();
        for word in body.split_whitespace() {
            if word.starts_with("#finding-") || word.starts_with("/finding") {
                let id = word
                    .replace("#finding-", "")
                    .replace("/finding", "")
                    .trim()
                    .to_string();
                if !id.is_empty() {
                    references.push(EntityRef {
                        ref_type: ReferenceType::Finding,
                        ref_id: id.clone(),
                        title: format!("Улика #{}", id),
                        metadata: serde_json::json!({ "type": "finding" }),
                    });
                }
            } else if word.starts_with("#process-") || word.starts_with("/process") {
                let id = word
                    .replace("#process-", "")
                    .replace("/process", "")
                    .trim()
                    .to_string();
                if !id.is_empty() {
                    references.push(EntityRef {
                        ref_type: ReferenceType::Process,
                        ref_id: id.clone(),
                        title: format!("Процесс PID/Имя: {}", id),
                        metadata: serde_json::json!({ "type": "process" }),
                    });
                }
            } else if word.starts_with("#evidence-") || word.starts_with("/evidence") {
                let id = word
                    .replace("#evidence-", "")
                    .replace("/evidence", "")
                    .trim()
                    .to_string();
                if !id.is_empty() {
                    references.push(EntityRef {
                        ref_type: ReferenceType::Evidence,
                        ref_id: id.clone(),
                        title: format!("Артефакт доказательства #{}", id),
                        metadata: serde_json::json!({ "type": "evidence" }),
                    });
                }
            } else if word.starts_with("#cve-") || word.starts_with("/cve") {
                let id = word
                    .replace("#cve-", "")
                    .replace("/cve", "")
                    .trim()
                    .to_string();
                if !id.is_empty() {
                    references.push(EntityRef {
                        ref_type: ReferenceType::Cve,
                        ref_id: id.clone(),
                        title: format!("Уязвимость CVE-{}", id),
                        metadata: serde_json::json!({ "type": "cve" }),
                    });
                }
            } else if word.starts_with("#T1")
                || word.starts_with("#t1")
                || word.starts_with("/mitre")
            {
                let id = word
                    .replace('#', "")
                    .replace("/mitre", "")
                    .trim()
                    .to_uppercase();
                if !id.is_empty() {
                    references.push(EntityRef {
                        ref_type: ReferenceType::Mitre,
                        ref_id: id.clone(),
                        title: format!("Техника MITRE ATT&CK {}", id),
                        metadata: serde_json::json!({ "type": "mitre" }),
                    });
                }
            }
        }

        let msg = ChatMessage {
            id: EntityId::new_v7(),
            channel_id,
            author_id: user.id,
            author_name: user.display_name.clone(),
            author_role: user.role.clone(),
            body: body.to_string(),
            reply_to_id: None,
            references,
            created_at: chrono::Utc::now(),
        };

        self.storage
            .insert_message(&msg)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;

        Ok(serde_json::to_value(&msg).unwrap_or_default())
    }

    fn handle_presence_list(&self) -> Result<serde_json::Value, ProblemDetails> {
        let presences = self
            .storage
            .list_presences()
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;
        Ok(serde_json::to_value(presences).unwrap_or_default())
    }

    fn handle_presence_update(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let is_online = params
            .get("is_online")
            .and_then(|o| o.as_bool())
            .unwrap_or(true);
        let status = params
            .get("status_text")
            .and_then(|s| s.as_str())
            .unwrap_or("В сети");
        let active_case = params.get("active_case_id").and_then(|c| c.as_str());

        let user = self.session_user(&params)?;

        self.storage
            .update_presence(user.id, is_online, active_case, status)
            .map_err(|e| ProblemDetails::bad_request(&e.to_string(), vec![]))?;

        Ok(serde_json::json!({
            "status": "updated",
            "user_id": user.id,
            "is_online": is_online,
            "status_text": status,
            "active_case_id": active_case
        }))
    }
}
