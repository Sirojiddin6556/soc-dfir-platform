use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: EntityId,
    pub case_id: Option<EntityId>,
    pub actor_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub details_json: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

impl AuditEvent {
    pub fn new(
        case_id: Option<EntityId>,
        actor_id: impl Into<String>,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: Option<String>,
        outcome: impl Into<String>,
        details_json: serde_json::Value,
    ) -> Self {
        Self {
            id: EntityId::new_v7(),
            case_id,
            actor_id: actor_id.into(),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id,
            outcome: outcome.into(),
            details_json,
            timestamp: Utc::now(),
        }
    }
}
