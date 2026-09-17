use crate::epistemic::Confidence;
use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceMember {
    pub fact_id: EntityId,
    pub relevance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EntityId,
    pub case_id: EntityId,
    pub title: String,
    pub description: String,
    pub confidence: Confidence,
    pub evidence_strength: f32,
    pub members: Vec<EvidenceMember>,
    pub created_at: DateTime<Utc>,
}
