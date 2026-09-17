use crate::epistemic::{AssertionType, Confidence, PainLevel, Severity, VerificationState};
use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Host,
    Process,
    NetworkSocket,
    Identity,
    File,
    MemoryRegion,
    Vulnerability,
    ThreatActor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub id: EntityId,
    pub case_id: EntityId,
    pub evidence_ids: Vec<EntityId>,
    pub assertion_type: AssertionType,
    pub verification_state: VerificationState,
    pub entity_type: EntityType,
    pub entity_key: String,
    pub fact_type: String,
    pub confidence: Confidence,
    pub severity: Severity,
    pub risk_score: f32,        // 0.0 .. 100.0
    pub evidence_strength: f32, // 0.0 .. 1.0
    pub pain_level: Option<PainLevel>,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl Fact {
    pub fn is_corroborated(&self) -> bool {
        self.evidence_ids.len() >= 2
    }
}
