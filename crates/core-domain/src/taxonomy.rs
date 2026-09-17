use crate::epistemic::{Confidence, VerificationState};
use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaxonomyNamespace {
    MitreAttackEnterprise,
    CyberKillChain,
    PyramidOfPain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxonomyVersion {
    pub id: String,
    pub namespace: TaxonomyNamespace,
    pub version: String,
    pub release_date: String,
    pub source_hash: String,
    pub imported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxonomyCandidate {
    pub technique_id: String,
    pub tactic: Option<String>,
    pub confidence: Confidence,
    pub verification_state: VerificationState,
    pub evidence_id: Option<EntityId>,
    pub mapping_rule_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxonomyMapping {
    pub id: EntityId,
    pub node_id: EntityId,
    pub taxonomy_version_id: String,
    pub technique_id: String,
    pub tactic: Option<String>,
    pub verification_state: VerificationState,
    pub confidence: Confidence,
    pub evidence_id: Option<EntityId>,
    pub mapping_rule_version: String,
}
