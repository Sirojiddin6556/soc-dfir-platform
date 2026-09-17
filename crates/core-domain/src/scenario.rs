use crate::id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioManifest {
    pub scenario_id: String,
    pub title: String,
    pub description: String,
    pub difficulty: String,
    pub signature: String, // Cryptographic verification of bundle
}

/// Sealed, isolated ground truth structure.
/// Inaccessible to player views or client RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub scenario_id: String,
    pub expected_assets: Vec<String>,
    pub expected_facts: Vec<String>,
    pub expected_attack_edges: Vec<(String, String, String)>,
    pub expected_mitre_techniques: Vec<String>,
    pub expected_kill_chain_stages: Vec<String>,
    pub expected_pyramid_levels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionScore {
    pub name: String,
    pub points_awarded: u32,
    pub max_points: u32,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub scenario_id: String,
    pub player_case_id: EntityId,
    pub total_score: u32,
    pub max_possible_score: u32,
    pub percentage: f32,
    pub criteria_scores: Vec<CriterionScore>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}
