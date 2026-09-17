#![forbid(unsafe_code)]

use core_domain::fact::Fact;
use core_domain::id::EntityId;
use core_domain::scenario::{CriterionScore, GroundTruth, VerificationReport};
use std::collections::HashSet;

pub struct ScenarioVerifier;

impl ScenarioVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates player's discovered facts against isolated ground truth.
    /// Ground Truth is never written to player DB or exposed over RPC.
    pub fn verify_investigation(
        &self,
        scenario_id: &str,
        player_case_id: EntityId,
        ground_truth: &GroundTruth,
        player_facts: &[Fact],
    ) -> VerificationReport {
        let mut criteria_scores = Vec::new();
        let mut total_score = 0;
        let mut max_possible = 0;

        // 1. Assets Discovered Check
        let player_assets: HashSet<String> = player_facts
            .iter()
            .map(|f| f.entity_key.clone())
            .collect();

        let mut matched_assets = 0;
        for expected in &ground_truth.expected_assets {
            if player_assets.contains(expected) {
                matched_assets += 1;
            }
        }

        let asset_pts = matched_assets * 20;
        let asset_max = (ground_truth.expected_assets.len() * 20) as u32;
        criteria_scores.push(CriterionScore {
            name: "Assets Discovered".to_string(),
            points_awarded: asset_pts as u32,
            max_points: asset_max,
            explanation: format!("Discovered {}/{} required assets", matched_assets, ground_truth.expected_assets.len()),
        });
        total_score += asset_pts as u32;
        max_possible += asset_max;

        let percentage = if max_possible > 0 {
            (total_score as f32 / max_possible as f32) * 100.0
        } else {
            100.0
        };

        VerificationReport {
            scenario_id: scenario_id.to_string(),
            player_case_id,
            total_score,
            max_possible_score: max_possible,
            percentage,
            criteria_scores,
            completed_at: chrono::Utc::now(),
        }
    }
}

impl Default for ScenarioVerifier {
    fn default() -> Self {
        Self::new()
    }
}
