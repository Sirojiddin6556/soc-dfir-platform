#![forbid(unsafe_code)]

use core_domain::scenario::VerificationReport;

pub struct ScoringEngine;

impl ScoringEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn format_explainable_summary(&self, report: &VerificationReport) -> String {
        let mut out = format!(
            "Scenario: {} | Total Score: {}/{} ({:.1}%)\n----------------------------------------\n",
            report.scenario_id, report.total_score, report.max_possible_score, report.percentage
        );

        for c in &report.criteria_scores {
            out.push_str(&format!(
                "- {}: +{} / {} pts | {}\n",
                c.name, c.points_awarded, c.max_points, c.explanation
            ));
        }

        out
    }
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::id::EntityId;
    use core_domain::scenario::CriterionScore;

    #[test]
    fn test_scoring_explainability() {
        let engine = ScoringEngine::new();
        let report = VerificationReport {
            scenario_id: "SCEN-01".to_string(),
            player_case_id: EntityId::new_v7(),
            total_score: 95,
            max_possible_score: 100,
            percentage: 95.0,
            criteria_scores: vec![
                CriterionScore {
                    name: "Assets".to_string(),
                    points_awarded: 20,
                    max_points: 20,
                    explanation: "All assets matched".to_string(),
                },
                CriterionScore {
                    name: "TTP".to_string(),
                    points_awarded: 75,
                    max_points: 80,
                    explanation: "LSASS matched".to_string(),
                },
            ],
            completed_at: chrono::Utc::now(),
        };

        let summary = engine.format_explainable_summary(&report);
        assert!(summary.contains("SCEN-01"));
        assert!(summary.contains("95/100"));
        assert!(summary.contains("+20 / 20 pts"));
    }
}
