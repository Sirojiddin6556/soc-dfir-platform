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
