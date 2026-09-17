#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use core_domain::fact::Fact;
use core_domain::id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineLane {
    pub lane_id: String,
    pub title: String,
    pub host_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub fact_id: EntityId,
    pub timestamp: DateTime<Utc>,
    pub lane_id: String,
    pub label: String,
    pub severity: core_domain::Severity,
}

pub struct TimelineEngine;

impl TimelineEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn build_timeline(&self, facts: &[Fact]) -> Vec<TimelineEntry> {
        let mut entries: Vec<TimelineEntry> = facts
            .iter()
            .map(|f| {
                let lane_id = f
                    .data
                    .get("host_ip")
                    .and_then(|h| h.as_str())
                    .unwrap_or("General")
                    .to_string();

                TimelineEntry {
                    fact_id: f.id,
                    timestamp: f.created_at,
                    lane_id,
                    label: format!("{}: {}", f.fact_type, f.entity_key),
                    severity: f.severity,
                }
            })
            .collect();

        entries.sort_by_key(|e| e.timestamp);
        entries
    }
}

impl Default for TimelineEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::epistemic::{AssertionType, Confidence, Severity, VerificationState};
    use core_domain::fact::EntityType;

    #[test]
    fn test_timeline_sorting_and_lanes() {
        let engine = TimelineEngine::new();
        let case_id = EntityId::new_v7();
        let now = Utc::now();

        let facts = vec![
            Fact {
                id: EntityId::new_v7(),
                case_id,
                evidence_ids: vec![EntityId::new_v7()],
                assertion_type: AssertionType::Fact,
                verification_state: VerificationState::Confirmed,
                entity_type: EntityType::Process,
                entity_key: "proc2".to_string(),
                fact_type: "Exec".to_string(),
                confidence: Confidence::new(1.0),
                severity: Severity::High,
                risk_score: 50.0,
                evidence_strength: 1.0,
                pain_level: None,
                data: serde_json::json!({"host_ip": "10.0.0.1"}),
                created_at: now + chrono::Duration::seconds(10),
            },
            Fact {
                id: EntityId::new_v7(),
                case_id,
                evidence_ids: vec![EntityId::new_v7()],
                assertion_type: AssertionType::Fact,
                verification_state: VerificationState::Confirmed,
                entity_type: EntityType::Process,
                entity_key: "proc1".to_string(),
                fact_type: "Exec".to_string(),
                confidence: Confidence::new(1.0),
                severity: Severity::Low,
                risk_score: 10.0,
                evidence_strength: 1.0,
                pain_level: None,
                data: serde_json::json!({"host_ip": "10.0.0.1"}),
                created_at: now,
            },
        ];

        let entries = engine.build_timeline(&facts);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].label, "Exec: proc1");
        assert_eq!(entries[1].label, "Exec: proc2");
        assert_eq!(entries[0].lane_id, "10.0.0.1");
    }
}
