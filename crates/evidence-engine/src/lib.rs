#![forbid(unsafe_code)]

use core_domain::epistemic::Confidence;
use core_domain::evidence::{Evidence, EvidenceMember};
use core_domain::fact::Fact;
use core_domain::id::EntityId;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EvidenceError {
    #[error("Empty evidence set")]
    EmptyEvidence,
}

pub struct EvidenceEngine;

impl EvidenceEngine {
    pub fn new() -> Self {
        Self
    }

    /// Aggregates related facts into an Evidence unit supporting an attack finding
    pub fn aggregate_facts(
        &self,
        case_id: EntityId,
        title: &str,
        description: &str,
        facts: &[&Fact],
    ) -> Result<Evidence, EvidenceError> {
        if facts.is_empty() {
            return Err(EvidenceError::EmptyEvidence);
        }

        let members: Vec<EvidenceMember> = facts
            .iter()
            .map(|f| EvidenceMember {
                fact_id: f.id,
                relevance_score: 1.0,
            })
            .collect();

        let avg_confidence =
            facts.iter().map(|f| f.confidence.value()).sum::<f32>() / (facts.len() as f32);

        Ok(Evidence {
            id: EntityId::new_v7(),
            case_id,
            title: title.to_string(),
            description: description.to_string(),
            confidence: Confidence::new(avg_confidence),
            evidence_strength: 1.0,
            members,
            created_at: chrono::Utc::now(),
        })
    }
}

impl Default for EvidenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::epistemic::{AssertionType, Severity, VerificationState};
    use core_domain::fact::EntityType;

    #[test]
    fn test_evidence_aggregation() {
        let engine = EvidenceEngine::new();
        let case_id = EntityId::new_v7();

        let fact1 = Fact {
            id: EntityId::new_v7(),
            case_id,
            observation_id: None,
            assertion_type: AssertionType::Fact,
            verification_state: VerificationState::Confirmed,
            entity_type: EntityType::Process,
            entity_key: "p1".to_string(),
            fact_type: "Spawn".to_string(),
            confidence: Confidence::new(0.9),
            severity: Severity::High,
            risk_score: 50.0,
            evidence_strength: 1.0,
            pain_level: None,
            data: serde_json::Value::Null,
            created_at: chrono::Utc::now(),
        };

        let fact2 = Fact {
            id: EntityId::new_v7(),
            case_id,
            observation_id: None,
            assertion_type: AssertionType::Fact,
            verification_state: VerificationState::Confirmed,
            entity_type: EntityType::Process,
            entity_key: "p2".to_string(),
            fact_type: "Access".to_string(),
            confidence: Confidence::new(1.0),
            severity: Severity::Critical,
            risk_score: 90.0,
            evidence_strength: 1.0,
            pain_level: None,
            data: serde_json::Value::Null,
            created_at: chrono::Utc::now(),
        };

        let evidence = engine
            .aggregate_facts(
                case_id,
                "Cred Dump Evidence",
                "LSASS access detected",
                &[&fact1, &fact2],
            )
            .unwrap();
        assert_eq!(evidence.members.len(), 2);
        assert!((evidence.confidence.value() - 0.95).abs() < 0.001);
    }
}
