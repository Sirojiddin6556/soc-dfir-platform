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

        let avg_confidence = facts
            .iter()
            .map(|f| f.confidence.value())
            .sum::<f32>()
            / (facts.len() as f32);

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
