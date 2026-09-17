#![forbid(unsafe_code)]

use core_domain::epistemic::{AssertionType, Confidence, Severity, VerificationState};
use core_domain::fact::{EntityType, Fact};
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CorrelationError {
    #[error("Rule evaluation failed: {0}")]
    EvaluationError(String),
}

pub struct DeterministicCorrelationEngine;

impl DeterministicCorrelationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates observations and derives verified security facts
    pub fn correlate(&self, observations: &[Observation]) -> Result<Vec<Fact>, CorrelationError> {
        let mut facts = Vec::new();

        for obs in observations {
            // Process creation heuristic
            if let Some(cmd) = obs.data.get("command_line").and_then(|c| c.as_str()) {
                let is_suspicious = cmd.contains("-enc") || cmd.contains("mimikatz") || cmd.contains("whoami");
                let severity = if is_suspicious { Severity::High } else { Severity::Info };
                let risk_score = if is_suspicious { 80.0 } else { 10.0 };

                facts.push(Fact {
                    id: EntityId::new_v7(),
                    case_id: obs.case_id,
                    observation_id: Some(obs.id),
                    assertion_type: AssertionType::Fact,
                    verification_state: VerificationState::Corroborated,
                    entity_type: EntityType::Process,
                    entity_key: format!("proc:{}", obs.id),
                    fact_type: "ProcessExecution".to_string(),
                    confidence: Confidence::new(1.0),
                    severity,
                    risk_score,
                    evidence_strength: 1.0,
                    pain_level: Some(core_domain::PainLevel::Tools),
                    data: obs.data.clone(),
                    created_at: chrono::Utc::now(),
                });
            }
        }

        Ok(facts)
    }
}

impl Default for DeterministicCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}
