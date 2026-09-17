#![forbid(unsafe_code)]

use core_domain::epistemic::{Confidence, VerificationState};
use core_domain::evidence::Evidence;
use core_domain::fact::Fact;
use core_domain::taxonomy::{TaxonomyCandidate, TaxonomyNamespace, TaxonomyVersion};

pub struct TaxonomyProjector;

impl TaxonomyProjector {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates facts and evidence against a specific versioned taxonomy.
    /// Emits candidates rather than unconditionally confirming techniques.
    pub fn project_candidates(
        &self,
        facts: &[Fact],
        _evidence: &[Evidence],
        taxonomy: &TaxonomyVersion,
    ) -> Vec<TaxonomyCandidate> {
        let mut candidates = Vec::new();

        if taxonomy.namespace == TaxonomyNamespace::MitreAttackEnterprise {
            for fact in facts {
                if let Some(cmd) = fact.data.get("command_line").and_then(|c| c.as_str()) {
                    if cmd.contains("powershell") {
                        candidates.push(TaxonomyCandidate {
                            technique_id: "T1059.001".to_string(), // PowerShell
                            tactic: Some("Execution".to_string()),
                            confidence: Confidence::new(0.95),
                            verification_state: VerificationState::Corroborated,
                            evidence_id: None,
                            mapping_rule_version: "v1.0.0".to_string(),
                        });
                    }
                    if cmd.contains("whoami") || cmd.contains("net user") {
                        candidates.push(TaxonomyCandidate {
                            technique_id: "T1033".to_string(), // System Owner/User Discovery
                            tactic: Some("Discovery".to_string()),
                            confidence: Confidence::new(0.90),
                            verification_state: VerificationState::Candidate,
                            evidence_id: None,
                            mapping_rule_version: "v1.0.0".to_string(),
                        });
                    }
                }
            }
        }

        candidates
    }
}

impl Default for TaxonomyProjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::epistemic::{AssertionType, Severity};
    use core_domain::fact::EntityType;
    use core_domain::id::EntityId;

    #[test]
    fn test_taxonomy_candidate_projection() {
        let projector = TaxonomyProjector::new();
        let taxonomy = TaxonomyVersion {
            id: "mitre-v14.1".to_string(),
            namespace: TaxonomyNamespace::MitreAttackEnterprise,
            version: "v14.1".to_string(),
            release_date: "2023-10-31".to_string(),
            source_hash: "sha256:abcd".to_string(),
            imported_at: chrono::Utc::now(),
        };

        let fact = Fact {
            id: EntityId::new_v7(),
            case_id: EntityId::new_v7(),
            observation_id: None,
            assertion_type: AssertionType::Fact,
            verification_state: VerificationState::Confirmed,
            entity_type: EntityType::Process,
            entity_key: "powershell.exe:1234".to_string(),
            fact_type: "ProcessExecution".to_string(),
            confidence: Confidence::new(1.0),
            severity: Severity::High,
            risk_score: 80.0,
            evidence_strength: 1.0,
            pain_level: None,
            data: serde_json::json!({"command_line": "powershell.exe -NoP -enc AAAA"}),
            created_at: chrono::Utc::now(),
        };

        let candidates = projector.project_candidates(&[fact], &[], &taxonomy);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].technique_id, "T1059.001");
        assert_eq!(candidates[0].tactic, Some("Execution".to_string()));
    }
}
