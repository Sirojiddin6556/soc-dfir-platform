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
