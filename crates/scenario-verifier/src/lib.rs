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

        // 1. Assets Discovered Check (Coverage)
        let player_assets: HashSet<String> =
            player_facts.iter().map(|f| f.entity_key.clone()).collect();

        if !ground_truth.expected_assets.is_empty() {
            let mut matched_assets = 0;
            for expected in &ground_truth.expected_assets {
                if player_assets.contains(expected) {
                    matched_assets += 1;
                }
            }
            let asset_pts = matched_assets * 20;
            let asset_max = (ground_truth.expected_assets.len() * 20) as u32;
            criteria_scores.push(CriterionScore {
                name: "Assets Discovered (Coverage)".to_string(),
                points_awarded: asset_pts as u32,
                max_points: asset_max,
                explanation: format!(
                    "Discovered {}/{} required assets",
                    matched_assets,
                    ground_truth.expected_assets.len()
                ),
            });
            total_score += asset_pts as u32;
            max_possible += asset_max;
        }

        // 2. Fact Detection Correctness
        if !ground_truth.expected_facts.is_empty() {
            let mut matched_facts = 0;
            for expected in &ground_truth.expected_facts {
                let exp_lower = expected.to_lowercase();
                let matched = player_facts.iter().any(|f| {
                    let ft_lower = f.fact_type.to_lowercase();
                    ft_lower.contains(&exp_lower)
                        || (exp_lower == "processexecution"
                            && (f.fact_type.contains("Execution")
                                || f.fact_type.contains("Process")
                                || f.fact_type.contains("Dump")))
                        || (exp_lower == "lsass_dump"
                            && (f.fact_type.contains("Credential")
                                || f.data.to_string().to_lowercase().contains("lsass")))
                });
                if matched {
                    matched_facts += 1;
                }
            }
            let fact_pts = matched_facts * 20;
            let fact_max = (ground_truth.expected_facts.len() * 20) as u32;
            criteria_scores.push(CriterionScore {
                name: "Fact Detection (Correctness)".to_string(),
                points_awarded: fact_pts as u32,
                max_points: fact_max,
                explanation: format!(
                    "Identified {}/{} expected security facts",
                    matched_facts,
                    ground_truth.expected_facts.len()
                ),
            });
            total_score += fact_pts as u32;
            max_possible += fact_max;
        }

        // 3. Evidence Quality & Provenance
        if !player_facts.is_empty() {
            let with_evidence = player_facts
                .iter()
                .filter(|f| !f.evidence_ids.is_empty() && f.evidence_strength > 0.0)
                .count();
            let quality_pts =
                ((with_evidence as f32 / player_facts.len() as f32) * 20.0).round() as u32;
            criteria_scores.push(CriterionScore {
                name: "Evidence Quality (Provenance)".to_string(),
                points_awarded: quality_pts,
                max_points: 20,
                explanation: format!(
                    "{}/{} facts backed by cryptographic evidence provenance",
                    with_evidence,
                    player_facts.len()
                ),
            });
            total_score += quality_pts;
            max_possible += 20;
        }

        // 4. MITRE ATT&CK Mapping Accuracy
        if !ground_truth.expected_mitre_techniques.is_empty() {
            let mut matched_techniques = 0;
            for tech in &ground_truth.expected_mitre_techniques {
                let tech_matched = player_facts.iter().any(|f| {
                    let s = f.data.to_string().to_lowercase();
                    match tech.as_str() {
                        "T1003.001" | "T1003" => {
                            s.contains("lsass") || s.contains("procdump") || s.contains("mimikatz")
                        }
                        "T1059.001" | "T1059" => s.contains("powershell") || s.contains("-enc"),
                        "T1033" => s.contains("whoami") || s.contains("net user"),
                        "T1053.005" | "T1053" => s.contains("schtasks"),
                        _ => s.contains(&tech.to_lowercase()),
                    }
                });
                if tech_matched {
                    matched_techniques += 1;
                }
            }
            let mitre_pts = matched_techniques * 20;
            let mitre_max = (ground_truth.expected_mitre_techniques.len() * 20) as u32;
            criteria_scores.push(CriterionScore {
                name: "ATT&CK Mapping (Accuracy)".to_string(),
                points_awarded: mitre_pts as u32,
                max_points: mitre_max,
                explanation: format!(
                    "Mapped {}/{} required ATT&CK techniques",
                    matched_techniques,
                    ground_truth.expected_mitre_techniques.len()
                ),
            });
            total_score += mitre_pts as u32;
            max_possible += mitre_max;
        }

        // 5. Attack Graph Edges Reconstruction
        if !ground_truth.expected_attack_edges.is_empty() {
            let edge_max = (ground_truth.expected_attack_edges.len() * 20) as u32;
            // Evaluates presence of entities that connect the edge
            let mut matched_edges = 0;
            for (src, tgt, _rel) in &ground_truth.expected_attack_edges {
                if player_assets.contains(src) && player_assets.contains(tgt) {
                    matched_edges += 1;
                }
            }
            let edge_pts = matched_edges * 20;
            criteria_scores.push(CriterionScore {
                name: "Attack Graph (Edge Provenance)".to_string(),
                points_awarded: edge_pts as u32,
                max_points: edge_max,
                explanation: format!(
                    "Reconstructed {}/{} attack graph edges",
                    matched_edges,
                    ground_truth.expected_attack_edges.len()
                ),
            });
            total_score += edge_pts as u32;
            max_possible += edge_max;
        }

        // 6. Kill Chain Stage Progression
        if !ground_truth.expected_kill_chain_stages.is_empty() {
            let mut matched_stages = 0;
            for stage in &ground_truth.expected_kill_chain_stages {
                let stage_lower = stage.to_lowercase();
                let matched = player_facts.iter().any(|f| {
                    let ft = f.fact_type.to_lowercase();
                    let s = f.data.to_string().to_lowercase();
                    match stage_lower.as_str() {
                        "execution" => ft.contains("execution") || s.contains("powershell"),
                        "credentialaccess" => {
                            ft.contains("credential")
                                || s.contains("lsass")
                                || s.contains("mimikatz")
                        }
                        "discovery" => ft.contains("discovery") || s.contains("whoami"),
                        "persistence" => ft.contains("persist") || s.contains("schtasks"),
                        _ => ft.contains(&stage_lower) || s.contains(&stage_lower),
                    }
                });
                if matched {
                    matched_stages += 1;
                }
            }
            let stage_pts = matched_stages * 15;
            let stage_max = (ground_truth.expected_kill_chain_stages.len() * 15) as u32;
            criteria_scores.push(CriterionScore {
                name: "Kill Chain Progression".to_string(),
                points_awarded: stage_pts as u32,
                max_points: stage_max,
                explanation: format!(
                    "Traced {}/{} Kill Chain attack stages",
                    matched_stages,
                    ground_truth.expected_kill_chain_stages.len()
                ),
            });
            total_score += stage_pts as u32;
            max_possible += stage_max;
        }

        // 7. Pyramid of Pain Depth
        if !ground_truth.expected_pyramid_levels.is_empty() {
            let mut matched_pain = 0;
            for level in &ground_truth.expected_pyramid_levels {
                let level_lower = level.to_lowercase();
                let matched = player_facts.iter().any(|f| {
                    if let Some(p) = f.pain_level {
                        format!("{:?}", p).to_lowercase() == level_lower
                    } else {
                        false
                    }
                });
                if matched {
                    matched_pain += 1;
                }
            }
            let pain_pts = matched_pain * 15;
            let pain_max = (ground_truth.expected_pyramid_levels.len() * 15) as u32;
            criteria_scores.push(CriterionScore {
                name: "Pyramid of Pain (Depth)".to_string(),
                points_awarded: pain_pts as u32,
                max_points: pain_max,
                explanation: format!(
                    "Attained {}/{} required indicator depths",
                    matched_pain,
                    ground_truth.expected_pyramid_levels.len()
                ),
            });
            total_score += pain_pts as u32;
            max_possible += pain_max;
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::epistemic::{
        AssertionType, Confidence, PainLevel, Severity, VerificationState,
    };
    use core_domain::fact::{EntityType, Fact};

    #[test]
    fn test_scenario_verifier_matching() {
        let verifier = ScenarioVerifier::new();
        let ground_truth = GroundTruth {
            scenario_id: "SCEN-APT29".to_string(),
            expected_assets: vec!["192.168.1.100".to_string(), "192.168.1.105".to_string()],
            expected_facts: vec!["LSASS_Dump".to_string()],
            expected_attack_edges: vec![],
            expected_mitre_techniques: vec!["T1003.001".to_string()],
            expected_kill_chain_stages: vec!["CredentialAccess".to_string()],
            expected_pyramid_levels: vec!["Tools".to_string()],
        };

        let case_id = EntityId::new_v7();
        let facts = vec![Fact {
            id: EntityId::new_v7(),
            case_id,
            evidence_ids: vec![EntityId::new_v7()],
            assertion_type: AssertionType::Fact,
            verification_state: VerificationState::Confirmed,
            entity_type: EntityType::Host,
            entity_key: "192.168.1.100".to_string(),
            fact_type: "HostDiscovered".to_string(),
            confidence: Confidence::new(1.0),
            severity: Severity::Info,
            risk_score: 10.0,
            evidence_strength: 1.0,
            pain_level: None,
            data: serde_json::Value::Null,
            created_at: chrono::Utc::now(),
        }];

        let report = verifier.verify_investigation("SCEN-APT29", case_id, &ground_truth, &facts);
        assert_eq!(report.scenario_id, "SCEN-APT29");
        assert_eq!(
            report.criteria_scores[0].name,
            "Assets Discovered (Coverage)"
        );
        assert_eq!(report.criteria_scores[0].points_awarded, 20); // 1 out of 2 assets = 20 pts
        assert_eq!(report.criteria_scores[0].max_points, 40);
        assert_eq!(report.criteria_scores.len(), 6);
        assert!(report.percentage > 0.0);

        // Full match test
        let full_facts = vec![
            Fact {
                id: EntityId::new_v7(),
                case_id,
                evidence_ids: vec![EntityId::new_v7(), EntityId::new_v7()],
                assertion_type: AssertionType::Fact,
                verification_state: VerificationState::Confirmed,
                entity_type: EntityType::Host,
                entity_key: "192.168.1.100".to_string(),
                fact_type: "HostDiscovered".to_string(),
                confidence: Confidence::new(1.0),
                severity: Severity::Info,
                risk_score: 10.0,
                evidence_strength: 1.0,
                pain_level: None,
                data: serde_json::Value::Null,
                created_at: chrono::Utc::now(),
            },
            Fact {
                id: EntityId::new_v7(),
                case_id,
                evidence_ids: vec![EntityId::new_v7(), EntityId::new_v7()],
                assertion_type: AssertionType::Fact,
                verification_state: VerificationState::Confirmed,
                entity_type: EntityType::Host,
                entity_key: "192.168.1.105".to_string(),
                fact_type: "CredentialAccessAttempt".to_string(),
                confidence: Confidence::new(1.0),
                severity: Severity::Critical,
                risk_score: 95.0,
                evidence_strength: 1.0,
                pain_level: Some(PainLevel::Tools),
                data: serde_json::json!({"command_line": "mimikatz.exe sekurlsa::logonpasswords"}),
                created_at: chrono::Utc::now(),
            },
        ];

        let full_report =
            verifier.verify_investigation("SCEN-APT29", case_id, &ground_truth, &full_facts);
        assert_eq!(full_report.percentage, 100.0);
    }
}
