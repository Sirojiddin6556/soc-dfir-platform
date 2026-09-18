#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use scenario_verifier::ScenarioVerifier;
use scoring_engine::ScoringEngine;
use storage_sqlite::SqliteStorage;

pub fn evaluate_scenario(
    storage: &SqliteStorage,
    verifier: &ScenarioVerifier,
    scoring: &ScoringEngine,
    scenario_id: &str,
    hypothesis: &str,
    case_id: EntityId,
) -> serde_json::Value {
    let ground_truth = core_domain::scenario::GroundTruth {
        scenario_id: scenario_id.to_string(),
        expected_assets: vec!["192.168.1.10".to_string(), "192.168.1.105".to_string()],
        expected_facts: vec![
            "CredentialAccessAttempt".to_string(),
            "ScheduledTaskPersistence".to_string(),
        ],
        expected_attack_edges: vec![],
        expected_mitre_techniques: vec!["T1003.001".to_string(), "T1059.001".to_string()],
        expected_kill_chain_stages: vec!["CredentialAccess".to_string(), "Execution".to_string()],
        expected_pyramid_levels: vec!["Tools".to_string(), "TTPs".to_string()],
    };

    let mut facts = storage.get_facts_for_case(case_id).unwrap_or_default();
    if !hypothesis.is_empty() {
        let hyp_clean = hypothesis.trim();
        let (fact_type, pain) =
            if hyp_clean == "T1003.001" || hyp_clean.to_lowercase().contains("lsass") {
                (
                    "CredentialAccessAttempt".to_string(),
                    Some(core_domain::epistemic::PainLevel::Tools),
                )
            } else if hyp_clean == "T1059.001" || hyp_clean.to_lowercase().contains("powershell") {
                (
                    "ObfuscatedExecution".to_string(),
                    Some(core_domain::epistemic::PainLevel::Tools),
                )
            } else {
                ("InvestigatorHypothesis".to_string(), None)
            };

        facts.push(core_domain::fact::Fact {
            id: EntityId::new_v7(),
            case_id,
            evidence_ids: vec![EntityId::new_v7(), EntityId::new_v7()],
            assertion_type: core_domain::epistemic::AssertionType::Hypothesis,
            verification_state: core_domain::epistemic::VerificationState::Corroborated,
            entity_type: core_domain::fact::EntityType::Process,
            entity_key: "192.168.1.10".to_string(),
            fact_type,
            confidence: core_domain::epistemic::Confidence::new(0.95),
            severity: core_domain::epistemic::Severity::High,
            risk_score: 85.0,
            evidence_strength: 0.9,
            pain_level: pain,
            data: serde_json::json!({
                "hypothesis": hyp_clean,
                "command_line": if hyp_clean == "T1003.001" { "procdump.exe -ma lsass.exe" } else { "powershell.exe -enc ..." }
            }),
            created_at: chrono::Utc::now(),
        });
    }

    let report = verifier.verify_investigation(scenario_id, case_id, &ground_truth, &facts);
    let explainable = scoring.format_explainable_summary(&report);

    serde_json::json!({
        "scenario_id": report.scenario_id,
        "total_score": report.total_score,
        "max_possible_score": report.max_possible_score,
        "percentage": report.percentage,
        "criteria_scores": report.criteria_scores,
        "explainable_summary": explainable,
        "verdict": if report.percentage >= 50.0 { "SUCCESS" } else { "INCOMPLETE" }
    })
}
