use correlation_engine::DeterministicCorrelationEngine;
use diagram_engine::{DiagramEngine, NodeShape};
use evidence_engine::EvidenceEngine;
use graph_engine::DeterministicGraphEngine;
use normalization_engine::{GenericLogNormalizer, Normalizer};
use scenario_verifier::ScenarioVerifier;
use scoring_engine::ScoringEngine;
use storage_cas::ContentAddressedStorage;
use storage_sqlite::SqliteStorage;
use taxonomy_projection::TaxonomyProjector;
use tool_adapters::{EvtxAdapter, ToolAdapter};

use core_domain::id::EntityId;
use core_domain::observation::RawToolResult;
use core_domain::scenario::GroundTruth;
use core_domain::taxonomy::{TaxonomyNamespace, TaxonomyVersion};

#[tokio::test]
async fn test_end_to_end_golden_dataset_pipeline() {
    let temp_dir = std::env::temp_dir().join(format!("dfir_golden_{}", uuid::Uuid::now_v7()));
    let cas = ContentAddressedStorage::new(temp_dir.join("cas"));
    let sqlite = SqliteStorage::open_in_memory().unwrap();

    let case_id = EntityId::new_v7();
    sqlite
        .insert_case(
            case_id,
            "Scenario 01: APT Lateral Movement",
            Some("Golden test run"),
        )
        .unwrap();

    // 1. Ingest Simulated EVTX Raw Log into CAS
    let raw_log_data = br#"{"event_id": 4688, "command_line": "powershell.exe -enc SQBFAFgA...", "host_ip": "10.0.0.15"}
{"event_id": 4688, "command_line": "whoami /all", "host_ip": "10.0.0.15"}"#;

    let cas_record = cas.store_bytes(raw_log_data).await.unwrap();
    assert!(!cas_record.blake3.is_empty());
    assert!(!cas_record.sha256.is_empty());

    // 2. Tool Adapter -> RawToolResult
    let fake_evtx_path = temp_dir.join("security.evtx");
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    tokio::fs::write(&fake_evtx_path, raw_log_data)
        .await
        .unwrap();

    let adapter = EvtxAdapter;
    let raw_tool_result: RawToolResult = adapter.parse_artifact(&fake_evtx_path).await.unwrap();
    assert_eq!(raw_tool_result.exit_code, 0);

    // 3. Normalizer -> Observations
    let normalizer = GenericLogNormalizer;
    let observations = normalizer.normalize(case_id, &raw_tool_result).unwrap();
    assert_eq!(observations.len(), 2);

    // 4. Correlation Engine -> Facts
    let correlation = DeterministicCorrelationEngine::new();
    let facts = correlation.correlate(&observations).unwrap();
    assert_eq!(facts.len(), 2);
    for f in &facts {
        sqlite.insert_fact(f).unwrap();
    }

    // 5. Evidence Engine -> Evidence
    let evidence_engine = EvidenceEngine::new();
    let fact_refs: Vec<&core_domain::fact::Fact> = facts.iter().collect();
    let evidence = evidence_engine
        .aggregate_facts(
            case_id,
            "PowerShell Recon Activity",
            "Detected encoded execution and user recon",
            &fact_refs,
        )
        .unwrap();
    assert_eq!(evidence.members.len(), 2);

    // 6. Graph Engine -> Attack Graph (Event-Derived with Provenance)
    let graph_engine = DeterministicGraphEngine::new();
    let attack_graph = graph_engine.build_graph_from_facts(case_id, &facts);
    assert!(!attack_graph.nodes.is_empty());
    assert!(!attack_graph.edges.is_empty());

    // Verify Explainability Invariant: every edge has supporting fact IDs
    for edge in &attack_graph.edges {
        assert!(
            !edge.supported_by.is_empty(),
            "Attack edge must have provenance facts"
        );
    }

    // 7. Taxonomy Projection -> Candidates
    let taxonomy_projector = TaxonomyProjector::new();
    let mitre_v14 = TaxonomyVersion {
        id: "mitre-enterprise-v14".to_string(),
        namespace: TaxonomyNamespace::MitreAttackEnterprise,
        version: "v14.1".to_string(),
        release_date: "2024-04-15".to_string(),
        source_hash: "sha256:abc123...".to_string(),
        imported_at: chrono::Utc::now(),
    };

    let candidates =
        taxonomy_projector.project_candidates(&facts, std::slice::from_ref(&evidence), &mitre_v14);
    assert!(candidates.iter().any(|c| c.technique_id == "T1059.001"));
    assert!(candidates.iter().any(|c| c.technique_id == "T1033"));

    // 8. Diagram Engine -> Visual Projections (NFR-UX-002 Shape Encoding)
    let diagram_engine = DiagramEngine::new();
    let diagram = diagram_engine.project_attack_graph(&attack_graph);
    assert_eq!(diagram.nodes.len(), attack_graph.nodes.len());
    assert!(diagram.nodes.iter().any(|n| n.shape == NodeShape::Hexagon)); // Process shape
    assert!(diagram.nodes.iter().any(|n| n.shape == NodeShape::Circle)); // Host shape

    // 9. Scenario Verifier (Ground Truth Isolation) & Scoring Engine
    let ground_truth = GroundTruth {
        scenario_id: "SCEN-APT-01".to_string(),
        expected_assets: vec![facts[0].entity_key.clone(), facts[1].entity_key.clone()],
        expected_facts: vec!["ProcessExecution".to_string()],
        expected_attack_edges: vec![],
        expected_mitre_techniques: vec!["T1059.001".to_string()],
        expected_kill_chain_stages: vec!["Execution".to_string()],
        expected_pyramid_levels: vec!["Tools".to_string()],
    };

    let verifier = ScenarioVerifier::new();
    let report = verifier.verify_investigation("SCEN-APT-01", case_id, &ground_truth, &facts);
    assert_eq!(report.total_score, 40);
    assert_eq!(report.percentage, 100.0);

    let scoring = ScoringEngine::new();
    let summary = scoring.format_explainable_summary(&report);
    assert!(summary.contains("Discovered 2/2 required assets"));

    // Cleanup temp
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
