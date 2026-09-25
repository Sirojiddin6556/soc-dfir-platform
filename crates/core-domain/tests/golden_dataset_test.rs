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
use tool_adapters::{EvtxJsonExportAdapter, ToolAdapter};

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
    let fake_evtx_path = temp_dir.join("security.jsonl");
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    tokio::fs::write(&fake_evtx_path, raw_log_data)
        .await
        .unwrap();

    let adapter = EvtxJsonExportAdapter;
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
    assert_eq!(report.total_score, 130);
    assert_eq!(report.percentage, 100.0);

    let scoring = ScoringEngine::new();
    let summary = scoring.format_explainable_summary(&report);
    assert!(summary.contains("Discovered 2/2 required assets"));

    // Cleanup temp
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_end_to_end_binary_pcap_and_evtx_forensic_pipeline() {
    let temp_dir =
        std::env::temp_dir().join(format!("binary_forensic_test_{}", EntityId::new_v7()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let cas = ContentAddressedStorage::new(temp_dir.join("cas"));
    let sqlite = SqliteStorage::open_in_memory().unwrap();
    let case_id = EntityId::new_v7();
    sqlite
        .insert_case(
            case_id,
            "Forensic Binary Validation",
            Some("PCAP + EVTX binary test"),
        )
        .unwrap();

    // 1. Build & Ingest Real Binary PCAP
    let mut pcap_buf = Vec::new();
    pcap_buf.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes()); // magic
    pcap_buf.extend_from_slice(&2u16.to_ne_bytes()); // major
    pcap_buf.extend_from_slice(&4u16.to_ne_bytes()); // minor
    pcap_buf.extend_from_slice(&0i32.to_ne_bytes()); // thiszone
    pcap_buf.extend_from_slice(&0u32.to_ne_bytes()); // sigfigs
    pcap_buf.extend_from_slice(&65535u32.to_ne_bytes()); // snaplen
    pcap_buf.extend_from_slice(&1u32.to_ne_bytes()); // linktype = Ethernet

    let pkt_len = 54u32;
    pcap_buf.extend_from_slice(&1720000000u32.to_ne_bytes());
    pcap_buf.extend_from_slice(&500u32.to_ne_bytes());
    pcap_buf.extend_from_slice(&pkt_len.to_ne_bytes());
    pcap_buf.extend_from_slice(&pkt_len.to_ne_bytes());
    pcap_buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
    pcap_buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
    pcap_buf.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
    pcap_buf.push(0x45);
    pcap_buf.push(0x00);
    pcap_buf.extend_from_slice(&40u16.to_be_bytes());
    pcap_buf.extend_from_slice(&5678u16.to_be_bytes());
    pcap_buf.extend_from_slice(&0u16.to_be_bytes());
    pcap_buf.push(64);
    pcap_buf.push(6); // TCP
    pcap_buf.extend_from_slice(&0u16.to_be_bytes());
    pcap_buf.extend_from_slice(&[192, 168, 1, 50]); // src ip
    pcap_buf.extend_from_slice(&[10, 0, 0, 80]); // dst ip
    pcap_buf.extend_from_slice(&51515u16.to_be_bytes()); // src port
    pcap_buf.extend_from_slice(&80u16.to_be_bytes()); // dst port (HTTP)
    pcap_buf.extend_from_slice(&200000u32.to_be_bytes());
    pcap_buf.extend_from_slice(&0u32.to_be_bytes());
    pcap_buf.push(0x50);
    pcap_buf.push(0x02); // SYN
    pcap_buf.extend_from_slice(&64240u16.to_be_bytes());
    pcap_buf.extend_from_slice(&0u16.to_be_bytes());
    pcap_buf.extend_from_slice(&0u16.to_be_bytes());

    let pcap_file = temp_dir.join("traffic.pcap");
    tokio::fs::write(&pcap_file, &pcap_buf).await.unwrap();

    let pcap_cas = cas.store_bytes(&pcap_buf).await.unwrap();
    assert!(!pcap_cas.blake3.is_empty());

    let pcap_adapter = tool_adapters::PcapAdapter;
    let pcap_result = pcap_adapter.parse_artifact(&pcap_file).await.unwrap();
    assert_eq!(pcap_result.exit_code, 0);

    let summary: tool_adapters::pcap::phase3::PcapParseResult =
        serde_json::from_slice(&pcap_result.stdout_bytes).unwrap();
    assert_eq!(summary.packets_seen, 1);
    assert_eq!(summary.packets_decoded, 1);

    // The adapter's production output is a bounded summary. Use the explicit
    // collection API for packet-level assertions instead of making the
    // streaming adapter retain every packet in memory.
    let parsed_packets = tool_adapters::pcap::phase3::parse_capture_collect(&pcap_file).unwrap();
    assert_eq!(parsed_packets.len(), 1);
    assert_eq!(parsed_packets[0].src_ip.as_deref(), Some("192.168.1.50"));
    assert_eq!(parsed_packets[0].dst_ip.as_deref(), Some("10.0.0.80"));
    assert_eq!(parsed_packets[0].protocol.as_deref(), Some("TCP"));
    assert_eq!(parsed_packets[0].dst_port, Some(80));

    // Cleanup temp
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
