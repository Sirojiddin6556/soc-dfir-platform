use engine_server::EngineApp;
use std::sync::Arc;

#[tokio::test]
async fn test_engine_app_composition_and_dispatch() {
    let temp_dir = std::env::temp_dir().join(format!("engine_test_{}", uuid::Uuid::now_v7()));
    let app = Arc::new(EngineApp::new_in_memory(temp_dir.clone()));

    // 1. Test Health Probe
    let health_req =
        r#"{"api_version": 1, "request_id": "req-1", "method": "health", "params": {}}"#;
    let health_resp = app.dispatch_request(health_req).await;
    assert!(health_resp.contains("\"live\":true"));

    // 2. Test Case Creation
    let case_req = r#"{"api_version": 1, "request_id": "req-2", "method": "cases.create", "params": {"title": "Incident Beta", "description": "Automated test"}}"#;
    let case_resp = app.dispatch_request(case_req).await;
    assert!(case_resp.contains("\"case_id\""));
    assert!(case_resp.contains("\"status\":\"Active\""));

    // 3. Test Cases List
    let list_req =
        r#"{"api_version": 1, "request_id": "req-3", "method": "cases.list", "params": {}}"#;
    let list_resp = app.dispatch_request(list_req).await;
    assert!(list_resp.contains("Incident Beta"));

    // 4. Test Broker Execute (Authorized: ReadProcesses)
    let broker_req = r#"{"api_version": 1, "request_id": "req-4", "method": "broker.execute", "params": {"CollectProcessMetadata": {"pid": 1234}}}"#;
    let broker_resp = app.dispatch_request(broker_req).await;
    assert!(broker_resp.contains("\"status\":\"running\""));

    // 5. Test Broker Execute (Forbidden: AcquireMemorySample without capability)
    let mem_req = r#"{"api_version": 1, "request_id": "req-5", "method": "broker.execute", "params": {"AcquireMemorySample": {"target": {"ProcessPid": 1234}, "chunk_size_mb": 64}}}"#;
    let mem_resp = app.dispatch_request(mem_req).await;
    assert!(mem_resp.contains("\"status\":403"));
    assert!(mem_resp.contains("Forbidden"));

    // 6. Test Unknown Method -> RFC 7807 404
    let unknown_req =
        r#"{"api_version": 1, "request_id": "req-6", "method": "non_existent", "params": {}}"#;
    let unknown_resp = app.dispatch_request(unknown_req).await;
    assert!(unknown_resp.contains("\"status\":404"));
    assert!(unknown_resp.contains("Not Found"));

    // 7. Test Scenario Evaluate
    let scen_req = r#"{"api_version": 1, "request_id": "req-7", "method": "scenario.evaluate", "params": {"scenario_id": "SCEN-APT29", "hypothesis": "T1003.001"}}"#;
    let scen_resp = app.dispatch_request(scen_req).await;
    assert!(scen_resp.contains("\"verdict\":\"SUCCESS\""));
    assert!(scen_resp.contains("\"percentage\""));

    let _ = tokio::fs::remove_dir_all(temp_dir).await;
}

#[tokio::test]
async fn test_case_id_required_and_data_survives_restart() {
    let scratch =
        std::env::temp_dir().join(format!("engine_persist_test_{}", uuid::Uuid::now_v7()));
    let cas_dir = scratch.join("cas");
    let db_path = scratch.join("case.db");

    let case_id = {
        let app = EngineApp::new(cas_dir.clone(), db_path.clone()).expect("open persistent db");

        // Collection must be rejected without a real case_id, not silently
        // fabricate a random one.
        let missing_case_req =
            r#"{"api_version": 1, "request_id": "r1", "method": "host.correlate", "params": {}}"#;
        let missing_case_resp = app.dispatch_request(missing_case_req).await;
        assert!(missing_case_resp.contains("\"status\":400"));

        // Create a real case and use its id end to end.
        let case_req = r#"{"api_version": 1, "request_id": "r2", "method": "cases.create", "params": {"title": "Incident Persist"}}"#;
        let case_resp = app.dispatch_request(case_req).await;
        let case_val: serde_json::Value = serde_json::from_str(&case_resp).unwrap();
        let case_id = case_val["result"]["case_id"].as_str().unwrap().to_string();

        let correlate_req = format!(
            r#"{{"api_version": 1, "request_id": "r3", "method": "host.correlate", "params": {{"case_id": "{}", "refresh": true}}}}"#,
            case_id
        );
        let correlate_resp = app.dispatch_request(&correlate_req).await;
        assert!(correlate_resp.contains("\"error\":null"));

        // Facts from correlation must be stored under the real case id.
        let cid = core_domain::id::EntityId::parse(&case_id).unwrap();
        let facts = app.storage.get_facts_for_case(cid).unwrap();
        assert!(
            !facts.is_empty(),
            "correlation should have produced facts for the real case"
        );

        case_id
    }; // app dropped here, simulating the application closing

    // Reopen against the same db file, as a fresh process would.
    let reopened = EngineApp::new(cas_dir, db_path.clone()).expect("reopen persistent db");
    let list_resp = reopened
        .dispatch_request(
            r#"{"api_version": 1, "request_id": "r4", "method": "cases.list", "params": {}}"#,
        )
        .await;
    assert!(list_resp.contains("Incident Persist"));

    let cid = core_domain::id::EntityId::parse(&case_id).unwrap();
    let facts_after_restart = reopened.storage.get_facts_for_case(cid).unwrap();
    assert!(
        !facts_after_restart.is_empty(),
        "facts must still be there after reopening the database"
    );

    let _ = tokio::fs::remove_dir_all(scratch).await;
}

fn build_synthetic_pcap_to_port(dst_port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    // Global header
    buf.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
    buf.extend_from_slice(&2u16.to_ne_bytes());
    buf.extend_from_slice(&4u16.to_ne_bytes());
    buf.extend_from_slice(&0i32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&65535u32.to_ne_bytes());
    buf.extend_from_slice(&1u32.to_ne_bytes()); // linktype = Ethernet

    let pkt_len = 54u32;
    buf.extend_from_slice(&1720000000u32.to_ne_bytes());
    buf.extend_from_slice(&1000u32.to_ne_bytes());
    buf.extend_from_slice(&pkt_len.to_ne_bytes());
    buf.extend_from_slice(&pkt_len.to_ne_bytes());

    buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    buf.extend_from_slice(&[0x08, 0x00]);

    buf.push(0x45);
    buf.push(0x00);
    buf.extend_from_slice(&40u16.to_be_bytes());
    buf.extend_from_slice(&1234u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(64);
    buf.push(6); // TCP
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&[192, 168, 1, 105]);
    buf.extend_from_slice(&[10, 0, 0, 15]);

    buf.extend_from_slice(&49152u16.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&100000u32.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.push(0x50);
    buf.push(0x02); // SYN
    buf.extend_from_slice(&64240u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf
}

#[tokio::test]
async fn test_evidence_ingest_pcap_produces_facts() {
    use base64::Engine as _;

    let scratch =
        std::env::temp_dir().join(format!("engine_evidence_test_{}", uuid::Uuid::now_v7()));
    let cas_dir = scratch.join("cas");
    let db_path = scratch.join("case.db");
    let app = EngineApp::new(cas_dir, db_path).expect("open persistent db");

    let case_req = r#"{"api_version": 1, "request_id": "r1", "method": "cases.create", "params": {"title": "Evidence Test"}}"#;
    let case_resp = app.dispatch_request(case_req).await;
    let case_val: serde_json::Value = serde_json::from_str(&case_resp).unwrap();
    let case_id = case_val["result"]["case_id"].as_str().unwrap().to_string();

    // Port 4444 matches the CORR-WIN-003a suspicious C2 port rule.
    let pcap_bytes = build_synthetic_pcap_to_port(4444);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&pcap_bytes);

    let ingest_req = serde_json::json!({
        "api_version": 1,
        "request_id": "r2",
        "method": "evidence.ingest",
        "params": {
            "case_id": case_id,
            "filename": "capture.pcap",
            "content_base64": b64
        }
    });
    let ingest_resp = app.dispatch_request(&ingest_req.to_string()).await;
    let ingest_val: serde_json::Value = serde_json::from_str(&ingest_resp).unwrap();
    assert!(
        ingest_val["error"].is_null(),
        "unexpected error: {}",
        ingest_val
    );
    assert_eq!(ingest_val["result"]["events_extracted"], 1);
    assert_eq!(ingest_val["result"]["facts_derived"], 1);

    let cid = core_domain::id::EntityId::parse(&case_id).unwrap();
    let facts = app.storage.get_facts_for_case(cid).unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].data["rule_id"], "CORR-WIN-003a");

    // Unsupported extensions must be refused, not silently accepted.
    let bad_req = serde_json::json!({
        "api_version": 1,
        "request_id": "r3",
        "method": "evidence.ingest",
        "params": {
            "case_id": case_id,
            "filename": "notes.txt",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(b"hello")
        }
    });
    let bad_resp = app.dispatch_request(&bad_req.to_string()).await;
    assert!(bad_resp.contains("\"status\":400"));

    let _ = tokio::fs::remove_dir_all(scratch).await;
}
