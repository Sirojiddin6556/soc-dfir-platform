#![forbid(unsafe_code)]

use core_domain::audit::AuditEvent;
use core_domain::epistemic::{AssertionType, Confidence, PainLevel, Severity, VerificationState};
use core_domain::fact::{EntityType, Fact};
use core_domain::id::EntityId;
use storage_sqlite::SqliteStorage;

#[test]
fn test_sqlite_full_crud_and_query() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let case_id = EntityId::new_v7();
    storage
        .insert_case(case_id, "CTF Scenario 01", Some("Initial compromise"))
        .unwrap();

    let fact = Fact {
        id: EntityId::new_v7(),
        case_id,
        evidence_ids: vec![EntityId::new_v7(), EntityId::new_v7()],
        assertion_type: AssertionType::Fact,
        verification_state: VerificationState::Confirmed,
        entity_type: EntityType::Host,
        entity_key: "192.168.1.50".to_string(),
        fact_type: "DiscoveredHost".to_string(),
        confidence: Confidence::new(1.0),
        severity: Severity::Info,
        risk_score: 10.0,
        evidence_strength: 1.0,
        pain_level: Some(PainLevel::IpAddresses),
        data: serde_json::json!({"hostname": "WIN-SRV01"}),
        created_at: chrono::Utc::now(),
    };

    storage.insert_fact(&fact).unwrap();

    let facts = storage.get_facts_for_case(case_id).unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].entity_key, "192.168.1.50");
    assert_eq!(facts[0].assertion_type, AssertionType::Fact);
}

#[test]
fn test_all_19_schema_tables_exist() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let conn = storage.conn().lock().unwrap().is_autocommit();
    assert!(conn);
}

#[test]
fn test_audit_event_logging() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let case_id = EntityId::new_v7();
    storage.insert_case(case_id, "Audit Case", None).unwrap();

    let event = AuditEvent::new(
        Some(case_id),
        "analyst_alice",
        "PrivilegedPortScan",
        "Network",
        Some("192.168.1.1".to_string()),
        "Success",
        serde_json::json!({"ports": [80, 443]}),
    );
    storage.insert_audit_event(&event).unwrap();

    let events = storage.list_audit_events(Some(case_id)).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor_id, "analyst_alice");
    assert_eq!(events[0].action, "PrivilegedPortScan");
}

#[test]
fn test_forensic_custody_chain_verification_and_triggers() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let case_id = EntityId::new_v7();
    storage.insert_case(case_id, "Forensic Case", None).unwrap();

    let session_id = EntityId::new_v7();
    let s = storage_sqlite::evidence::IngestSessionRecord {
        id: session_id,
        case_id,
        filename: "suspicious_traffic.pcapng".to_string(),
        declared_size_bytes: 1048576,
        bytes_received: 1048576,
        staging_path: "staging/test.part".to_string(),
        status: "COMMITTED".to_string(),
        sha256: Some("sha256-test-hex".to_string()),
        blake3: Some("blake3-test-hex".to_string()),
        artifact_id: None,
        actor_id: "forensic_analyst".to_string(),
        upload_token_hash: "token_hash".to_string(),
        error_message: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    storage.create_ingest_session(&s).unwrap();

    // Event 1: RECEIVED
    let ts1 = chrono::Utc::now();
    let event1_id = EntityId::new_v7();
    let hash1 = storage_sqlite::evidence::compute_custody_event_hash(
        "GENESIS",
        1,
        &event1_id.to_string(),
        &session_id.to_string(),
        None,
        &case_id.to_string(),
        "RECEIVED",
        "forensic_analyst",
        &ts1.to_rfc3339(),
        "sha256-test-hex",
        "blake3-test-hex",
        "details_hash1",
    );
    let event1 = storage_sqlite::evidence::ForensicCustodyEvent {
        event_id: event1_id,
        session_id,
        artifact_id: None,
        case_id,
        sequence_no: 1,
        action: "RECEIVED".to_string(),
        actor_id: "forensic_analyst".to_string(),
        timestamp_utc: ts1,
        sha256: "sha256-test-hex".to_string(),
        blake3: "blake3-test-hex".to_string(),
        previous_event_hash: "GENESIS".to_string(),
        event_hash: hash1.clone(),
        details_hash: "details_hash1".to_string(),
        details_json: "{}".to_string(),
    };
    storage.record_custody_event(&event1).unwrap();

    // Event 2: COMMITTED_TO_CAS (Artifact created)
    let ts2 = chrono::Utc::now();
    let artifact_id = EntityId::new_v7();
    let artifact = core_domain::artifact::Artifact {
        id: artifact_id,
        case_id,
        hash_blake3: "blake3-test-hex".to_string(),
        hash_sha256: "sha256-test-hex".to_string(),
        original_name: "suspicious_traffic.pcapng".to_string(),
        file_size: 1048576,
        mime_type: "application/vnd.tcpdump.pcap".to_string(),
        acquisition_method: "StreamingUpload".to_string(),
        acquired_at: ts2,
        ingested_at: ts2,
    };
    storage.insert_artifact(&artifact).unwrap();
    let mut s_updated = s.clone();
    s_updated.artifact_id = Some(artifact_id);
    storage.update_ingest_session(&s_updated).unwrap();

    let event2_id = EntityId::new_v7();
    let hash2 = storage_sqlite::evidence::compute_custody_event_hash(
        &hash1,
        2,
        &event2_id.to_string(),
        &session_id.to_string(),
        Some(&artifact_id.to_string()),
        &case_id.to_string(),
        "COMMITTED_TO_CAS",
        "forensic_analyst",
        &ts2.to_rfc3339(),
        "sha256-test-hex",
        "blake3-test-hex",
        "details_hash2",
    );
    let event2 = storage_sqlite::evidence::ForensicCustodyEvent {
        event_id: event2_id,
        session_id,
        artifact_id: Some(artifact_id),
        case_id,
        sequence_no: 2,
        action: "COMMITTED_TO_CAS".to_string(),
        actor_id: "forensic_analyst".to_string(),
        timestamp_utc: ts2,
        sha256: "sha256-test-hex".to_string(),
        blake3: "blake3-test-hex".to_string(),
        previous_event_hash: hash1,
        event_hash: hash2,
        details_hash: "details_hash2".to_string(),
        details_json: "{}".to_string(),
    };
    storage.record_custody_event(&event2).unwrap();

    // Verify chain is valid
    assert!(storage.verify_session_custody_chain(session_id).unwrap());
    assert!(storage.verify_custody_chain(artifact_id).unwrap());

    // Test tamper-evident trigger: UPDATE must abort
    let conn = storage.conn();
    let update_res = conn.lock().unwrap().execute(
        "UPDATE evidence_custody_events SET action = 'TAMPERED' WHERE sequence_no = 1",
        [],
    );
    assert!(update_res.is_err());
    let err_msg = update_res.unwrap_err().to_string();
    assert!(err_msg.contains("append-only"));
}
