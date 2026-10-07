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

    // 4. Test Broker Execute (Authorized: ReadProcesses) against a process
    //    that really exists -- this test binary.
    let me = std::process::id();
    let broker_req = format!(
        r#"{{"api_version": 1, "request_id": "req-4", "method": "broker.execute", "params": {{"CollectProcessMetadata": {{"pid": {}}}}}}}"#,
        me
    );
    let broker_resp = app.dispatch_request(&broker_req).await;
    let broker_val: serde_json::Value = serde_json::from_str(&broker_resp).unwrap();
    assert_eq!(broker_val["result"]["pid"], me);
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    assert_ne!(broker_val["result"]["status"], "not_found");
    // A pid that cannot exist (above Linux pid_max, not a multiple of 4 as
    // every Windows pid is) must not be reported as running.
    let ghost_req = r#"{"api_version": 1, "request_id": "req-4b", "method": "broker.execute", "params": {"CollectProcessMetadata": {"pid": 4294967}}}"#;
    let ghost_resp = app.dispatch_request(ghost_req).await;
    assert!(ghost_resp.contains("\"status\":\"not_found\""));

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

/// A real, harmless process (a copy of `sleep` / `PING.EXE`) running from a
/// world-writable directory: precisely the on-host condition CORR-LIN-001b
/// (Linux) and CORR-WIN-001f (Windows) detect. Live correlation of a clean
/// machine legitimately produces no facts, so a test that needs facts must
/// create a genuine finding on the host rather than rely on whatever happens
/// to be running. Killed and removed on drop.
struct SuspiciousProcess {
    child: std::process::Child,
    dir: std::path::PathBuf,
}

impl SuspiciousProcess {
    fn spawn() -> Self {
        #[cfg(target_os = "windows")]
        let (bases, sources, file, args): (&[&str], &[&str], &str, &[&str]) = (
            &["C:\\Users\\Public"],
            &["C:\\Windows\\System32\\PING.EXE"],
            "ping.exe",
            &["-n", "120", "127.0.0.1"],
        );
        #[cfg(not(target_os = "windows"))]
        let (bases, sources, file, args): (&[&str], &[&str], &str, &[&str]) = (
            &["/tmp", "/var/tmp", "/dev/shm"],
            &["/bin/sleep", "/usr/bin/sleep"],
            "sleep",
            &["120"],
        );
        let source = sources
            .iter()
            .find(|s| std::path::Path::new(s).exists())
            .expect("a harmless system binary to copy");
        for base in bases {
            let dir =
                std::path::Path::new(base).join(format!("soc-dfir-it-{}", uuid::Uuid::now_v7()));
            if std::fs::create_dir_all(&dir).is_err() {
                continue;
            }
            let exe = dir.join(file);
            if std::fs::copy(source, &exe).is_ok() {
                // A noexec mount makes spawn fail; try the next directory.
                if let Ok(child) = std::process::Command::new(&exe)
                    .args(args)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                {
                    return Self { child, dir };
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
        panic!(
            "could not execute a binary from any world-writable directory {:?}",
            bases
        );
    }
}

impl Drop for SuspiciousProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn test_case_id_required_and_data_survives_restart() {
    let suspicious = SuspiciousProcess::spawn();
    let suspicious_pid = suspicious.child.id();

    let scratch =
        std::env::temp_dir().join(format!("engine_persist_test_{}", uuid::Uuid::now_v7()));
    let cas_dir = scratch.join("cas");
    let db_path = scratch.join("case.db");

    let (case_id, finding_id) = {
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

        // Facts from correlation must be stored under the real case id, and
        // must include the finding for the process this test started.
        let cid = core_domain::id::EntityId::parse(&case_id).unwrap();
        let facts = app.storage.get_facts_for_case(cid).unwrap();
        let finding = facts
            .iter()
            .find(|f| f.data["pid"] == suspicious_pid)
            .unwrap_or_else(|| {
                panic!(
                    "live correlation must flag pid {} running from a world-writable dir; facts: {:?}",
                    suspicious_pid,
                    facts.iter().map(|f| &f.data["rule_id"]).collect::<Vec<_>>()
                )
            });
        #[cfg(target_os = "linux")]
        assert_eq!(finding.data["rule_id"], "CORR-LIN-001b");
        #[cfg(target_os = "windows")]
        assert_eq!(finding.data["rule_id"], "CORR-WIN-001f");

        (case_id, finding.id)
    }; // app dropped here, simulating the application closing
    drop(suspicious);

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
        facts_after_restart.iter().any(|f| f.id == finding_id),
        "the finding must still be there after reopening the database"
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
    assert!(
        ingest_val["result"]["events_extracted"]
            .as_u64()
            .is_some_and(|count| count >= 2),
        "packet and flow observations should both be persisted: {}",
        ingest_val
    );
    assert_eq!(ingest_val["result"]["facts_derived"], 1);

    let cid = core_domain::id::EntityId::parse(&case_id).unwrap();
    let facts = app.storage.get_facts_for_case(cid).unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].data["rule_id"], "CORR-WIN-003a");

    let timeline_before = app.storage.list_timeline_events_for_case(cid).unwrap();
    assert!(
        !timeline_before.is_empty(),
        "production ingest must persist TIME-001 projections"
    );
    let analysis_before =
        engine_server::analysis::process_persisted_observations(&app.storage, cid).unwrap();
    let timeline_after = app.storage.list_timeline_events_for_case(cid).unwrap();
    let correlations_after = app.storage.list_correlations_for_case(cid).unwrap();
    assert_eq!(timeline_before, timeline_after);
    assert!(
        correlations_after.is_empty(),
        "unattributed network data must not be correlated"
    );
    assert_eq!(
        analysis_before.timeline_events_created,
        timeline_after.len() as u64
    );

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

#[tokio::test]
async fn phase4_production_evtx_ingest_persists_observations_and_timeline() {
    use base64::Engine as _;

    let scratch = std::env::temp_dir().join(format!("phase4_evtx_ingest_{}", uuid::Uuid::now_v7()));
    let app = EngineApp::new(scratch.join("cas"), scratch.join("case.db")).unwrap();
    let case: serde_json::Value = serde_json::from_str(
        &app.dispatch_request(
            r#"{"api_version":1,"request_id":"phase4-case","method":"cases.create","params":{"title":"Phase 4 EVTX"}}"#,
        )
        .await,
    )
    .unwrap();
    let case_id = case["result"]["case_id"].as_str().unwrap().to_string();
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forensics/sysmon_real.evtx");
    let ingest = serde_json::json!({
        "api_version": 1,
        "request_id": "phase4-sysmon",
        "method": "evidence.ingest",
        "params": {
            "case_id": case_id,
            "filename": "sysmon_phase4.evtx",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(
                std::fs::read(fixture).unwrap()
            )
        }
    });
    let response: serde_json::Value =
        serde_json::from_str(&app.dispatch_request(&ingest.to_string()).await).unwrap();
    assert!(response["error"].is_null(), "{response}");

    let case_id = core_domain::id::EntityId::parse(&case_id).unwrap();
    assert_eq!(response["result"]["events_extracted"].as_u64(), Some(8));
    assert_eq!(
        app.storage
            .list_observations_for_case(case_id)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        app.storage
            .list_timeline_events_for_case(case_id)
            .unwrap()
            .len(),
        8
    );
    assert!(app
        .storage
        .list_correlations_for_case(case_id)
        .unwrap()
        .is_empty());
    let _ = tokio::fs::remove_dir_all(scratch).await;
}

#[tokio::test]
async fn phase3_h20_restart_and_cas_replay_preserve_network_semantics() {
    use base64::Engine as _;
    use std::fs;
    use tool_adapters::pcap::phase3::{reconstruct_flows_with_artifact, Flow};
    use tool_adapters::PcapAdapter;

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/forensics/tls")
            .join(name);
        fs::read_to_string(path)
            .unwrap()
            .split_whitespace()
            .flat_map(|part| {
                (0..part.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&part[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    fn fixture_bytes_from_path(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/forensics")
            .join(name);
        fs::read_to_string(path)
            .unwrap()
            .split_whitespace()
            .flat_map(|part| {
                (0..part.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&part[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    fn canonical(values: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
        let mut result: Vec<_> = values
            .into_iter()
            .map(|mut value| {
                if let Some(object) = value.as_object_mut() {
                    object.remove("id");
                    object.remove("timestamp");
                }
                value
            })
            .collect();
        result.sort_by_key(|value| value.to_string());
        result
    }

    let scratch = std::env::temp_dir().join(format!("phase3_h20_{}", uuid::Uuid::now_v7()));
    let cas_dir = scratch.join("cas");
    let db_path = scratch.join("case.db");
    let app = EngineApp::new(cas_dir.clone(), db_path.clone()).expect("open storage");
    let case_resp = app
        .dispatch_request(r#"{"api_version":1,"request_id":"h20-case","method":"cases.create","params":{"title":"H20"}}"#)
        .await;
    let case_id = serde_json::from_str::<serde_json::Value>(&case_resp).unwrap()["result"]
        ["case_id"]
        .as_str()
        .unwrap()
        .to_string();
    let bytes = fixture_bytes("tls12_complete_clienthello.pcap.hex");
    let ingest = serde_json::json!({
        "api_version": 1,
        "request_id": "h20-ingest",
        "method": "evidence.ingest",
        "params": {
            "case_id": case_id,
            "filename": "tls12.pcap",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes)
        }
    });
    let ingest_value =
        serde_json::from_str::<serde_json::Value>(&app.dispatch_request(&ingest.to_string()).await)
            .unwrap();
    assert!(ingest_value["error"].is_null(), "{}", ingest_value);
    let artifact_id =
        core_domain::id::EntityId::parse(ingest_value["result"]["artifact_id"].as_str().unwrap())
            .unwrap();
    let before = canonical(
        app.storage
            .list_observations_for_artifact(artifact_id)
            .unwrap(),
    );
    assert!(before
        .iter()
        .any(|value| value["event_type"] == "network_flow"));
    assert!(before
        .iter()
        .any(|value| value["data"]["_network_quality"].is_object()));

    let artifact = app.storage.get_artifact(artifact_id).unwrap().unwrap();
    let replay_path = app.cas.get_path_for_blake3(&artifact.hash_blake3);
    let mut replay_packets = Vec::new();
    let replay_summary = PcapAdapter::parse_capture_with_sink(&replay_path, |packet| {
        replay_packets.push(packet);
        Ok(())
    })
    .unwrap();
    let replay_flows: Vec<Flow> =
        reconstruct_flows_with_artifact(&artifact.hash_sha256, &replay_packets);
    assert!(!replay_flows.is_empty());
    let replay_flow_ids: Vec<_> = replay_flows
        .iter()
        .map(|flow| flow.flow_instance_id.clone())
        .collect();
    assert!(before.iter().any(|value| {
        replay_flow_ids
            .iter()
            .any(|id| value["data"]["flow"]["flow_instance_id"] == *id)
    }));
    assert_eq!(
        replay_summary.packets_decoded as usize,
        replay_packets.len()
    );

    let pcapng = fixture_bytes_from_path("pcapng_multi_section_interfaces.pcapng.hex");
    let pcapng_ingest = serde_json::json!({
        "api_version": 1,
        "request_id": "h20-pcapng",
        "method": "evidence.ingest",
        "params": {
            "case_id": case_id,
            "filename": "interfaces.pcapng",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(&pcapng)
        }
    });
    let pcapng_value = serde_json::from_str::<serde_json::Value>(
        &app.dispatch_request(&pcapng_ingest.to_string()).await,
    )
    .unwrap();
    assert!(pcapng_value["error"].is_null(), "{}", pcapng_value);
    let pcapng_id =
        core_domain::id::EntityId::parse(pcapng_value["result"]["artifact_id"].as_str().unwrap())
            .unwrap();
    let pcapng_before = canonical(
        app.storage
            .list_observations_for_artifact(pcapng_id)
            .unwrap(),
    );
    assert!(pcapng_before
        .iter()
        .any(|value| value["event_type"] == "network_flow"));

    drop(app);
    let reopened = EngineApp::new(cas_dir, db_path).expect("reopen storage");
    let after = canonical(
        reopened
            .storage
            .list_observations_for_artifact(artifact_id)
            .unwrap(),
    );
    assert_eq!(before, after);
    let pcapng_after = canonical(
        reopened
            .storage
            .list_observations_for_artifact(pcapng_id)
            .unwrap(),
    );
    assert_eq!(pcapng_before, pcapng_after);
    let _ = tokio::fs::remove_dir_all(scratch).await;
}
