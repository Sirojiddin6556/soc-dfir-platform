#![forbid(unsafe_code)]

use base64::Engine as _;
use engine_server::EngineApp;
use serde_json::json;
use std::path::{Path, PathBuf};

fn corpus_dir() -> Option<PathBuf> {
    std::env::var_os("SOCDFIR_PHASE4_LOCAL_CORPUS").map(PathBuf::from)
}

fn read_file(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|error| {
        panic!(
            "cannot read local corpus file '{}': {error}",
            dir.join(name).display()
        )
    })
}

async fn request(app: &EngineApp, value: serde_json::Value) -> serde_json::Value {
    serde_json::from_str(&app.dispatch_request(&value.to_string()).await)
        .expect("valid engine response")
}

async fn ingest(app: &EngineApp, case_id: &str, filename: &str, bytes: &[u8]) {
    let response = request(
        app,
        json!({
            "api_version": 1,
            "request_id": format!("local-corpus-{filename}"),
            "method": "evidence.ingest",
            "params": {
                "case_id": case_id,
                "filename": filename,
                "content_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            }
        }),
    )
    .await;
    assert!(response["error"].is_null(), "{filename}: {response}");
}

#[tokio::test]
async fn phase4_local_windows_corpus_survives_restart_and_replay() {
    let Some(dir) = corpus_dir() else {
        eprintln!("SOCDFIR_PHASE4_LOCAL_CORPUS is not set; local corpus test skipped");
        return;
    };
    let sysmon = read_file(&dir, "sysmon.evtx");
    let pcapng = read_file(&dir, "traffic.pcapng");
    assert!(!sysmon.is_empty(), "Sysmon EVTX is empty");
    assert!(!pcapng.is_empty(), "PCAPNG is empty");

    let scratch = std::env::temp_dir().join(format!("phase4_local_{}", uuid::Uuid::now_v7()));
    let cas = scratch.join("cas");
    let db = scratch.join("case.db");
    let app = EngineApp::new(cas.clone(), db.clone()).expect("create engine app");
    let case = request(
        &app,
        json!({
            "api_version": 1,
            "request_id": "local-corpus-case",
            "method": "cases.create",
            "params": {"title": "Phase 4 local Windows corpus"}
        }),
    )
    .await;
    let case_id = case["result"]["case_id"]
        .as_str()
        .expect("case id")
        .to_owned();

    ingest(&app, &case_id, "sysmon.evtx", &sysmon).await;
    ingest(&app, &case_id, "traffic.pcapng", &pcapng).await;

    let id = core_domain::id::EntityId::parse(&case_id).expect("valid case id");
    let observations = app.storage.list_observations_for_case(id).unwrap();
    let timeline = app.storage.list_timeline_events_for_case(id).unwrap();
    let correlations = app.storage.list_correlations_for_case(id).unwrap();
    assert!(
        !observations.is_empty(),
        "local corpus produced no observations"
    );
    assert!(
        !timeline.is_empty(),
        "local corpus produced no timeline events"
    );
    assert!(
        observations.iter().any(|item| {
            item.raw_event_type == "process_create"
                && item
                    .data
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("powershell")
        }),
        "local Sysmon corpus contains no PowerShell process-create observation"
    );
    assert!(
        observations.iter().any(|item| {
            matches!(
                item.raw_event_type.as_str(),
                "network_connection"
                    | "network_socket"
                    | "network_flow"
                    | "dns_message"
                    | "http_request"
                    | "tls_handshake"
            )
        }),
        "local PCAPNG corpus contains no network observation"
    );
    eprintln!("local_observation_count={}", observations.len());
    let mut kind_counts = std::collections::BTreeMap::new();
    for item in &observations {
        *kind_counts
            .entry(item.raw_event_type.clone())
            .or_insert(0usize) += 1;
    }
    eprintln!("local_observation_kinds={kind_counts:?}");
    if std::env::var("SOCDFIR_PHASE4_REQUIRE_CORRELATION").as_deref() == Ok("1") {
        assert!(
            !correlations.is_empty(),
            "local corpus produced no correlation"
        );
    } else {
        eprintln!(
            "local_correlation_count={}; set SOCDFIR_PHASE4_REQUIRE_CORRELATION=1 for the strict positive gate",
            correlations.len()
        );
    }
    let before = (observations.len(), timeline.len(), correlations.clone());
    drop(app);

    let reopened = EngineApp::new(cas, db).expect("reopen engine app");
    let after_restart = (
        reopened
            .storage
            .list_observations_for_case(id)
            .unwrap()
            .len(),
        reopened
            .storage
            .list_timeline_events_for_case(id)
            .unwrap()
            .len(),
        reopened.storage.list_correlations_for_case(id).unwrap(),
    );
    assert_eq!(
        before.0, after_restart.0,
        "observation count changed after restart"
    );
    assert_eq!(
        before.1, after_restart.1,
        "timeline count changed after restart"
    );
    assert_eq!(
        before.2, after_restart.2,
        "correlations changed after restart"
    );
    let _ = tokio::fs::remove_dir_all(scratch).await;
}
