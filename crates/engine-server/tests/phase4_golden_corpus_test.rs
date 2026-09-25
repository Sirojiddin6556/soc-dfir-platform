#![forbid(unsafe_code)]

use base64::Engine as _;
use engine_server::EngineApp;
use serde_json::json;
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forensics/phase4")
        .join(name)
        .pipe(|path| std::fs::read(path).expect("phase4 fixture"))
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

async fn ingest(app: &EngineApp, case_id: &str, filename: &str, bytes: &[u8]) -> serde_json::Value {
    let request = json!({
        "api_version": 1,
        "request_id": format!("phase4-{filename}"),
        "method": "evidence.ingest",
        "params": {
            "case_id": case_id,
            "filename": filename,
            "content_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    });
    serde_json::from_str(&app.dispatch_request(&request.to_string()).await).unwrap()
}

#[tokio::test]
async fn phase4_real_corpus_production_projection_smoke() {
    let scratch = std::env::temp_dir().join(format!("phase4_golden_{}", uuid::Uuid::now_v7()));
    let app = EngineApp::new(scratch.join("cas"), scratch.join("case.db")).unwrap();
    let case: serde_json::Value = serde_json::from_str(
        &app.dispatch_request(
            r#"{"api_version":1,"request_id":"phase4-case","method":"cases.create","params":{"title":"Phase 4 real golden corpus"}}"#,
        )
        .await,
    )
    .unwrap();
    let case_id = case["result"]["case_id"].as_str().unwrap().to_string();

    for (name, bytes) in [
        ("security_phase4.evtx", fixture("security_phase4.evtx")),
        ("sysmon_phase4.evtx", fixture("sysmon_phase4.evtx")),
        ("traffic_phase4.pcapng", fixture("traffic_phase4.pcapng")),
    ] {
        let response = ingest(&app, &case_id, name, &bytes).await;
        assert!(response["error"].is_null(), "{name}: {response}");
        eprintln!("{name}: {}", response["result"]);
    }

    let id = core_domain::id::EntityId::parse(&case_id).unwrap();
    let observations = app.storage.list_observations_for_case(id).unwrap();
    let timeline = app.storage.list_timeline_events_for_case(id).unwrap();
    let correlations = app.storage.list_correlations_for_case(id).unwrap();
    let mut kinds = std::collections::BTreeMap::new();
    for observation in &observations {
        *kinds
            .entry(observation.raw_event_type.clone())
            .or_insert(0usize) += 1;
    }
    eprintln!("observation_kinds={kinds:?}");
    let process_names: Vec<_> = observations
        .iter()
        .filter(|item| item.raw_event_type == "process_create")
        .map(|item| {
            (
                item.data.get("process_name").cloned(),
                item.data.get("new_process_name").cloned(),
                item.data.get("image").cloned(),
                item.data.get("host").cloned(),
                item.data.get("computer").cloned(),
            )
        })
        .filter(|item| {
            item.0
                .as_ref()
                .is_some_and(|v| v.to_string().to_ascii_lowercase().contains("power"))
                || item
                    .1
                    .as_ref()
                    .is_some_and(|v| v.to_string().to_ascii_lowercase().contains("power"))
                || item
                    .2
                    .as_ref()
                    .is_some_and(|v| v.to_string().to_ascii_lowercase().contains("power"))
        })
        .collect();
    eprintln!("powershell_processes={process_names:?}");
    let process_samples: Vec<_> = observations
        .iter()
        .filter(|item| item.raw_event_type == "process_create")
        .take(30)
        .map(|item| {
            (
                item.data.get("process_name").cloned(),
                item.data.get("new_process_name").cloned(),
                item.data.get("Image").cloned(),
                item.data.get("computer").cloned(),
            )
        })
        .collect();
    eprintln!("process_samples={process_samples:?}");
    for observation in observations
        .iter()
        .filter(|item| {
            item.raw_event_type == "dns_message"
                || item.raw_event_type == "tls_handshake"
                || item
                    .data
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("powershell")
        })
        .take(20)
    {
        eprintln!(
            "relevant={:?} time={:?} data={}",
            observation.raw_event_type, observation.source_timestamp, observation.data
        );
    }
    eprintln!("timeline_count={}", timeline.len());
    eprintln!("correlations={correlations:?}");
    assert!(!observations.is_empty());
    assert!(!timeline.is_empty());

    let _ = tokio::fs::remove_dir_all(scratch).await;
}
