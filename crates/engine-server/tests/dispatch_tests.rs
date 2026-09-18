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
