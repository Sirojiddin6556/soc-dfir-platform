#![forbid(unsafe_code)]

use engine_server::ctf_dispatch::{handle_ctf_command, try_dispatch_jsonrpc};
use engine_server::EngineApp;
use ipc_protocol::*;
use serde_json::json;

#[tokio::test]
async fn test_ctf_dispatch_competition_and_challenge_flow() {
    let app = EngineApp::new_in_memory(
        std::env::temp_dir().join(format!("cas_test_{}", uuid::Uuid::now_v7())),
    );

    // 1. Create competition
    let comp_create = json!({
        "name": "BSides 2026",
        "description": "Annual security competition",
        "flag_format": r"bsides\{[a-zA-Z0-9_\-]+\}"
    });
    let res = handle_ctf_command(&app, "competitions.create", comp_create)
        .await
        .unwrap();
    let comp_id = res["id"].as_str().unwrap().to_string();

    // 2. Get competition
    let get_comp = json!({ "id": comp_id });
    let comp = handle_ctf_command(&app, "competitions.get", get_comp)
        .await
        .unwrap();
    assert_eq!(comp["name"], "BSides 2026");

    // 3. Create challenge
    let chal_create = json!({
        "competition_id": comp_id,
        "name": "Buffer Overflow Alpha",
        "category": "pwn",
        "points": 250,
        "expected_flag": "bsides{b0f_expl0it_succ3ss}",
        "target": {
            "host": "10.10.10.5",
            "port": 1337,
            "protocol": "tcp"
        }
    });
    let res = handle_ctf_command(&app, "challenges.create", chal_create)
        .await
        .unwrap();
    let chal_id = res["id"].as_str().unwrap().to_string();

    // 4. Update challenge status
    let status_req = json!({
        "id": chal_id,
        "status": "in_progress"
    });
    let status_res = handle_ctf_command(&app, "challenges.update_status", status_req)
        .await
        .unwrap();
    assert_eq!(status_res["updated"], true);

    // 5. Register flag candidate
    let flag_req = json!({
        "challenge_id": chal_id,
        "value": "bsides{b0f_expl0it_succ3ss}",
        "source_ref": "gdb_exploit"
    });
    let flag_res = handle_ctf_command(&app, "flags.register", flag_req)
        .await
        .unwrap();
    let candidate_id = flag_res["candidate_id"].as_str().unwrap();

    let wrong_req = json!({
        "challenge_id": chal_id,
        "value": "bsides{wrong_answer}",
        "source_ref": "manual"
    });
    let wrong_res = handle_ctf_command(&app, "flags.register", wrong_req)
        .await
        .unwrap();
    let wrong_accept = handle_ctf_command(
        &app,
        "flags.accept",
        json!({ "candidate_id": wrong_res["candidate_id"] }),
    )
    .await
    .unwrap();
    assert_eq!(wrong_accept["accepted"], false);

    // 6. Accept flag
    let accept_req = json!({ "candidate_id": candidate_id });
    let accept_res = handle_ctf_command(&app, "flags.accept", accept_req)
        .await
        .unwrap();
    assert_eq!(accept_res["accepted"], true);

    // 7. Verify challenge automatically became solved
    let get_chal = json!({ "id": chal_id });
    let chal_details = handle_ctf_command(&app, "challenges.get", get_chal)
        .await
        .unwrap();
    assert_eq!(chal_details["challenge"]["status"], "solved");

    // 8. Generate writeup draft
    let writeup_req = json!({ "challenge_id": chal_id, "include_timeline": true });
    let writeup_res = handle_ctf_command(&app, "writeups.generate_draft", writeup_req)
        .await
        .unwrap();
    assert!(writeup_res["markdown"]
        .as_str()
        .unwrap()
        .contains("Buffer Overflow Alpha"));
}

#[tokio::test]
async fn test_jsonrpc_2_framing_and_error_codes() {
    let app = EngineApp::new_in_memory(
        std::env::temp_dir().join(format!("cas_test_rpc_{}", uuid::Uuid::now_v7())),
    );

    // Test health
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "health",
        "params": {}
    });
    let resp_str = try_dispatch_jsonrpc(&app, &req.to_string()).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["ready"], true);

    // Test unknown method error -32601
    let req_unknown = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "unknown.method",
        "params": {}
    });
    let resp_str = try_dispatch_jsonrpc(&app, &req_unknown.to_string())
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["error"]["code"], METHOD_NOT_FOUND);

    // Test security violation on shell injection -32001
    let req_injection = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "jobs.submit",
        "params": {
            "challenge_id": "c1",
            "tool_id": "sh",
            "argv": ["sh", "-c", "whoami"]
        }
    });
    let resp_str = try_dispatch_jsonrpc(&app, &req_injection.to_string())
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["error"]["code"], SECURITY_VIOLATION);

    // Test validation error on slice length limit (> 65536) -32602
    let req_slice_invalid = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "artifacts.get_slice",
        "params": {
            "artifact_id": "art-1",
            "offset": 0,
            "length": 70000
        }
    });
    let resp_str = try_dispatch_jsonrpc(&app, &req_slice_invalid.to_string())
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["error"]["code"], INVALID_PARAMS);

    // Test recipe preview in JSON-RPC
    let req_recipe = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "recipes.preview",
        "params": {
            "input_data": "flag{rot13_test_secret}",
            "ops": ["Rot13"]
        }
    });
    let resp_recipe_str = try_dispatch_jsonrpc(&app, &req_recipe.to_string())
        .await
        .unwrap();
    let resp_recipe: serde_json::Value = serde_json::from_str(&resp_recipe_str).unwrap();
    assert!(resp_recipe["result"]["output_sample"]
        .as_str()
        .unwrap()
        .contains("synt"));
}

#[tokio::test]
async fn test_ctf_artifacts_and_tools_api() {
    let app = EngineApp::new_in_memory(
        std::env::temp_dir().join(format!("cas_test_art_{}", uuid::Uuid::now_v7())),
    );

    // 1. Store sample bytes in CAS
    let data = b"CTF-BINARY-FORENSIC-PAYLOAD-1337";
    let stored = app.cas.store_bytes(data).await.unwrap();

    // 2. Read slice via JSON-RPC
    let slice_req = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "artifacts.get_slice",
        "params": {
            "artifact_id": stored.blake3,
            "offset": 4,
            "length": 6
        }
    });
    let resp_str = try_dispatch_jsonrpc(&app, &slice_req.to_string())
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["length"], 6);

    // 3. Verify integrity
    let verify_req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "artifacts.verify",
        "params": { "hash": stored.blake3 }
    });
    let verify_resp_str = try_dispatch_jsonrpc(&app, &verify_req.to_string())
        .await
        .unwrap();
    let verify_resp: serde_json::Value = serde_json::from_str(&verify_resp_str).unwrap();
    assert_eq!(verify_resp["result"]["valid"], true);

    // 4. Tools list
    let tools_req = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools.list",
        "params": {}
    });
    let tools_resp_str = try_dispatch_jsonrpc(&app, &tools_req.to_string())
        .await
        .unwrap();
    let tools_resp: serde_json::Value = serde_json::from_str(&tools_resp_str).unwrap();
    assert!(tools_resp["result"].as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn test_dispatch_request_backward_compatibility() {
    let app = EngineApp::new_in_memory(
        std::env::temp_dir().join(format!("cas_compat_{}", uuid::Uuid::now_v7())),
    );

    // 1. Legacy IpcRequest envelope for health
    let legacy_health = json!({
        "api_version": 1,
        "request_id": "req-001",
        "method": "health",
        "params": {}
    });
    let resp1 = app.dispatch_request(&legacy_health.to_string()).await;
    assert!(resp1.contains("\"result\":{\"live\":true"));

    // 2. Legacy IpcRequest envelope calling CTF namespace (competitions.list)
    let legacy_ctf = json!({
        "api_version": 1,
        "request_id": "req-002",
        "method": "competitions.list",
        "params": {}
    });
    let resp2 = app.dispatch_request(&legacy_ctf.to_string()).await;
    assert!(resp2.contains("\"result\":[]"));

    // 3. Modern JSON-RPC 2.0 envelope
    let jsonrpc_req = json!({
        "jsonrpc": "2.0",
        "id": "rpc-001",
        "method": "competitions.list",
        "params": {}
    });
    let resp3 = app.dispatch_request(&jsonrpc_req.to_string()).await;
    assert!(resp3.contains("\"jsonrpc\":\"2.0\""));
    assert!(resp3.contains("\"result\":[]"));
}
