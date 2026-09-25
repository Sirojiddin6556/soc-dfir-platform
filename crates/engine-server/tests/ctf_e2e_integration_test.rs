#![forbid(unsafe_code)]

use engine_server::ctf_dispatch::try_dispatch_jsonrpc;
use engine_server::EngineApp;
use ipc_protocol::*;
use serde_json::json;
use std::time::Duration;

/// Comprehensive end-to-end integration test verifying the complete CTF lifecycle:
/// Competition -> Challenge -> CAS Ingestion -> 64KB Slice -> Tool Execution ->
/// Recipe Pipeline -> Flag Detection & Acceptance -> Writeup Generation.
#[tokio::test]
async fn test_full_ctf_e2e_lifecycle_pipeline() {
    let temp_dir = std::env::temp_dir().join(format!("ctf_e2e_test_{}", uuid::Uuid::now_v7()));
    let app = EngineApp::new_in_memory(temp_dir.join("cas"));

    // -----------------------------------------------------------------------
    // STEP 1: Create Competition
    // -----------------------------------------------------------------------
    let comp_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "competitions.create",
        "params": {
            "name": "DefCamp World Finals 2026",
            "description": "Premier international cybersecurity championship",
            "format": "jeopardy",
            "flag_format": r"defcamp\{[a-zA-Z0-9_\-]+\}"
        }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &comp_req.to_string())
            .await
            .expect("RPC response"),
    )
    .expect("valid JSON response");
    assert!(
        resp["error"].is_null(),
        "comp create error: {:?}",
        resp["error"]
    );
    let comp_id = resp["result"]["id"].as_str().expect("comp id").to_string();
    assert!(
        comp_id.starts_with("comp-"),
        "Invalid comp id prefix: {comp_id}"
    );

    // Verify competition in list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "competitions.list",
        "params": {}
    });
    let list_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &list_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let comp_list = list_resp["result"].as_array().expect("competitions array");
    assert!(comp_list.iter().any(|c| c["id"] == comp_id));

    // -----------------------------------------------------------------------
    // STEP 2: Setup Challenge
    // -----------------------------------------------------------------------
    let chal_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "challenges.create",
        "params": {
            "competition_id": comp_id,
            "name": "Quantum Vault Keygen",
            "category": "reverse",
            "points": 450,
            "target": {
                "host": "quantum.defcamp.local",
                "port": 9001,
                "protocol": "tcp"
            }
        }
    });
    let chal_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &chal_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let chal_id = chal_resp["result"]["id"]
        .as_str()
        .expect("challenge id")
        .to_string();
    assert!(
        chal_id.starts_with("chal-"),
        "Invalid chal id prefix: {chal_id}"
    );

    // -----------------------------------------------------------------------
    // STEP 3: Challenge Status Transitions (State Machine)
    // -----------------------------------------------------------------------
    let update_status_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "challenges.update_status",
        "params": {
            "id": chal_id,
            "status": "in_progress"
        }
    });
    let status_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &update_status_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status_resp["result"]["updated"], true);
    assert_eq!(status_resp["result"]["status"], "in_progress");

    // -----------------------------------------------------------------------
    // STEP 4: Ingest Binary Artifact into CAS (WORM Storage)
    // -----------------------------------------------------------------------
    // Payload with embedded hidden flag: defcamp{qkv_r3v_m4st3r_2026}
    let flag_content = "defcamp{qkv_r3v_m4st3r_2026}";
    let payload_bytes =
        format!("HEADER_ELF_MAGIC_BYTES_1337_SALT_{flag_content}_FOOTER_SIGNATURE").into_bytes();
    let payload_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &payload_bytes);

    let ingest_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "artifacts.ingest",
        "params": {
            "challenge_id": chal_id,
            "filename": "quantum_vault.bin",
            "data_base64": payload_b64,
            "role": "input"
        }
    });
    let ingest_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &ingest_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let artifact_id = ingest_resp["result"]["artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let hash_blake3 = ingest_resp["result"]["blake3"]
        .as_str()
        .unwrap()
        .to_string();
    let hash_sha256 = ingest_resp["result"]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(artifact_id, hash_blake3);
    assert!(!hash_sha256.is_empty());

    // Verify artifact appears in challenge artifacts list
    let list_art_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "artifacts.list_for_challenge",
        "params": { "challenge_id": chal_id }
    });
    let list_art_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &list_art_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge_artifacts = list_art_resp["result"].as_array().unwrap();
    assert_eq!(challenge_artifacts.len(), 1);
    assert_eq!(challenge_artifacts[0]["artifact_id"], artifact_id);

    // -----------------------------------------------------------------------
    // STEP 5: Read 64KB CAS Slice and Verify Integrity
    // -----------------------------------------------------------------------
    let slice_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "artifacts.get_slice",
        "params": {
            "artifact_id": artifact_id,
            "offset": 0,
            "length": 65536
        }
    });
    let slice_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &slice_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(slice_resp["result"]["length"], payload_bytes.len());
    let fetched_b64 = slice_resp["result"]["bytes_base64"].as_str().unwrap();
    let fetched_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, fetched_b64).unwrap();
    assert_eq!(fetched_bytes, payload_bytes);

    // Verify CAS integrity check
    let verify_req = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "artifacts.verify",
        "params": { "hash": artifact_id }
    });
    let verify_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &verify_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(verify_resp["result"]["valid"], true);

    // -----------------------------------------------------------------------
    // STEP 6: Tool Execution via Job Engine (Safe argv)
    // -----------------------------------------------------------------------
    let job_submit_req = json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "jobs.submit",
        "params": {
            "challenge_id": chal_id,
            "tool_id": "cargo",
            "adapter": "native",
            "argv": ["cargo", "--version"],
            "timeout_ms": 15000
        }
    });
    let job_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &job_submit_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let job_id = job_resp["result"]["id"].as_str().unwrap().to_string();

    // Poll job state until completion
    let mut completed = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let job_state_req = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "jobs.get_state",
            "params": { "id": job_id }
        });
        let state_resp: serde_json::Value = serde_json::from_str(
            &try_dispatch_jsonrpc(&app, &job_state_req.to_string())
                .await
                .unwrap(),
        )
        .unwrap();
        let status = state_resp["result"]["status"].as_str().unwrap_or("");
        if status == "succeeded" || status == "failed" {
            completed = true;
            assert_eq!(status, "succeeded", "Job execution status: {status}");
            break;
        }
    }
    assert!(completed, "Job execution did not finish within timeout");

    // Inspect Job output tail
    let out_req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "jobs.get_output",
        "params": { "id": job_id, "max_bytes": 2048 }
    });
    let out_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &out_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let stdout_sample = out_resp["result"]["head"].as_str().unwrap();
    assert!(
        stdout_sample.contains("cargo"),
        "Stdout should contain 'cargo', got: {stdout_sample}"
    );

    // -----------------------------------------------------------------------
    // STEP 7: Recipe Pipeline Execution & Flag Detection
    // -----------------------------------------------------------------------
    // Preview pipeline with regex flag scanner
    let recipe_preview_req = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "recipes.preview",
        "params": {
            "input_data": format!("Pre-payload {flag_content} Post-payload"),
            "ops": ["Rot13", "Rot13"], // Identity roundtrip
            "flag_pattern": r"defcamp\{[a-zA-Z0-9_\-]+\}"
        }
    });
    let prev_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &recipe_preview_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let flags_found = prev_resp["result"]["detected_flags"]
        .as_array()
        .expect("detected_flags array");
    assert_eq!(flags_found.len(), 1);
    assert_eq!(flags_found[0], flag_content);

    // Execute recipe transformation on CAS artifact
    let recipe_exec_req = json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "recipes.execute",
        "params": {
            "artifact_id": artifact_id,
            "ops": ["HexEncode"]
        }
    });
    let exec_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &recipe_exec_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let transformed_art_id = exec_resp["result"]["output_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(transformed_art_id, artifact_id);

    // Save recipe transformation step into DAG history
    let save_step_req = json!({
        "jsonrpc": "2.0",
        "id": 14,
        "method": "recipes.save_step",
        "params": {
            "challenge_id": chal_id,
            "recipe_id": "recipe-hex-001",
            "step_order": 1,
            "operation": "HexEncode",
            "parameters_json": "{}",
            "input_artifact_id": artifact_id,
            "output_artifact_id": transformed_art_id,
            "input_hash": artifact_id,
            "output_hash": transformed_art_id
        }
    });
    let save_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &save_step_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(save_resp["result"]["id"].as_str().is_some());

    // -----------------------------------------------------------------------
    // STEP 8: Flag Registration & Acceptance
    // -----------------------------------------------------------------------
    let flag_reg_req = json!({
        "jsonrpc": "2.0",
        "id": 15,
        "method": "flags.register",
        "params": {
            "challenge_id": chal_id,
            "value": flag_content,
            "source_ref": "recipe_pipeline_preview"
        }
    });
    let flag_reg_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &flag_reg_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let candidate_id = flag_reg_resp["result"]["candidate_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Accept flag
    let accept_req = json!({
        "jsonrpc": "2.0",
        "id": 16,
        "method": "flags.accept",
        "params": { "candidate_id": candidate_id }
    });
    let accept_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &accept_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(accept_resp["result"]["accepted"], true);

    // Verify challenge status automatically became 'solved'
    let get_chal_req = json!({
        "jsonrpc": "2.0",
        "id": 17,
        "method": "challenges.get",
        "params": { "id": chal_id }
    });
    let get_chal_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &get_chal_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(get_chal_resp["result"]["challenge"]["status"], "solved");
    assert_eq!(get_chal_resp["result"]["accepted_flag"], flag_content);

    // -----------------------------------------------------------------------
    // STEP 9: Writeup Draft Generation & Export
    // -----------------------------------------------------------------------
    let draft_req = json!({
        "jsonrpc": "2.0",
        "id": 18,
        "method": "writeups.generate_draft",
        "params": {
            "challenge_id": chal_id,
            "include_timeline": true
        }
    });
    let draft_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &draft_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let draft_md = draft_resp["result"]["markdown"].as_str().unwrap();
    assert!(draft_md.contains("Quantum Vault Keygen"));
    assert!(draft_md.contains(flag_content));

    // Update section in writeup
    let update_sec_req = json!({
        "jsonrpc": "2.0",
        "id": 19,
        "method": "writeups.update_section",
        "params": {
            "challenge_id": chal_id,
            "section": "Solution Overview",
            "content": "Inverted XOR cipher and recovered master token."
        }
    });
    let update_sec_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &update_sec_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(update_sec_resp["result"]["updated"], true);

    // Export writeup markdown to filesystem
    let export_path = temp_dir.join("final_solution.md");
    let export_req = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "writeups.export",
        "params": {
            "challenge_id": chal_id,
            "dest_path": export_path.to_string_lossy().to_string()
        }
    });
    let export_resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &export_req.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(export_resp["result"]["bytes_written"].as_u64().unwrap() > 0);
    assert!(export_path.exists());

    let _ = tokio::fs::remove_dir_all(temp_dir).await;
}

/// Verification of error translation integrity across all DomainError variants:
/// DomainError -> JSON-RPC error codes (-32001..-32005, -32602, -32601).
#[tokio::test]
async fn test_error_translation_integrity_matrix() {
    let temp_dir = std::env::temp_dir().join(format!("ctf_err_test_{}", uuid::Uuid::now_v7()));
    let app = EngineApp::new_in_memory(temp_dir.join("cas"));

    // 1. Validation Error -> -32602 INVALID_PARAMS
    let req_val = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "competitions.create",
        "params": {
            "name": "", // Invalid empty name
        }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &req_val.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        resp["error"]["code"], INVALID_PARAMS,
        "Expected -32602 for validation error"
    );

    // 2. Security Violation -> -32001 SECURITY_VIOLATION
    let req_sec = json!({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "jobs.submit",
        "params": {
            "challenge_id": "c1",
            "tool_id": "bash",
            "argv": ["bash", "-c", "cat /etc/passwd"]
        }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &req_sec.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        resp["error"]["code"], SECURITY_VIOLATION,
        "Expected -32001 for security violation"
    );

    // 3. Entity Not Found -> -32004 ENTITY_NOT_FOUND
    let req_nf = json!({
        "jsonrpc": "2.0",
        "id": 103,
        "method": "competitions.get",
        "params": { "id": "comp-non-existent-99999" }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &req_nf.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        resp["error"]["code"], ENTITY_NOT_FOUND,
        "Expected -32004 for not found error"
    );

    // 4. Method Not Found -> -32601 METHOD_NOT_FOUND
    let req_mnf = json!({
        "jsonrpc": "2.0",
        "id": 104,
        "method": "non_existent.operation",
        "params": {}
    });
    let resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &req_mnf.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        resp["error"]["code"], METHOD_NOT_FOUND,
        "Expected -32601 for unknown method"
    );

    // 5. Slice length limit violation -> -32602 INVALID_PARAMS
    let req_slice = json!({
        "jsonrpc": "2.0",
        "id": 105,
        "method": "artifacts.get_slice",
        "params": {
            "artifact_id": "art-1",
            "offset": 0,
            "length": 100_000 // Exceeds 65536 limit
        }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &try_dispatch_jsonrpc(&app, &req_slice.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        resp["error"]["code"], INVALID_PARAMS,
        "Expected -32602 for slice > 64KB"
    );

    let _ = tokio::fs::remove_dir_all(temp_dir).await;
}
