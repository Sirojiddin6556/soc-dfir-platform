#![forbid(unsafe_code)]

use engine_server::handle_connection;
use engine_server::EngineApp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_test_server(
    cas_dir: PathBuf,
    db_path: PathBuf,
) -> (u16, Arc<EngineApp>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Arc::new(EngineApp::new(cas_dir, db_path).unwrap());
    let server_app = Arc::clone(&app);

    let handle = tokio::spawn(async move {
        let dummy_ui = PathBuf::from("target/dummy_ui");
        while let Ok((socket, _)) = listener.accept().await {
            let a = Arc::clone(&server_app);
            let u = dummy_ui.clone();
            tokio::spawn(async move {
                let _ = handle_connection(socket, a, &u).await;
            });
        }
    });

    (port, app, handle)
}

async fn rpc_call(port: u16, method: &str, params: serde_json::Value) -> serde_json::Value {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let req = serde_json::json!({
        "api_version": 1,
        "request_id": uuid::Uuid::new_v4().to_string(),
        "method": method,
        "params": params,
    });
    let body = serde_json::to_string(&req).unwrap();
    let http_req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(http_req.as_bytes()).await.unwrap();

    let mut resp_buf = Vec::new();
    stream.read_to_end(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf);
    let body_start = resp_str
        .find("\r\n\r\n")
        .expect("HTTP response header terminator")
        + 4;
    serde_json::from_str(&resp_str[body_start..]).unwrap()
}

async fn upload_chunk(
    port: u16,
    session_id: &str,
    token: &str,
    offset: u64,
    chunk: &[u8],
) -> (u16, String) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let http_req = format!(
        "PUT /ingest/{session_id}/chunk HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Ingest {token}\r\nUpload-Offset: {offset}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        chunk.len()
    );
    stream.write_all(http_req.as_bytes()).await.unwrap();
    stream.write_all(chunk).await.unwrap();

    let mut resp_buf = Vec::new();
    stream.read_to_end(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf);
    let status_code: u16 = resp_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    (status_code, resp_str.to_string())
}

#[tokio::test]
async fn test_phase1_streaming_ingest_and_custody_lifecycle() {
    let temp_dir = std::env::temp_dir().join(format!("phase1_test_{}", uuid::Uuid::now_v7()));
    let cas_dir = temp_dir.join("cas");
    let db_path = temp_dir.join("case.db");

    let (port, app, _server_handle) = spawn_test_server(cas_dir.clone(), db_path.clone()).await;

    // 1. Create a Case
    let case_resp = rpc_call(
        port,
        "cases.create",
        serde_json::json!({
            "title": "DFIR Investigation Alpha",
            "description": "Testing streaming ingestion and custody chain"
        }),
    )
    .await;
    assert!(case_resp["error"].is_null());
    let case_id = case_resp["result"]["case_id"].as_str().unwrap();

    // 2. Prepare Valid Forensic Payload (128 KB PCAP-NG = two 64 KB chunks)
    let mut payload = vec![0u8; 128 * 1024];
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    // Set PCAP-NG Section Header Block magic (0x0A0D0D0A)
    payload[0..4].copy_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]);

    let expected_sha256 = hex::encode(Sha256::digest(&payload));
    let expected_blake3 = blake3::hash(&payload).to_hex().to_string();

    // 3. Begin Ingest Session (EVID-001, EVID-002)
    let begin_resp = rpc_call(
        port,
        "evidence.ingest.begin",
        serde_json::json!({
            "case_id": case_id,
            "filename": "traffic.pcapng",
            "declared_size_bytes": payload.len() as u64,
            "actor_id": "investigator-01"
        }),
    )
    .await;
    assert!(begin_resp["error"].is_null(), "{:?}", begin_resp);
    let session_id = begin_resp["result"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let upload_token = begin_resp["result"]["upload_token"]
        .as_str()
        .unwrap()
        .to_string();

    // 4. Upload First Chunk (64 KB) via Binary Data Plane
    let chunk1 = &payload[..64 * 1024];
    let (code1, header1) = upload_chunk(port, &session_id, &upload_token, 0, chunk1).await;
    assert_eq!(code1, 200, "Chunk 1 upload failed: {}", header1);
    assert!(header1.contains("Upload-Offset: 65536"));

    // 5. Query Ingest Status (EVID-002)
    let status_resp = rpc_call(
        port,
        "evidence.ingest.status",
        serde_json::json!({ "session_id": session_id }),
    )
    .await;
    assert_eq!(status_resp["result"]["status"], "RECEIVING");
    assert_eq!(status_resp["result"]["bytes_received"], 65536);
    assert_eq!(status_resp["result"]["custody_chain_valid"], true);

    // 6. Test Offset Mismatch Rejection (EVID-007)
    let (conflict_code, conflict_body) =
        upload_chunk(port, &session_id, &upload_token, 0, chunk1).await;
    assert_eq!(
        conflict_code, 409,
        "Expected 409 Conflict on bad offset: {}",
        conflict_body
    );

    // 7. Upload Second Chunk (64 KB) at offset 65536 (Resume / Progress)
    let chunk2 = &payload[64 * 1024..];
    let (code2, header2) = upload_chunk(port, &session_id, &upload_token, 65536, chunk2).await;
    assert_eq!(code2, 200, "Chunk 2 upload failed: {}", header2);
    assert!(header2.contains("Upload-Offset: 131072"));

    // 8. Complete Ingest Session (EVID-004, EVID-006)
    let complete_resp = rpc_call(
        port,
        "evidence.ingest.complete",
        serde_json::json!({ "session_id": session_id }),
    )
    .await;
    assert!(complete_resp["error"].is_null(), "{:?}", complete_resp);
    assert_eq!(complete_resp["result"]["status"], "COMMITTED");
    assert_eq!(complete_resp["result"]["format"], "pcapng");
    assert_eq!(
        complete_resp["result"]["parser_status"],
        "PENDING_IMPLEMENTATION"
    );
    assert_eq!(complete_resp["result"]["sha256"], expected_sha256);
    assert_eq!(complete_resp["result"]["blake3"], expected_blake3);
    assert_eq!(complete_resp["result"]["size_bytes"], payload.len() as u64);

    let artifact_id = complete_resp["result"]["artifact_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Verify Staging file was moved and CAS object exists
    let staging_file = temp_dir
        .join("staging")
        .join(format!("{}.part", session_id));
    assert!(
        !staging_file.exists(),
        "Staging file should be committed into CAS and removed from staging"
    );
    assert!(app.cas.has_object(&expected_blake3));

    // 9. Verify Tamper-Evident Chain-of-Custody (EVID-006)
    let custody_resp = rpc_call(
        port,
        "evidence.custody.verify",
        serde_json::json!({ "artifact_id": artifact_id }),
    )
    .await;
    assert!(custody_resp["error"].is_null(), "{:?}", custody_resp);
    assert_eq!(custody_resp["result"]["chain_valid"], true);
    let event_count = custody_resp["result"]["event_count"].as_u64().unwrap();
    assert!(
        event_count >= 4,
        "Expected at least 4 custody events (RECEIVED, HASHED, VALIDATED, COMMITTED_TO_CAS)"
    );

    // 10. Test CAS Deduplication (EVID-005)
    // Upload identical bytes in a new session
    let begin_dedup = rpc_call(
        port,
        "evidence.ingest.begin",
        serde_json::json!({
            "case_id": case_id,
            "filename": "memory_sample_copy.raw",
            "declared_size_bytes": payload.len() as u64,
            "actor_id": "investigator-02"
        }),
    )
    .await;
    let session2_id = begin_dedup["result"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let token2 = begin_dedup["result"]["upload_token"]
        .as_str()
        .unwrap()
        .to_string();

    let (c_code, _) = upload_chunk(port, &session2_id, &token2, 0, &payload).await;
    assert_eq!(c_code, 200);

    let complete_dedup = rpc_call(
        port,
        "evidence.ingest.complete",
        serde_json::json!({ "session_id": session2_id }),
    )
    .await;
    assert_eq!(complete_dedup["result"]["status"], "COMMITTED");
    assert_eq!(complete_dedup["result"]["blake3"], expected_blake3);
    let artifact2_id = complete_dedup["result"]["artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        artifact_id, artifact2_id,
        "Deduplication creates separate artifact reference"
    );

    // Verify dedup custody chain is also valid
    let custody_dedup = rpc_call(
        port,
        "evidence.custody.verify",
        serde_json::json!({ "artifact_id": artifact2_id }),
    )
    .await;
    assert_eq!(custody_dedup["result"]["chain_valid"], true);

    // 11. Test Cancel Protection on Committed Session (EVID-008)
    let cancel_committed = rpc_call(
        port,
        "evidence.ingest.cancel",
        serde_json::json!({ "session_id": session_id }),
    )
    .await;
    assert!(
        !cancel_committed["error"].is_null(),
        "Cancelling committed session must fail"
    );
    assert_eq!(cancel_committed["error"]["status"], 409);

    // 12. Test Cancel on Uncommitted Session (EVID-008)
    let begin_cancel = rpc_call(
        port,
        "evidence.ingest.begin",
        serde_json::json!({
            "case_id": case_id,
            "filename": "aborted_upload.bin",
            "declared_size_bytes": 1000,
            "actor_id": "investigator-01"
        }),
    )
    .await;
    let cancel_session_id = begin_cancel["result"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let cancel_token = begin_cancel["result"]["upload_token"]
        .as_str()
        .unwrap()
        .to_string();

    upload_chunk(port, &cancel_session_id, &cancel_token, 0, b"partial").await;
    let cancel_resp = rpc_call(
        port,
        "evidence.ingest.cancel",
        serde_json::json!({ "session_id": cancel_session_id }),
    )
    .await;
    assert!(cancel_resp["error"].is_null());
    assert_eq!(cancel_resp["result"]["status"], "CANCELLED");

    let cancel_status = rpc_call(
        port,
        "evidence.ingest.status",
        serde_json::json!({ "session_id": cancel_session_id }),
    )
    .await;
    assert_eq!(cancel_status["result"]["status"], "CANCELLED");

    // 13. Test Magic Byte Format Detection (EVTX magic: ElfFile\0)
    let mut evtx_header = vec![0u8; 4096];
    evtx_header[0..8].copy_from_slice(b"ElfFile\0");
    let begin_evtx = rpc_call(
        port,
        "evidence.ingest.begin",
        serde_json::json!({
            "case_id": case_id,
            "filename": "Security.evtx",
            "declared_size_bytes": evtx_header.len() as u64,
            "actor_id": "collector-agent"
        }),
    )
    .await;
    let evtx_sess_id = begin_evtx["result"]["session_id"].as_str().unwrap();
    let evtx_token = begin_evtx["result"]["upload_token"].as_str().unwrap();

    let (evtx_up_code, _) = upload_chunk(port, evtx_sess_id, evtx_token, 0, &evtx_header).await;
    assert_eq!(evtx_up_code, 200);

    let complete_evtx = rpc_call(
        port,
        "evidence.ingest.complete",
        serde_json::json!({ "session_id": evtx_sess_id }),
    )
    .await;
    assert_eq!(complete_evtx["result"]["status"], "COMMITTED");
    assert_eq!(complete_evtx["result"]["format"], "evtx");
    assert_eq!(
        complete_evtx["result"]["parser_status"],
        "PENDING_IMPLEMENTATION"
    );

    // 14. Test Unrecognized Magic Byte Quarantine (EVID-006)
    let bad_bytes = b"NOT_A_VALID_FORENSIC_FORMAT_12345678";
    let begin_bad = rpc_call(
        port,
        "evidence.ingest.begin",
        serde_json::json!({
            "case_id": case_id,
            "filename": "corrupted.dat",
            "declared_size_bytes": bad_bytes.len() as u64,
            "actor_id": "investigator-01"
        }),
    )
    .await;
    let bad_sess_id = begin_bad["result"]["session_id"].as_str().unwrap();
    let bad_token = begin_bad["result"]["upload_token"].as_str().unwrap();

    let (bad_up_code, _) = upload_chunk(port, bad_sess_id, bad_token, 0, bad_bytes).await;
    assert_eq!(bad_up_code, 200);

    let complete_bad = rpc_call(
        port,
        "evidence.ingest.complete",
        serde_json::json!({ "session_id": bad_sess_id }),
    )
    .await;
    assert!(
        !complete_bad["error"].is_null(),
        "Unrecognized magic must fail completion"
    );
    assert!(complete_bad["error"]["detail"]
        .as_str()
        .unwrap()
        .contains("QUARANTINED"));

    let bad_status = rpc_call(
        port,
        "evidence.ingest.status",
        serde_json::json!({ "session_id": bad_sess_id }),
    )
    .await;
    assert_eq!(bad_status["result"]["status"], "QUARANTINED");
    assert_eq!(bad_status["result"]["custody_chain_valid"], true);

    let _ = tokio::fs::remove_dir_all(temp_dir).await;
}
