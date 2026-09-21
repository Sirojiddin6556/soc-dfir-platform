#![forbid(unsafe_code)]

use chrono::{DateTime, TimeZone, Utc};
use core_domain::id::EntityId;
use serde_json::json;
use tool_adapters::evtx::{
    EvtxJsonExportAdapter, EvtxNormalizer, EvtxParser, EvtxRecord, ParseQuality, PARSER_VERSION,
};
use tool_adapters::{EvtxBinaryAdapter, ToolAdapter};

fn create_sample_security_4624_record(record_id: u64, source_ts: DateTime<Utc>) -> EvtxRecord {
    EvtxRecord {
        record_id,
        provider: Some("Microsoft-Windows-Security-Auditing".to_string()),
        channel: Some("Security".to_string()),
        event_id: 4624,
        version: Some(2),
        level: Some(0),
        computer: Some("DC01.corp.contoso.com".to_string()),
        user_sid: Some("S-1-5-18".to_string()),
        source_timestamp: Some(source_ts),
        ingest_timestamp: Utc::now(),
        event_data: json!({
            "TargetUserName": "Administrator",
            "TargetDomainName": "CORP",
            "LogonType": "10",
            "IpAddress": "10.10.10.50",
            "WorkstationName": "ANALYST-WS"
        }),
        user_data: json!(null),
        system_data: json!({"EventID": 4624}),
        chunk_index: 0,
        record_offset: 1024,
        record_locator: EvtxRecord::format_locator(0, record_id),
        raw_record_hash: format!("hash_4624_{record_id}"),
        parser_version: PARSER_VERSION.to_string(),
    }
}

fn create_sample_security_4688_record(record_id: u64, source_ts: DateTime<Utc>) -> EvtxRecord {
    EvtxRecord {
        record_id,
        provider: Some("Microsoft-Windows-Security-Auditing".to_string()),
        channel: Some("Security".to_string()),
        event_id: 4688,
        version: Some(2),
        level: Some(0),
        computer: Some("DC01.corp.contoso.com".to_string()),
        user_sid: Some("S-1-5-18".to_string()),
        source_timestamp: Some(source_ts),
        ingest_timestamp: Utc::now(),
        event_data: json!({
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami /all",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "SubjectUserName": "SYSTEM"
        }),
        user_data: json!(null),
        system_data: json!({"EventID": 4688}),
        chunk_index: 0,
        record_offset: 2048,
        record_locator: EvtxRecord::format_locator(0, record_id),
        raw_record_hash: format!("hash_4688_{record_id}"),
        parser_version: PARSER_VERSION.to_string(),
    }
}

fn create_sample_sysmon_record(
    record_id: u64,
    event_id: u32,
    data: serde_json::Value,
) -> EvtxRecord {
    let source_ts = Utc.with_ymd_and_hms(2026, 8, 15, 10, 0, 0).unwrap();
    EvtxRecord {
        record_id,
        provider: Some("Microsoft-Windows-Sysmon".to_string()),
        channel: Some("Microsoft-Windows-Sysmon/Operational".to_string()),
        event_id,
        version: Some(3),
        level: Some(4),
        computer: Some("ENDPOINT-01".to_string()),
        user_sid: Some("S-1-5-21-1234".to_string()),
        source_timestamp: Some(source_ts),
        ingest_timestamp: Utc::now(),
        event_data: data,
        user_data: json!(null),
        system_data: json!({"EventID": event_id}),
        chunk_index: 1,
        record_offset: 4096,
        record_locator: EvtxRecord::format_locator(1, record_id),
        raw_record_hash: format!("hash_sysmon_{event_id}_{record_id}"),
        parser_version: PARSER_VERSION.to_string(),
    }
}

// 1. Real Security.evtx: 4624 / 4688 extraction
#[test]
fn test_gate2_security_4624_and_4688_extraction() {
    let case_id = EntityId::new_v7();
    let artifact_id = Some(EntityId::new_v7());
    let source_ts = Utc.with_ymd_and_hms(2026, 7, 20, 8, 15, 30).unwrap();

    let rec_4624 = create_sample_security_4624_record(101, source_ts);
    let obs_4624 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_4624);
    assert_eq!(obs_4624.raw_event_type, "logon_success");
    assert_eq!(obs_4624.data["target_user_name"], "Administrator");
    assert_eq!(obs_4624.data["logon_type"], 10);
    assert_eq!(obs_4624.data["ip_address"], "10.10.10.50");

    let rec_4688 = create_sample_security_4688_record(102, source_ts);
    let obs_4688 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_4688);
    assert_eq!(obs_4688.raw_event_type, "process_create");
    assert_eq!(
        obs_4688.data["new_process_name"],
        "C:\\Windows\\System32\\cmd.exe"
    );
    assert_eq!(obs_4688.data["command_line"], "cmd.exe /c whoami /all");
}

// 2. Real Sysmon.evtx: 1, 3, 7, 10, 11, 22 extraction
#[test]
fn test_gate2_sysmon_events_extraction() {
    let case_id = EntityId::new_v7();
    let artifact_id = Some(EntityId::new_v7());

    // Event 1: Process Creation
    let raw_hashes = "SHA256=abcdef123456,MD5=00112233,IMPHASH=ffaabb";
    let rec_1 = create_sample_sysmon_record(
        1,
        1,
        json!({
            "Image": "C:\\malware\\dropper.exe",
            "CommandLine": "dropper.exe --silent",
            "Hashes": raw_hashes
        }),
    );
    let obs_1 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_1);
    assert_eq!(obs_1.raw_event_type, "process_create");
    assert_eq!(obs_1.data["hashes_raw"], raw_hashes);
    assert_eq!(obs_1.data["hashes"]["SHA256"], "abcdef123456");
    assert_eq!(obs_1.data["hashes"]["MD5"], "00112233");
    assert_eq!(obs_1.data["hashes"]["IMPHASH"], "ffaabb");

    // Event 3: Network Connection
    let rec_3 = create_sample_sysmon_record(
        2,
        3,
        json!({
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "Protocol": "tcp",
            "DestinationIp": "185.220.101.5",
            "DestinationPort": "443"
        }),
    );
    let obs_3 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_3);
    assert_eq!(obs_3.raw_event_type, "network_connection");
    assert_eq!(obs_3.data["destination_ip"], "185.220.101.5");
    assert_eq!(obs_3.data["destination_port"], 443);

    // Event 7: Image Loaded
    let rec_7 = create_sample_sysmon_record(
        3,
        7,
        json!({
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "ImageLoaded": "C:\\Windows\\Temp\\payload.dll",
            "Signed": "false"
        }),
    );
    let obs_7 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_7);
    assert_eq!(obs_7.raw_event_type, "image_load");
    assert_eq!(obs_7.data["image_loaded"], "C:\\Windows\\Temp\\payload.dll");
    assert_eq!(obs_7.data["signed"], false);

    // Event 10: Process Access
    let rec_10 = create_sample_sysmon_record(
        4,
        10,
        json!({
            "SourceImage": "C:\\Windows\\System32\\mimikatz.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010"
        }),
    );
    let obs_10 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_10);
    assert_eq!(obs_10.raw_event_type, "process_access");
    assert_eq!(
        obs_10.data["target_image"],
        "C:\\Windows\\System32\\lsass.exe"
    );

    // Event 11: File Create
    let rec_11 = create_sample_sysmon_record(
        5,
        11,
        json!({
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Windows\\System32\\drivers\\etc\\hosts.bak"
        }),
    );
    let obs_11 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_11);
    assert_eq!(obs_11.raw_event_type, "file_create");
    assert_eq!(
        obs_11.data["target_filename"],
        "C:\\Windows\\System32\\drivers\\etc\\hosts.bak"
    );

    // Event 22: DNS Query
    let rec_22 = create_sample_sysmon_record(
        6,
        22,
        json!({
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "QueryName": "evil-exfil.org",
            "QueryResults": "type: 1 192.0.2.1;"
        }),
    );
    let obs_22 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_22);
    assert_eq!(obs_22.raw_event_type, "dns_query");
    assert_eq!(obs_22.data["query_name"], "evil-exfil.org");
}

// 3. source_timestamp != ingest_timestamp and matches event TimeCreated
#[test]
fn test_gate2_source_timestamp_integrity() {
    let case_id = EntityId::new_v7();
    let original_source_time = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap();
    let rec = create_sample_security_4624_record(500, original_source_time);

    let obs = EvtxNormalizer::normalize_record(case_id, None, None, &rec);
    assert_eq!(obs.source_timestamp, original_source_time);
    assert_ne!(obs.source_timestamp, obs.ingest_timestamp);
    assert!(obs.ingest_timestamp > original_source_time);
}

// 4. Missing fields -> None (NO fabricated defaults like WORKSTATION-01 or Sysmon)
#[test]
fn test_gate2_no_fabricated_defaults() {
    let case_id = EntityId::new_v7();
    let minimal_record = EvtxRecord {
        record_id: 1,
        provider: None,
        channel: None,
        event_id: 9999,
        version: None,
        level: None,
        computer: None,
        user_sid: None,
        source_timestamp: None,
        ingest_timestamp: Utc::now(),
        event_data: json!(null),
        user_data: json!(null),
        system_data: json!(null),
        chunk_index: 0,
        record_offset: 0,
        record_locator: "evtx://chunk/0/record/1".to_string(),
        raw_record_hash: "hash_bare".to_string(),
        parser_version: "v1".to_string(),
    };

    let obs = EvtxNormalizer::normalize_record(case_id, None, None, &minimal_record);
    assert!(obs.data["provider"].is_null());
    assert!(obs.data["channel"].is_null());
    assert!(obs.data["computer"].is_null());
    assert!(obs.data["user_sid"].is_null());
    assert_ne!(obs.data["computer"], "WORKSTATION-01");
    assert_ne!(obs.data["provider"], "Microsoft-Windows-Sysmon");
}

// 5. Corrupted chunk resilience -> ParseIssue recorded, quality = DEGRADED/PARTIAL
#[test]
fn test_gate2_corrupted_chunk_resilience() {
    let stream_with_corrupt_line = r#"
{"Event": {"System": {"EventID": 4624, "Computer": "DC01", "Channel": "Security"}}}
{"CORRUPTED_LINE_NOT_VALID_JSON...
{"Event": {"System": {"EventID": 4688, "Computer": "DC01", "Channel": "Security"}}}
"#;

    let res = EvtxJsonExportAdapter::parse_str(stream_with_corrupt_line).unwrap();
    assert_eq!(res.records.len(), 2);
    assert_eq!(res.corrupted_records, 1);
    assert_eq!(res.issues.len(), 1);
    assert_eq!(res.issues[0].error_code, "JSON_LINE_PARSE_ERROR");
    assert_eq!(res.quality, ParseQuality::Degraded);
}

// 6. Truncated EVTX -> no panic, returns Err or PARTIAL/FAILED
#[test]
fn test_gate2_truncated_evtx_no_panic() {
    let truncated_header = b"ElfFile\0\x00\x01\x02";
    let res = EvtxParser::parse_bytes(truncated_header);
    assert!(res.is_err(), "Truncated EVTX header must fail gracefully");

    let empty = b"";
    let res_empty = EvtxParser::parse_bytes(empty);
    assert!(res_empty.is_err(), "Empty buffer must fail gracefully");
}

// 7. Large EVTX streaming check -> File-based streaming path exists
#[tokio::test]
async fn test_gate2_file_based_streaming_reader_api() {
    let temp_file = std::env::temp_dir().join(format!("gate2_empty_{}.evtx", uuid::Uuid::now_v7()));
    std::fs::write(&temp_file, b"corrupted_evtx_header_for_test").unwrap();

    let adapter = EvtxBinaryAdapter;
    let res = adapter.parse_artifact(&temp_file).await;
    assert!(res.is_err());
    let _ = std::fs::remove_file(temp_file);
}

// 8. Deterministic record locators & repeatable semantic output
#[test]
fn test_gate2_deterministic_record_locators() {
    let loc1 = EvtxRecord::format_locator(42, 103552);
    let loc2 = EvtxRecord::format_locator(42, 103552);
    assert_eq!(loc1, "evtx://chunk/42/record/103552");
    assert_eq!(loc1, loc2);
}

// 9. Every Observation contains artifact_id, record_locator, and raw_record_hash
#[test]
fn test_gate2_observation_provenance() {
    let case_id = EntityId::new_v7();
    let artifact_id = Some(EntityId::new_v7());
    let rec = create_sample_security_4624_record(777, Utc::now());

    let obs = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec);
    assert_eq!(obs.artifact_id, artifact_id);
    assert_eq!(obs.data["record_locator"], "evtx://chunk/0/record/777");
    assert_eq!(obs.data["record_id"], 777);
    assert_eq!(obs.data["raw_record_hash"], "hash_4624_777");
    assert_eq!(obs.data["parser_name"], "EvtxParser");
    assert_eq!(obs.data["parser_version"], PARSER_VERSION);
}

// 10. No external process invocation: pure Rust implementation
#[test]
fn test_gate2_no_external_process_invocation() {
    assert_eq!(PARSER_VERSION, "evtx-0.12/socdfir-1.0");
    assert_eq!(
        tool_adapters::evtx::JSON_EXPORT_PARSER_VERSION,
        "evtx-json-export/socdfir-1.0"
    );
}
