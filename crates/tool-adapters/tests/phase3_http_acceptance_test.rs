use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use tool_adapters::pcap::phase3::{
    extract_http, parse_capture_file_with_sink, reassemble_tcp, reconstruct_flows, HttpMessage,
    ReassemblyStatus,
};

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forensics/http")
        .join(name);
    assert!(
        path.exists(),
        "mandatory HTTP fixture missing: {}",
        path.display()
    );
    let hex = fs::read_to_string(path).expect("read mandatory HTTP fixture");
    hex.split_whitespace()
        .flat_map(|line| {
            (0..line.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn parse_fixture(name: &str) -> (Vec<u8>, Vec<tool_adapters::pcap::ParsedPacket>) {
    let bytes = fixture_bytes(name);
    let path = std::env::temp_dir().join(format!("http_acceptance_{}.pcap", uuid::Uuid::now_v7()));
    fs::write(&path, &bytes).unwrap();
    let mut packets = Vec::new();
    let summary = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("HTTP fixture container must parse");
    fs::remove_file(path).unwrap();
    assert_eq!(summary.packets_decoded as usize, packets.len());
    (bytes, packets)
}

fn observation_for_http(message: &HttpMessage) -> Observation {
    Observation {
        id: EntityId::new_v7(),
        case_id: EntityId::new_v7(),
        artifact_id: None,
        tool_run_id: None,
        source_tool: "pcap_parser".into(),
        raw_event_type: "http_message".into(),
        source_timestamp: None,
        ingest_timestamp: Utc::now(),
        data: serde_json::to_value(message).unwrap(),
        network_quality: None,
        network_provenance: None,
    }
}

#[test]
fn gate_h12_h13_segmented_http_request_reassembles_and_discards_body() {
    let raw = fixture_bytes("http_segmented_request.pcap.hex");
    assert_eq!(raw.len(), 313);
    assert_eq!(
        blake3::hash(&raw).to_hex().to_string(),
        "bef06a284e58787d281104a988baf9d9508008bbddf4a6bced90ea35ad56b230"
    );
    let (raw, packets) = parse_fixture("http_segmented_request.pcap.hex");
    assert_eq!(packets.len(), 3);
    assert_eq!(reconstruct_flows(&packets).len(), 1);
    assert_eq!(packets[1].tcp_sequence, Some(1008));
    assert_eq!(packets[2].tcp_sequence, Some(1023));
    assert!(raw
        .windows(b"SECRET_BODY_1234".len())
        .any(|w| w == b"SECRET_BODY_1234"));

    let stream = reassemble_tcp(&packets);
    assert_eq!(stream.status, ReassemblyStatus::Complete);
    assert!(stream.issues.is_empty());
    assert_eq!(stream.overlap_conflicts, 0);
    assert!(stream
        .bytes
        .windows(b"SECRET_BODY_1234".len())
        .any(|w| w == b"SECRET_BODY_1234"));

    let http = extract_http(&stream.bytes).expect("segmented request must parse");
    assert_eq!(http.method.as_deref(), Some("GET"));
    assert_eq!(http.uri.as_deref(), Some("/admin"));
    assert_eq!(http.host.as_deref(), Some("example.test"));
    assert_eq!(http.content_length, Some(16));
    assert!(!http.body_retained);

    let observation = observation_for_http(&http);
    let serialized = serde_json::to_string(&observation).unwrap();
    assert!(!serialized.contains("SECRET_BODY_1234"));
    assert!(!serde_json::to_string(&http)
        .unwrap()
        .contains("SECRET_BODY_1234"));
}

#[test]
fn gate_h12_h13_segmented_http_response_preserves_metadata_without_body() {
    let (raw, packets) = parse_fixture("http_segmented_response.pcap.hex");
    assert_eq!(raw.len(), 259);
    assert_eq!(
        blake3::hash(&raw).to_hex().to_string(),
        "c9ee7c4253beda0eb0d3faeb2d26deda0ccaf1a0f7b01997dcb2a45f8b5df965"
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(reconstruct_flows(&packets).len(), 1);

    let stream = reassemble_tcp(&packets);
    assert_eq!(stream.status, ReassemblyStatus::Complete);
    assert!(stream.issues.is_empty());
    assert_eq!(stream.overlap_conflicts, 0);

    let http = extract_http(&stream.bytes).expect("segmented response must parse");
    assert_eq!(http.status_code, Some(200));
    assert_eq!(http.server.as_deref(), Some("nginx"));
    assert_eq!(http.content_type.as_deref(), Some("text/html"));
    assert_eq!(http.content_length, Some(16));
    assert!(!http.body_retained);
    assert!(!serde_json::to_string(&observation_for_http(&http))
        .unwrap()
        .contains("RESPONSE_BODY_16"));
}
