use std::fs;
use std::path::PathBuf;

use blake3::Hasher;
use tool_adapters::pcap::phase3::{parse_capture_file_with_sink, TimestampResolution};

fn fixture_bytes() -> Vec<u8> {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forensics/pcapng_multi_section_interfaces.pcapng.hex");
    assert!(
        fixture.exists(),
        "mandatory Phase 3 forensic fixture missing"
    );
    let hex = fs::read_to_string(fixture).expect("read mandatory fixture");
    hex.split_whitespace()
        .flat_map(|line| {
            (0..line.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn temp_fixture() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pcapng_multi_section_interfaces_{}.pcapng",
        uuid::Uuid::now_v7()
    ));
    fs::write(&path, fixture_bytes()).expect("write mandatory acceptance fixture");
    path
}

#[test]
fn gate_h04_multi_section_interface_timestamp_semantics() {
    let path = temp_fixture();
    let fixture_bytes = fs::read(&path).unwrap();
    assert_eq!(
        blake3::hash(&fixture_bytes).to_hex().to_string(),
        "b39fc9fbfbe5390d8beebc2061d936c3dab60be2892a03274aa1d43729a03f16"
    );
    let mut packets = Vec::new();
    let summary = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("PCAPNG fixture must parse through streaming path");
    fs::remove_file(path).expect("remove temporary fixture");

    assert_eq!(summary.packets_decoded, 3);
    assert_eq!(summary.interfaces.len(), 3);

    let first = packets[0].capture_timestamp.as_ref().unwrap();
    assert_eq!(first.raw_value, 1_700_000_000_123_456);
    assert_eq!(first.resolution, TimestampResolution::Decimal(6));
    assert_eq!(first.offset_seconds, 0);
    assert!(!first.precision_loss);
    assert_eq!(packets[0].section_index, Some(0));
    assert_eq!(packets[0].interface_id, Some(0));

    let second = packets[1].capture_timestamp.as_ref().unwrap();
    assert_eq!(second.raw_value, 1_700_000_000_123_456_789);
    assert_eq!(second.resolution, TimestampResolution::Decimal(9));
    assert_eq!(second.offset_seconds, 3600);
    assert_eq!(packets[1].section_index, Some(0));
    assert_eq!(packets[1].interface_id, Some(1));

    let third = packets[2].capture_timestamp.as_ref().unwrap();
    assert_eq!(third.raw_value, 1_025);
    assert_eq!(third.resolution, TimestampResolution::Binary(10));
    assert_eq!(third.offset_seconds, -3600);
    assert!(third.precision_loss);
    assert_eq!(packets[2].section_index, Some(1));
    assert_eq!(packets[2].interface_id, Some(0));

    assert!(packets[1]
        .packet_locator
        .starts_with("pcapng://section/0/interface/1/"));
    assert!(packets[2]
        .packet_locator
        .starts_with("pcapng://section/1/interface/0/"));
}

#[test]
fn gate_h05_packet_hash_is_hash_of_captured_bytes() {
    let path = temp_fixture();
    let mut packets = Vec::new();
    parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .unwrap();
    fs::remove_file(path).unwrap();

    let expected = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
    let mut hasher = Hasher::new();
    hasher.update(&expected);
    assert_eq!(
        packets[0].packet_hash,
        hasher.finalize().to_hex().to_string()
    );
    assert_eq!(packets[0].captured_len, expected.len() as u32);
    assert_eq!(packets[0].original_len, expected.len() as u32);
}
