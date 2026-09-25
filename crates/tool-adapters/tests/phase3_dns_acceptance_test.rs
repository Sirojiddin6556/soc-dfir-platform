use std::fs;
use std::path::{Path, PathBuf};

use tool_adapters::pcap::phase3::{
    extract_dns_detailed, extract_dns_tcp_messages_detailed, parse_capture_file_with_sink,
    reassemble_tcp, CaptureParseIssueKind, DnsParseIssueKind,
};

mod support;
use support::pcap_builder::{TcpFixture, UdpFixture};

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forensics/dns")
        .join(name);
    assert!(
        path.exists(),
        "mandatory DNS fixture missing: {}",
        path.display()
    );
    let hex = fs::read_to_string(path).expect("read mandatory DNS fixture");
    hex.split_whitespace()
        .flat_map(|line| {
            (0..line.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn malformed_fixture_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forensics/malformed")
        .join(name);
    assert!(
        path.exists(),
        "mandatory malformed fixture missing: {}",
        path.display()
    );
    let hex = fs::read_to_string(path).expect("read mandatory malformed fixture");
    hex.split_whitespace()
        .flat_map(|line| {
            (0..line.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn materialize(bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("dns_acceptance_{}.pcap", uuid::Uuid::now_v7()));
    fs::write(&path, bytes).expect("materialize DNS fixture");
    assert!(Path::new(&path).exists());
    path
}

fn classic_pcap(snaplen: u32, records: &[(u32, u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(&snaplen.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    for (ts_usec, incl_len, orig_len, payload) in records {
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&ts_usec.to_le_bytes());
        bytes.extend_from_slice(&incl_len.to_le_bytes());
        bytes.extend_from_slice(&orig_len.to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    bytes
}

fn parse_generated_pcap(
    bytes: &[u8],
) -> (
    tool_adapters::pcap::phase3::PcapParseResult,
    Vec<tool_adapters::pcap::ParsedPacket>,
) {
    let path = materialize(bytes);
    let mut packets = Vec::new();
    let result = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("generated PCAP must return a summary");
    fs::remove_file(path).unwrap();
    (result, packets)
}

#[test]
fn gate_h10_udp_malformed_packet_does_not_abort_following_dns_packets() {
    let bytes = fixture_bytes("dns_udp_resilience.pcap.hex");
    assert_eq!(
        blake3::hash(&bytes).to_hex().to_string(),
        "db5db559ae79a96110524ce52634db4fda9c63653401967c94ba0713b23f9dc2"
    );
    let path = materialize(&bytes);
    let mut packets = Vec::new();
    let summary = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("valid PCAP must pass the streaming reader");
    fs::remove_file(path).unwrap();

    assert_eq!(summary.packets_decoded, 3);
    assert_eq!(packets.len(), 3);
    let malformed = extract_dns_detailed(&packets[0].payload).unwrap_err();
    assert_eq!(malformed.kind, DnsParseIssueKind::CompressionLoop);

    let a = extract_dns_detailed(&packets[1].payload).expect("A response must survive");
    assert_eq!(a.id, 0x2002);
    assert_eq!(a.qname.as_deref(), Some("example.com"));
    assert_eq!(a.answers[0].name, "example.com");
    assert_eq!(a.answers[0].record_type, 1);
    assert_eq!(a.answers[0].record_class, 1);
    assert_eq!(a.answers[0].ttl, 60);
    assert_eq!(a.answers[0].rdata_len, 4);
    assert_eq!(a.answers[0].value.as_deref(), Some("1.2.3.4"));
    assert!(a.answers[0].rdata_hash.is_some());

    let aaaa = extract_dns_detailed(&packets[2].payload).expect("AAAA response must survive");
    assert_eq!(aaaa.id, 0x2003);
    assert_eq!(aaaa.answers[0].name, "example.com");
    assert_eq!(aaaa.answers[0].record_type, 28);
    assert_eq!(aaaa.answers[0].rdata_len, 16);
    assert_eq!(aaaa.answers[0].value.as_deref(), Some("::1"));
}

#[test]
fn gate_h11_permanent_pointer_cycle_fixture_is_valid_container() {
    let bytes = fixture_bytes("dns_pointer_cycle.pcap.hex");
    assert_eq!(
        blake3::hash(&bytes).to_hex().to_string(),
        "ca7fb474ceb8929cb4118375b8a5f8541933cd552c1cf203c4f3e063e0b94b51"
    );
    let path = materialize(&bytes);
    let mut packets = Vec::new();
    let summary = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("valid PCAP container must parse");
    fs::remove_file(path).unwrap();

    assert_eq!(summary.packets_decoded, 1);
    assert_eq!(packets.len(), 1);
    let issue = extract_dns_detailed(&packets[0].payload).unwrap_err();
    assert_eq!(issue.kind, DnsParseIssueKind::CompressionLoop);
}

#[test]
fn gate_h11_immutable_pointer_jump_limit_is_not_a_compression_loop() {
    let bytes = fixture_bytes("dns_pointer_jump_limit.pcap.hex");
    assert_eq!(
        blake3::hash(&bytes).to_hex().to_string(),
        "7148d2f15e0e1e4a4628782faa0712df1901c5827dd857352cf9628c2d2e9b7e"
    );

    let path = materialize(&bytes);
    let mut packets = Vec::new();
    let summary = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("valid PCAP container must parse");
    fs::remove_file(path).unwrap();

    assert_eq!(summary.packets_decoded, 1);
    assert_eq!(packets.len(), 1);
    let issue = extract_dns_detailed(&packets[0].payload).unwrap_err();
    assert_eq!(issue.kind, DnsParseIssueKind::CompressionJumpLimitExceeded);
    assert_ne!(issue.kind, DnsParseIssueKind::CompressionLoop);
}

#[test]
fn gate_h11_dns_failure_isolation_keeps_independent_tcp_message_alive() {
    let malformed_udp = vec![
        0x40, 0x01, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1,
    ];
    let incomplete_tcp = vec![0, 20, 0xaa, 0xbb, 0xcc];
    let valid_dns = vec![
        0x40, 0x02, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    let mut incomplete = TcpFixture::new(incomplete_tcp, 1000);
    incomplete.dst_port = 54;
    let mut valid = TcpFixture::new(
        [(valid_dns.len() as u16 >> 8) as u8, valid_dns.len() as u8]
            .into_iter()
            .chain(valid_dns)
            .collect(),
        2000,
    );
    valid.dst_port = 55;
    let capture = support::pcap_builder::classic_pcap(&[
        UdpFixture::new(malformed_udp).ethernet_frame(),
        incomplete.ethernet_frame(),
        valid.ethernet_frame(),
    ]);

    let (summary, packets) = parse_generated_pcap(&capture);
    assert_eq!(summary.packets_decoded, 3);
    assert_eq!(
        summary.quality,
        tool_adapters::pcap::phase3::PcapQuality::Complete
    );
    assert_eq!(
        extract_dns_detailed(&packets[0].payload).unwrap_err().kind,
        DnsParseIssueKind::CompressionLoop
    );
    assert_eq!(
        extract_dns_tcp_messages_detailed(&packets[1].payload)
            .unwrap_err()
            .kind,
        DnsParseIssueKind::IncompleteTcpFrame
    );
    let messages = extract_dns_tcp_messages_detailed(&packets[2].payload)
        .expect("independent valid TCP DNS message must survive");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, 0x4002);
    assert_eq!(messages[0].qname.as_deref(), Some("example.com"));
}

#[test]
fn gate_h11_second_wave_name_failures_are_typed_and_non_panicking() {
    let mut pointer_out_of_bounds = vec![0u8; 14];
    pointer_out_of_bounds[4..6].copy_from_slice(&1u16.to_be_bytes());
    pointer_out_of_bounds[12..14].copy_from_slice(&[0xc0, 0xff]);
    assert_eq!(
        extract_dns_detailed(&pointer_out_of_bounds)
            .unwrap_err()
            .kind,
        DnsParseIssueKind::CompressionPointerOutOfBounds
    );

    let mut truncated_pointer = vec![0u8; 13];
    truncated_pointer[4..6].copy_from_slice(&1u16.to_be_bytes());
    truncated_pointer[12] = 0xc0;
    assert_eq!(
        extract_dns_detailed(&truncated_pointer).unwrap_err().kind,
        DnsParseIssueKind::TruncatedName
    );

    let mut invalid_label_type = vec![0u8; 13];
    invalid_label_type[4..6].copy_from_slice(&1u16.to_be_bytes());
    invalid_label_type[12] = 0x40;
    assert_eq!(
        extract_dns_detailed(&invalid_label_type).unwrap_err().kind,
        DnsParseIssueKind::InvalidLabelType
    );

    let mut name_too_long = vec![0u8; 12];
    name_too_long[4..6].copy_from_slice(&1u16.to_be_bytes());
    for _ in 0..4 {
        name_too_long.push(63);
        name_too_long.extend(std::iter::repeat_n(b'a', 63));
    }
    name_too_long.push(0);
    assert_eq!(
        extract_dns_detailed(&name_too_long).unwrap_err().kind,
        DnsParseIssueKind::ExpandedNameTooLong
    );
}

#[test]
fn gate_h11_permanent_truncated_rr_fixture_is_dns_only_failure() {
    let bytes = fixture_bytes("dns_truncated_rr.pcap.hex");
    assert_eq!(
        blake3::hash(&bytes).to_hex().to_string(),
        "3f8503db7c16fba21451858333a789b65276d7be8fc3520579ec103f6568e393"
    );
    let path = materialize(&bytes);
    let mut packets = Vec::new();
    let summary = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("valid PCAP container must parse");
    fs::remove_file(path).unwrap();

    assert_eq!(summary.packets_decoded, 1);
    let issue = extract_dns_detailed(&packets[0].payload).unwrap_err();
    assert_eq!(issue.kind, DnsParseIssueKind::TruncatedRecord);
}

#[test]
fn gate_h11_invalid_tcp_length_is_typed_and_does_not_panic() {
    let mut invalid = vec![0, 1, 0x01, 0x02];
    let issue = extract_dns_tcp_messages_detailed(&invalid).unwrap_err();
    assert_eq!(issue.kind, DnsParseIssueKind::InvalidTcpFrameLength);
    invalid = vec![0, 12, 0x01, 0x02];
    let issue = extract_dns_tcp_messages_detailed(&invalid).unwrap_err();
    assert_eq!(issue.kind, DnsParseIssueKind::IncompleteTcpFrame);
    invalid.clear();
    let issue = extract_dns_tcp_messages_detailed(&invalid);
    assert!(issue.unwrap().is_empty());
}

#[test]
fn gate_h11_builder_keeps_container_geometry_valid_for_malformed_dns() {
    let mut malformed = vec![0u8; 12];
    malformed[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    malformed[4..6].copy_from_slice(&1u16.to_be_bytes());
    malformed[6..8].copy_from_slice(&1u16.to_be_bytes());
    malformed.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    let valid = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let capture = support::pcap_builder::classic_pcap(&[
        UdpFixture::new(malformed).ethernet_frame(),
        UdpFixture::new(valid).ethernet_frame(),
    ]);
    let (summary, packets) = parse_generated_pcap(&capture);
    assert_eq!(summary.packets_decoded, 2);
    assert_eq!(packets.len(), 2);
    assert_eq!(
        packets[0].captured_len as usize,
        packets[0].payload.len() + 42
    );
    assert_eq!(
        packets[1].captured_len as usize,
        packets[1].payload.len() + 42
    );
    assert_eq!(
        extract_dns_detailed(&packets[0].payload).unwrap_err().kind,
        DnsParseIssueKind::CompressionLoop
    );
    assert!(extract_dns_detailed(&packets[1].payload).is_ok());
}

#[test]
fn gate_h11_tcp_builder_preserves_sequence_geometry() {
    let first = TcpFixture::new(b"dns-one".to_vec(), 1000);
    let second = TcpFixture::new(b"dns-two".to_vec(), first.next_sequence());
    let capture =
        support::pcap_builder::classic_pcap(&[first.ethernet_frame(), second.ethernet_frame()]);
    let (summary, packets) = parse_generated_pcap(&capture);

    assert_eq!(summary.packets_decoded, 2);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].tcp_sequence, Some(1000));
    assert_eq!(packets[1].tcp_sequence, Some(first.next_sequence()));
    assert_eq!(packets[0].payload, b"dns-one");
    assert_eq!(packets[1].payload, b"dns-two");
    assert_eq!(
        packets[0].captured_len as usize,
        packets[0].payload.len() + 54
    );
    assert_eq!(
        packets[1].captured_len as usize,
        packets[1].payload.len() + 54
    );
}

#[test]
fn gate_h18_malformed_classic_pcap_record_does_not_panic() {
    let bytes = malformed_fixture_bytes("pcap_bad_record_geometry.pcap.hex");
    assert_eq!(
        blake3::hash(&bytes).to_hex().to_string(),
        "c373c45cb8436aca4ad66941f4b52d1ecf3c4fcf39833e35518afddd7c4752a9"
    );
    let path = materialize(&bytes);
    let result = std::panic::catch_unwind(|| parse_capture_file_with_sink(&path, |_packet| Ok(())));
    fs::remove_file(path).unwrap();
    assert!(result.is_ok(), "malformed PCAP must not panic");
    let summary = result
        .unwrap()
        .expect("reader should return a degraded summary");
    assert_ne!(
        summary.quality,
        tool_adapters::pcap::phase3::PcapQuality::Complete
    );
    assert!(!summary.issues.is_empty());
    assert!(summary
        .diagnostics
        .iter()
        .any(|issue| issue.kind == CaptureParseIssueKind::TruncatedPacketRecord));
}

#[test]
fn gate_h18_reachable_typed_diagnostics_and_recovery_matrix() {
    let cases = [
        (
            "packet length limit",
            classic_pcap(
                u32::MAX,
                &[(0, 16 * 1024 * 1024 + 1, 16 * 1024 * 1024 + 1, vec![])],
            ),
            CaptureParseIssueKind::PacketLengthLimitExceeded,
            false,
        ),
        (
            "truncated record",
            classic_pcap(65_535, &[(0, 100, 100, vec![1, 2, 3])]),
            CaptureParseIssueKind::TruncatedPacketRecord,
            false,
        ),
        (
            "captured exceeds snaplen",
            classic_pcap(64, &[(0, 100, 100, vec![0; 100])]),
            CaptureParseIssueKind::CapturedLengthExceedsSnaplen,
            false,
        ),
        (
            "original smaller than captured",
            classic_pcap(65_535, &[(0, 100, 80, vec![0; 100]), (0, 0, 0, vec![])]),
            CaptureParseIssueKind::OriginalLengthSmallerThanCaptured,
            true,
        ),
        (
            "invalid timestamp fraction",
            classic_pcap(65_535, &[(1_000_000, 0, 0, vec![]), (0, 0, 0, vec![])]),
            CaptureParseIssueKind::InvalidTimestampFraction,
            true,
        ),
    ];

    for (name, bytes, expected_kind, recoverable) in cases {
        let (summary, packets) = parse_generated_pcap(&bytes);
        let diagnostic = summary
            .diagnostics
            .iter()
            .find(|issue| issue.kind == expected_kind)
            .unwrap_or_else(|| panic!("missing {expected_kind:?} diagnostic for {name}"));
        assert_eq!(diagnostic.recoverable, recoverable, "case: {name}");
        assert_ne!(
            summary.quality,
            tool_adapters::pcap::phase3::PcapQuality::Complete
        );
        if recoverable {
            let expected_packets: u64 =
                if expected_kind == CaptureParseIssueKind::InvalidTimestampFraction {
                    2
                } else {
                    1
                };
            assert_eq!(
                summary.packets_decoded, expected_packets,
                "following record must survive: {name}"
            );
            assert_eq!(
                packets.len(),
                expected_packets as usize,
                "following record must be delivered: {name}"
            );
        } else {
            assert!(
                summary.packets_decoded <= 1,
                "fatal case must stop deterministically: {name}"
            );
        }
    }

    let (_summary, packets) = parse_generated_pcap(&classic_pcap(
        65_535,
        &[(1_000_000, 0, 0, vec![]), (0, 0, 0, vec![])],
    ));
    assert_eq!(packets.len(), 2);
    assert!(packets[0].capture_timestamp.is_none());
    assert!(packets[1].capture_timestamp.is_some());
}

#[test]
fn gate_h10_tcp_fixture_validates_geometry_and_extracts_two_messages() {
    let bytes = fixture_bytes("dns_tcp_multi_segment.pcap.hex");
    assert_eq!(
        blake3::hash(&bytes).to_hex().to_string(),
        "a0aad303dca89b66431dae103a49a737d26ca554da2304927ffaffd0a57e7dbd"
    );
    let path = materialize(&bytes);
    let mut packets = Vec::new();
    let summary = parse_capture_file_with_sink(&path, |packet| {
        packets.push(packet);
        Ok(())
    })
    .expect("valid segmented DNS/TCP PCAP must parse");
    fs::remove_file(path).unwrap();

    assert_eq!(summary.packets_decoded, 3);
    assert_eq!(
        packets.iter().map(|p| p.captured_len).collect::<Vec<_>>(),
        [71, 72, 83]
    );
    assert_eq!(
        packets.iter().map(|p| p.payload_len).collect::<Vec<_>>(),
        [17, 18, 29]
    );
    assert_eq!(
        packets.iter().map(|p| p.tcp_sequence).collect::<Vec<_>>(),
        [Some(1000), Some(1017), Some(1035)]
    );
    for packet in &packets {
        assert_eq!(packet.captured_len, packet.original_len);
        assert_eq!(
            packet.captured_len as usize,
            14 + 20 + 20 + packet.payload_len
        );
    }

    let stream = reassemble_tcp(&packets);
    assert!(
        stream.issues.is_empty(),
        "unexpected issues: {:?}",
        stream.issues
    );
    let messages = extract_dns_tcp_messages_detailed(&stream.bytes).expect("two DNS frames");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, 0x3001);
    assert_eq!(messages[0].qname.as_deref(), Some("example.test"));
    assert_eq!(messages[0].qtype, Some(1));
    assert_eq!(messages[1].id, 0x3002);
    assert_eq!(messages[1].qname.as_deref(), Some("example.test"));
    assert_eq!(messages[1].qtype, Some(28));
}
