use std::path::PathBuf;

use tool_adapters::pcap::phase3::{
    extract_tls, parse_certificate_metadata, parse_tls_handshake_observation, parse_tls_records,
    protocol_quality_from_tls_issue, CertificateVisibility, TlsFieldVisibility, TlsParseIssue,
    TlsParseIssueKind,
};

fn client_hello_record() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend(std::iter::repeat_n(0x11, 32));
    body.extend_from_slice(&[0, 0, 4, 0xc0, 0x2f, 0x13, 1, 1, 0]);
    let name = b"example.test";
    let mut ext = vec![0, 0, 0, 17, 0, 15, 0, 0, name.len() as u8];
    ext.extend_from_slice(name);
    ext.extend_from_slice(&[
        0, 16, 0, 14, 0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
    ]);
    ext.extend_from_slice(&[0, 43, 0, 5, 4, 3, 3, 3, 4]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let hs = [vec![1, 0, 0, body.len() as u8], body].concat();
    [vec![22, 3, 3, (hs.len() >> 8) as u8, hs.len() as u8], hs].concat()
}

fn server_hello_record() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend(std::iter::repeat_n(0x22, 32));
    body.extend_from_slice(&[0, 0x13, 0x01, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
    let hs = [vec![2, 0, 0, body.len() as u8], body].concat();
    [vec![22, 3, 3, (hs.len() >> 8) as u8, hs.len() as u8], hs].concat()
}

fn certificate_fixture() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/forensics/tls/certificate_example_test.der.hex");
    std::fs::read_to_string(path)
        .unwrap()
        .split_whitespace()
        .flat_map(|line| {
            (0..line.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
        })
        .collect()
}

#[test]
fn gate_h19_quality_contract_keeps_visibility_separate_from_quality() {
    use core_domain::{CaptureQuality, FlowQuality, ProtocolQuality};
    use tool_adapters::pcap::phase3::{FlowQuality as PcapFlowQuality, PcapQuality};

    let matrix = [
        (
            PcapQuality::Complete,
            PcapFlowQuality::Complete,
            ProtocolQuality::Complete,
        ),
        (
            PcapQuality::Degraded,
            PcapFlowQuality::Complete,
            ProtocolQuality::Degraded,
        ),
        (
            PcapQuality::Complete,
            PcapFlowQuality::Partial,
            ProtocolQuality::Partial,
        ),
        (
            PcapQuality::Complete,
            PcapFlowQuality::Truncated,
            ProtocolQuality::Partial,
        ),
    ];
    assert_eq!(CaptureQuality::Complete, matrix[0].0.into());
    assert_eq!(FlowQuality::Partial, matrix[2].1.into());
    assert_eq!(ProtocolQuality::Partial, matrix[2].2);

    let encrypted_followup = core_domain::NetworkObservationQuality {
        capture: CaptureQuality::Complete,
        flow: Some(FlowQuality::Complete),
        protocol: Some(ProtocolQuality::Complete),
    };
    assert_eq!(encrypted_followup.protocol, Some(ProtocolQuality::Complete));
    assert_eq!(
        protocol_quality_from_tls_issue(&TlsParseIssue {
            kind: TlsParseIssueKind::TruncatedHandshake,
            offset: 0,
        }),
        ProtocolQuality::Partial
    );
    assert_eq!(
        protocol_quality_from_tls_issue(&TlsParseIssue {
            kind: TlsParseIssueKind::MalformedCertificate,
            offset: 0,
        }),
        ProtocolQuality::Degraded
    );
}

fn certificate_record() -> Vec<u8> {
    let der = certificate_fixture();
    let mut body = Vec::with_capacity(3 + 3 + der.len() + 2);
    let list_len = 3 + der.len() + 2;
    body.extend_from_slice(&(list_len as u32).to_be_bytes()[1..]);
    body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
    body.extend_from_slice(&der);
    body.extend_from_slice(&[0, 0]);
    let body_len = (body.len() as u32).to_be_bytes();
    let hs = [vec![11, body_len[1], body_len[2], body_len[3]], body].concat();
    let record_len = (hs.len() as u16).to_be_bytes();
    [vec![22, 3, 3, record_len[0], record_len[1]], hs].concat()
}

#[test]
fn gate_h14_segmented_clienthello_extracts_metadata() {
    let record = client_hello_record();
    let split = record.len() / 2;
    let obs =
        parse_tls_handshake_observation(&[&record[..split], &record[split..]].concat()).unwrap();
    assert!(obs.hello.client);
    assert_eq!(obs.hello.sni.as_deref(), Some("example.test"));
    assert_eq!(obs.hello.alpn, ["h2", "http/1.1"]);
    assert_eq!(obs.hello.offered_versions, [0x0303, 0x0304]);
    assert_eq!(
        obs.certificate_visibility,
        CertificateVisibility::NotPresentInCapture
    );
}

#[test]
fn gate_h15_serverhello_observes_version_and_cipher() {
    let obs = parse_tls_handshake_observation(&server_hello_record()).unwrap();
    assert!(!obs.hello.client);
    assert_eq!(obs.hello.selected_version, Some(0x0304));
    assert_eq!(obs.hello.selected_cipher, Some(0x1301));
    assert_eq!(
        obs.selected_alpn_visibility,
        TlsFieldVisibility::NotPresentInCapture
    );
}

#[test]
fn gate_h16_certificate_metadata_hashes_original_der() {
    let der = certificate_fixture();
    let metadata = parse_certificate_metadata(&der).unwrap();
    assert!(metadata.subject.unwrap().contains("example.test"));
    assert!(metadata.issuer.unwrap().contains("DFIR Test"));
    assert_eq!(
        metadata.certificate_sha256,
        "d5b4c889e729e9cf42c654853ae034ce291f4326477125bdaa01226a7e81bf55"
    );
}

#[test]
fn gate_h17_visibility_and_bounds_are_typed() {
    let hello = extract_tls(&client_hello_record()).unwrap();
    let encrypted = tool_adapters::pcap::phase3::tls13_encrypted_followup_observation(hello);
    assert_eq!(
        encrypted.certificate_visibility,
        CertificateVisibility::NotObservableEncryptedHandshake
    );
    assert_eq!(
        parse_tls_records(&[22, 3, 3, 0, 5, 1, 2]).unwrap_err().kind,
        TlsParseIssueKind::TruncatedRecord
    );
    let mut oversized = vec![22, 3, 3, 0x48, 1];
    oversized.extend(std::iter::repeat_n(0, 18_433));
    assert_eq!(
        parse_tls_records(&oversized).unwrap_err().kind,
        TlsParseIssueKind::RecordLengthLimitExceeded
    );
    assert_eq!(
        parse_certificate_metadata(&[0x30, 1, 0]).unwrap_err().kind,
        TlsParseIssueKind::MalformedCertificate
    );
}

#[test]
fn gate_h16_certificate_handshake_is_observed_and_hashed() {
    let data = [server_hello_record(), certificate_record()].concat();
    let obs = parse_tls_handshake_observation(&data).unwrap();
    assert_eq!(obs.certificate_visibility, CertificateVisibility::Observed);
    assert_eq!(obs.certificates.len(), 1);
    assert_eq!(
        obs.certificates[0].certificate_sha256,
        "d5b4c889e729e9cf42c654853ae034ce291f4326477125bdaa01226a7e81bf55"
    );
}

#[test]
fn gate_h15_tls13_rejects_tls12_cipher_suite() {
    let mut record = server_hello_record();
    let cipher = record
        .windows(2)
        .position(|window| window == [0x13, 0x01])
        .unwrap();
    record[cipher..cipher + 2].copy_from_slice(&[0xc0, 0x2f]);
    assert_eq!(
        parse_tls_handshake_observation(&record).unwrap_err().kind,
        TlsParseIssueKind::InconsistentNegotiation
    );
}
