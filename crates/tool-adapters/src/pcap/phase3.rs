#![forbid(unsafe_code)]

//! Phase 3 network evidence primitives. The parser is deliberately loss-aware:
//! malformed blocks are rejected or reported as partial, never silently skipped.

use super::super::pcap::{parse_binary_pcap, ParsedPacket};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDescription {
    pub id: u32,
    pub linktype: u16,
    pub snaplen: u32,
    pub section_index: u32,
    pub timestamp_resolution: TimestampResolution,
    pub tsoffset_seconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureTimestamp {
    pub raw_value: u64,
    pub resolution: TimestampResolution,
    pub offset_seconds: i64,
    pub normalized_utc: DateTime<Utc>,
    pub precision_loss: bool,
}

impl TimestampResolution {
    fn normalized(self, raw: u64, offset_seconds: i64) -> Result<(DateTime<Utc>, bool), String> {
        let (seconds, remainder, denominator) = match self {
            TimestampResolution::Decimal(power) => {
                if power > 38 {
                    return Err("decimal timestamp resolution exponent is too large".into());
                }
                let denominator = 10u128.pow(power as u32);
                let raw = raw as u128;
                (raw / denominator, raw % denominator, denominator)
            }
            TimestampResolution::Binary(power) => {
                if power >= 64 {
                    return Err("binary timestamp resolution exponent is too large".into());
                }
                let denominator = 1u128 << power;
                let raw = raw as u128;
                (raw / denominator, raw % denominator, denominator)
            }
        };
        let nanos_numerator = remainder * 1_000_000_000u128;
        let nanos = (nanos_numerator / denominator) as u32;
        let precision_loss = !nanos_numerator.is_multiple_of(denominator);
        let seconds = i64::try_from(seconds)
            .map_err(|_| "timestamp seconds exceed DateTime range".to_string())?
            .checked_add(offset_seconds)
            .ok_or_else(|| "timestamp offset exceeds DateTime range".to_string())?;
        let timestamp = Utc
            .timestamp_opt(seconds, nanos)
            .single()
            .ok_or_else(|| "timestamp is outside DateTime range".to_string())?;
        Ok((timestamp, precision_loss))
    }

    pub fn capture_timestamp(
        self,
        raw_value: u64,
        offset_seconds: i64,
    ) -> Result<CaptureTimestamp, String> {
        let (normalized_utc, precision_loss) = self.normalized(raw_value, offset_seconds)?;
        Ok(CaptureTimestamp {
            raw_value,
            resolution: self,
            offset_seconds,
            normalized_utc,
            precision_loss,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureParseResult {
    pub packets: Vec<ParsedPacket>,
    pub format: String,
    pub partial: bool,
    pub issues: Vec<String>,
    pub interfaces: Vec<InterfaceDescription>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcapQuality {
    Complete,
    Degraded,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowQuality {
    Complete,
    Partial,
    Truncated,
}

impl From<PcapQuality> for core_domain::CaptureQuality {
    fn from(value: PcapQuality) -> Self {
        match value {
            PcapQuality::Complete => Self::Complete,
            PcapQuality::Degraded => Self::Degraded,
            PcapQuality::Partial => Self::Partial,
            PcapQuality::Failed => Self::Failed,
        }
    }
}

impl From<FlowQuality> for core_domain::FlowQuality {
    fn from(value: FlowQuality) -> Self {
        match value {
            FlowQuality::Complete => Self::Complete,
            FlowQuality::Partial => Self::Partial,
            FlowQuality::Truncated => Self::Truncated,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureParseIssueKind {
    PacketLengthLimitExceeded,
    TruncatedPacketRecord,
    CapturedLengthExceedsSnaplen,
    OriginalLengthSmallerThanCaptured,
    RecordOffsetOverflow,
    InvalidTimestampFraction,
    TimestampOutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureParseIssue {
    pub kind: CaptureParseIssueKind,
    pub record_index: Option<u64>,
    pub physical_offset: Option<u64>,
    pub declared_incl_len: Option<u32>,
    pub declared_orig_len: Option<u32>,
    pub snaplen: Option<u32>,
    pub ts_sec: Option<u32>,
    pub ts_fraction: Option<u32>,
    pub recoverable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapParseResult {
    pub format: String,
    pub packets_seen: u64,
    pub packets_decoded: u64,
    pub packets_corrupt: u64,
    pub flows_created: u64,
    pub issues: Vec<String>,
    pub diagnostics: Vec<CaptureParseIssue>,
    pub quality: PcapQuality,
    pub interfaces: Vec<InterfaceDescription>,
    pub parser_version: String,
}

/// Consumer contract for production capture ingestion.
///
/// Implementations must process each packet before the parser advances.  The
/// parser never owns a packet collection; callers that need one must opt into
/// the explicitly bounded compatibility collector below.
pub trait CaptureSink {
    fn on_packet(&mut self, packet: ParsedPacket) -> Result<(), String>;

    fn on_issue(&mut self, _issue: &str) -> Result<(), String> {
        Ok(())
    }

    fn finish(&mut self, summary: &PcapParseResult) -> Result<(), String> {
        let _ = summary;
        Ok(())
    }
}

pub const PARSER_VERSION: &str = "pcap-phase3/socdfir-1.0";
pub const FLOW_IDENTITY_SCHEMA: &str = "flow-instance-v1";
pub const PACKET_LOCATOR_SCHEMA: &str = "packet-locator-v1";
pub const DERIVATION_SCHEMA: &str = "derivation-v1";
pub const MAX_COMPAT_CAPTURE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CAPTURE_PACKET_BYTES: usize = 16 * 1024 * 1024;

pub fn checked_record_end(
    physical_offset: u64,
    incl_len: u32,
) -> Result<u64, CaptureParseIssueKind> {
    physical_offset
        .checked_add(incl_len as u64)
        .ok_or(CaptureParseIssueKind::RecordOffsetOverflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    Blake3,
    Sha256,
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDigest {
    pub algorithm: DigestAlgorithm,
    pub digest: Vec<u8>,
}

fn put_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn canonical_identity_bytes(
    artifact: &ArtifactDigest,
    key: &FlowKey,
    discriminator: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    put_field(&mut out, FLOW_IDENTITY_SCHEMA.as_bytes());
    out.push(match artifact.algorithm {
        DigestAlgorithm::Blake3 => 1,
        DigestAlgorithm::Sha256 => 2,
        DigestAlgorithm::Opaque => 255,
    });
    put_field(&mut out, &artifact.digest);
    put_field(&mut out, key.protocol.as_bytes());
    put_field(&mut out, key.left.as_bytes());
    put_field(&mut out, key.right.as_bytes());
    put_field(&mut out, discriminator.as_bytes());
    out
}

pub fn parse_pcap_file_with_sink<F>(path: &Path, mut sink: F) -> Result<PcapParseResult, String>
where
    F: FnMut(ParsedPacket) -> Result<(), String>,
{
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(file);
    let mut header = [0u8; 24];
    reader
        .read_exact(&mut header)
        .map_err(|e| format!("truncated PCAP header: {e}"))?;
    if header[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
        return Err("PCAP-NG streaming reader requires block-aware dispatch".into());
    }
    let little = matches!(
        header[..4],
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]
    );
    let nanos = matches!(
        header[..4],
        [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d]
    );
    if !little
        && !matches!(
            header[..4],
            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d]
        )
    {
        return Err("invalid PCAP magic".into());
    }
    let mut seen = 0;
    let mut decoded = 0;
    let mut issues = Vec::new();
    let mut diagnostics = Vec::new();
    let read_u32 = |buf: &[u8]| -> u32 {
        if little {
            u32::from_le_bytes(buf.try_into().unwrap())
        } else {
            u32::from_be_bytes(buf.try_into().unwrap())
        }
    };
    let snaplen = read_u32(&header[16..20]);
    loop {
        let offset = 24u64 + seen;
        let mut ph = [0u8; 16];
        match reader.read_exact(&mut ph) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        };
        let incl_raw = read_u32(&ph[8..12]);
        let orig_len = read_u32(&ph[12..16]);
        let ts_sec = read_u32(&ph[0..4]);
        let ts_fraction = read_u32(&ph[4..8]);
        let incl = incl_raw as usize;
        let issue_context = |kind, recoverable| CaptureParseIssue {
            kind,
            record_index: Some(decoded),
            physical_offset: Some(offset),
            declared_incl_len: Some(incl_raw),
            declared_orig_len: Some(orig_len),
            snaplen: Some(snaplen),
            ts_sec: Some(ts_sec),
            ts_fraction: Some(ts_fraction),
            recoverable,
        };
        if incl > MAX_CAPTURE_PACKET_BYTES {
            diagnostics.push(issue_context(
                CaptureParseIssueKind::PacketLengthLimitExceeded,
                false,
            ));
            issues.push(format!(
                "packet at {offset} exceeds configured capture packet limit"
            ));
            break;
        }
        let mut data = vec![0u8; incl];
        if let Err(e) = reader.read_exact(&mut data) {
            diagnostics.push(issue_context(
                CaptureParseIssueKind::TruncatedPacketRecord,
                false,
            ));
            issues.push(format!("truncated packet at {offset}: {e}"));
            break;
        }
        if incl_raw > snaplen {
            diagnostics.push(issue_context(
                CaptureParseIssueKind::CapturedLengthExceedsSnaplen,
                false,
            ));
            issues.push(format!(
                "packet at {offset} captured length exceeds snaplen"
            ));
            break;
        }
        if orig_len < incl_raw {
            diagnostics.push(issue_context(
                CaptureParseIssueKind::OriginalLengthSmallerThanCaptured,
                true,
            ));
            issues.push(format!(
                "packet at {offset} original length is smaller than captured length"
            ));
            seen = seen.checked_add(16 + incl_raw as u64).ok_or_else(|| {
                "record offset overflow after inconsistent packet lengths".to_string()
            })?;
            continue;
        }
        let mut one = header.to_vec();
        one.extend_from_slice(&ph);
        one.extend_from_slice(&data);
        let mut p = parse_binary_pcap(&one)?
            .pop()
            .ok_or("packet decoder returned no packet")?;
        let fraction_valid = if nanos {
            ts_fraction < 1_000_000_000
        } else {
            ts_fraction < 1_000_000
        };
        if !fraction_valid {
            diagnostics.push(issue_context(
                CaptureParseIssueKind::InvalidTimestampFraction,
                true,
            ));
            issues.push(format!("packet at {offset} has invalid timestamp fraction"));
            p.capture_timestamp = None;
        } else if p.capture_timestamp.is_none() {
            diagnostics.push(issue_context(
                CaptureParseIssueKind::TimestampOutOfRange,
                true,
            ));
            issues.push(format!("packet at {offset} timestamp is out of range"));
        }
        p.physical_offset = Some(offset);
        p.packet_locator = format!("pcap://offset/0x{offset:08X}/packet/{decoded}");
        sink(p)?;
        let record_header_end = seen.checked_add(16).ok_or_else(|| {
            diagnostics.push(issue_context(
                CaptureParseIssueKind::RecordOffsetOverflow,
                false,
            ));
            "record header offset overflow".to_string()
        })?;
        seen = checked_record_end(record_header_end, incl_raw).map_err(|kind| {
            diagnostics.push(issue_context(kind, false));
            format!("record offset overflow at {offset}")
        })?;
        decoded += 1;
    }
    Ok(PcapParseResult {
        format: "pcap".into(),
        packets_seen: decoded,
        packets_decoded: decoded,
        packets_corrupt: issues.len() as u64,
        flows_created: 0,
        quality: if issues.is_empty() {
            PcapQuality::Complete
        } else {
            PcapQuality::Partial
        },
        issues,
        diagnostics,
        interfaces: Vec::new(),
        parser_version: PARSER_VERSION.into(),
    })
}

pub fn parse_capture_file_with_capture_sink<S: CaptureSink>(
    path: &Path,
    mut sink: S,
) -> Result<PcapParseResult, String> {
    let result = parse_capture_file_with_sink(path, |packet| sink.on_packet(packet))?;
    for issue in &result.issues {
        sink.on_issue(issue)?;
    }
    sink.finish(&result)?;
    Ok(result)
}

/// Compatibility-only collection API. Production ingestion must use a
/// `CaptureSink`; this function has a hard byte-size guard to prevent the old
/// whole-capture memory behavior from being reintroduced accidentally.
pub fn parse_capture_collect(path: &Path) -> Result<Vec<ParsedPacket>, String> {
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > MAX_COMPAT_CAPTURE_BYTES {
        return Err(format!(
            "compatibility capture collection is limited to {MAX_COMPAT_CAPTURE_BYTES} bytes"
        ));
    }
    let mut packets = Vec::new();
    parse_capture_file_with_sink(path, |packet| {
        packets.push(packet);
        Ok(())
    })?;
    Ok(packets)
}

pub fn parse_capture_file_with_sink<F>(path: &Path, mut sink: F) -> Result<PcapParseResult, String>
where
    F: FnMut(ParsedPacket) -> Result<(), String>,
{
    let mut probe = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut magic = [0u8; 4];
    std::io::Read::read_exact(&mut probe, &mut magic).map_err(|e| e.to_string())?;
    if magic != [0x0a, 0x0d, 0x0d, 0x0a] {
        return parse_pcap_file_with_sink(path, sink);
    }
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(file);
    let mut section_index = 0u32;
    let mut packet_index = 0u64;
    let mut physical_offset = 0u64;
    let mut endian_le = true;
    let mut metadata: Vec<u8> = Vec::new();
    let mut current_interfaces = Vec::new();
    let mut all_interfaces = Vec::new();
    let mut issues = Vec::new();
    loop {
        let block_offset = physical_offset;
        let mut prefix = [0u8; 8];
        match reader.read_exact(&mut prefix) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
        let kind = if endian_le {
            u32::from_le_bytes(prefix[..4].try_into().unwrap())
        } else {
            u32::from_be_bytes(prefix[..4].try_into().unwrap())
        };
        let mut total_len = if endian_le {
            u32::from_le_bytes(prefix[4..].try_into().unwrap())
        } else {
            u32::from_be_bytes(prefix[4..].try_into().unwrap())
        } as usize;
        let mut first12 = [0u8; 4];
        if kind == 0x0a0d0d0a {
            reader
                .read_exact(&mut first12)
                .map_err(|e| format!("truncated section header: {e}"))?;
            let bom = &first12[..4];
            endian_le = match bom {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => return Err("invalid PCAPNG byte-order magic".into()),
            };
            total_len = u32::from_ne_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]) as usize;
            if !endian_le {
                total_len =
                    u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]) as usize;
            }
        }
        if !(12..=16 * 1024 * 1024).contains(&total_len) || !total_len.is_multiple_of(4) {
            issues.push(format!("invalid block length at offset {block_offset}"));
            break;
        }
        let mut block = Vec::with_capacity(total_len);
        block.extend_from_slice(&prefix);
        let already = if kind == 0x0a0d0d0a {
            first12.to_vec()
        } else {
            Vec::new()
        };
        block.extend_from_slice(&already);
        let remaining = total_len.saturating_sub(block.len());
        let mut tail = vec![0u8; remaining];
        if let Err(e) = reader.read_exact(&mut tail) {
            issues.push(format!("truncated block at offset {block_offset}: {e}"));
            break;
        }
        block.extend_from_slice(&tail);
        physical_offset += total_len as u64;
        if kind == 0x0a0d0d0a {
            section_index += if metadata.is_empty() { 0 } else { 1 };
            metadata = block.clone();
            current_interfaces.clear();
            continue;
        }
        if kind == 1 {
            metadata.extend_from_slice(&block);
            if let Ok(capture) = parse_pcapng(&metadata) {
                current_interfaces = capture.interfaces;
                for interface in &mut current_interfaces {
                    interface.section_index = section_index;
                }
                all_interfaces.retain(|interface: &InterfaceDescription| {
                    interface.section_index != section_index
                });
                all_interfaces.extend(current_interfaces.iter().cloned());
            }
            continue;
        }
        if kind == 6 {
            let mut one_input = metadata.clone();
            one_input.extend_from_slice(&block);
            match parse_pcapng(&one_input) {
                Ok(mut capture) if !capture.packets.is_empty() => {
                    let mut p = capture.packets.remove(0);
                    p.packet_index = packet_index as usize;
                    p.section_index = Some(section_index);
                    p.physical_offset = Some(block_offset);
                    p.packet_locator=format!("pcapng://section/{section_index}/interface/{}/offset/0x{block_offset:08X}/packet/{packet_index}", p.interface_id.unwrap_or(0));
                    sink(p)?;
                    packet_index += 1;
                }
                Ok(_) => issues.push(format!("undecodable packet block at offset {block_offset}")),
                Err(e) => issues.push(e),
            }
        }
    }
    Ok(PcapParseResult {
        format: "pcapng".into(),
        packets_seen: packet_index,
        packets_decoded: packet_index,
        packets_corrupt: issues.len() as u64,
        flows_created: 0,
        quality: if issues.is_empty() {
            PcapQuality::Complete
        } else {
            PcapQuality::Partial
        },
        issues,
        diagnostics: Vec::new(),
        interfaces: all_interfaces,
        parser_version: PARSER_VERSION.into(),
    })
}

pub fn parse_capture(bytes: &[u8]) -> Result<CaptureParseResult, String> {
    if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        parse_pcapng(bytes)
    } else {
        Ok(CaptureParseResult {
            packets: parse_binary_pcap(bytes)?,
            format: "pcap".into(),
            partial: false,
            issues: Vec::new(),
            interfaces: Vec::new(),
        })
    }
}

impl CaptureParseResult {
    pub fn summary(&self) -> PcapParseResult {
        let quality = if self.packets.is_empty() && !self.issues.is_empty() {
            PcapQuality::Failed
        } else if self.partial {
            PcapQuality::Partial
        } else if !self.issues.is_empty() {
            PcapQuality::Degraded
        } else {
            PcapQuality::Complete
        };
        PcapParseResult {
            format: self.format.clone(),
            packets_seen: self.packets.len() as u64,
            packets_decoded: self.packets.len() as u64,
            packets_corrupt: self.issues.len() as u64,
            flows_created: reconstruct_flows(&self.packets).len() as u64,
            issues: self.issues.clone(),
            diagnostics: Vec::new(),
            quality,
            interfaces: self.interfaces.clone(),
            parser_version: PARSER_VERSION.to_string(),
        }
    }
}

fn u32e(b: &[u8], o: usize, le: bool) -> u32 {
    let x = [b[o], b[o + 1], b[o + 2], b[o + 3]];
    if le {
        u32::from_le_bytes(x)
    } else {
        u32::from_be_bytes(x)
    }
}
fn u16e(b: &[u8], o: usize, le: bool) -> u16 {
    let x = [b[o], b[o + 1]];
    if le {
        u16::from_le_bytes(x)
    } else {
        u16::from_be_bytes(x)
    }
}

pub fn parse_pcapng(bytes: &[u8]) -> Result<CaptureParseResult, String> {
    if bytes.len() < 28 {
        return Err("PCAP-NG section header is truncated".into());
    }
    let mut pos = 0;
    let mut le = true;
    let mut interfaces = BTreeMap::new();
    let mut packets = Vec::new();
    let mut issues = Vec::new();
    let mut partial = false;
    while pos + 12 <= bytes.len() {
        if bytes[pos..pos + 4] == [0x0a, 0x0d, 0x0d, 0x0a] {
            if pos + 12 > bytes.len() {
                break;
            }
            let bom = &bytes[pos + 8..pos + 12];
            le = match bom {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => return Err("PCAP-NG invalid byte-order magic".into()),
            };
        }
        let kind = u32e(bytes, pos, le);
        let len = u32e(bytes, pos + 4, le) as usize;
        if len < 12 || pos + len > bytes.len() {
            partial = true;
            issues.push(format!("truncated block at offset {pos}"));
            break;
        }
        if u32e(bytes, pos + len - 4, le) as usize != len {
            partial = true;
            issues.push(format!("invalid block length at offset {pos}"));
            pos += len;
            continue;
        }
        match kind {
            1 if len >= 20 => {
                let id = interfaces.len() as u32;
                let linktype = u16e(bytes, pos + 8, le);
                let snaplen = u32e(bytes, pos + 12, le);
                let mut timestamp_resolution = TimestampResolution::Decimal(6);
                let mut tsoffset_seconds = 0i64;
                let mut opt = pos + 16;
                while opt + 4 <= pos + len - 4 {
                    let code = u16e(bytes, opt, le);
                    let olen = u16e(bytes, opt + 2, le) as usize;
                    if code == 0 {
                        break;
                    }
                    if code == 9 && olen >= 1 && opt + 4 + olen <= pos + len - 4 {
                        let raw = bytes[opt + 4];
                        timestamp_resolution = if raw & 0x80 == 0 {
                            TimestampResolution::Decimal(raw)
                        } else {
                            TimestampResolution::Binary(raw & 0x7f)
                        };
                    }
                    if code == 14 && olen >= 8 && opt + 4 + olen <= pos + len - 4 {
                        let raw = [
                            bytes[opt + 4],
                            bytes[opt + 5],
                            bytes[opt + 6],
                            bytes[opt + 7],
                            bytes[opt + 8],
                            bytes[opt + 9],
                            bytes[opt + 10],
                            bytes[opt + 11],
                        ];
                        tsoffset_seconds = if le {
                            i64::from_le_bytes(raw)
                        } else {
                            i64::from_be_bytes(raw)
                        };
                    }
                    opt += 4 + ((olen + 3) & !3);
                }
                interfaces.insert(
                    id,
                    InterfaceDescription {
                        id,
                        linktype,
                        snaplen,
                        section_index: 0,
                        timestamp_resolution,
                        tsoffset_seconds,
                    },
                );
            }
            6 if len >= 32 => {
                let id = u32e(bytes, pos + 8, le);
                let ts_hi = u32e(bytes, pos + 12, le);
                let ts_lo = u32e(bytes, pos + 16, le);
                let cap = u32e(bytes, pos + 20, le) as usize;
                let orig = u32e(bytes, pos + 24, le);
                let data_start = pos + 28;
                if data_start + cap > pos + len - 4 {
                    partial = true;
                    issues.push(format!("truncated enhanced packet at offset {pos}"));
                } else {
                    let link = interfaces.get(&id).map(|v| v.linktype).unwrap_or(1);
                    let interface = interfaces
                        .get(&id)
                        .cloned()
                        .unwrap_or(InterfaceDescription {
                            id,
                            linktype: link,
                            snaplen: 0,
                            section_index: 0,
                            timestamp_resolution: TimestampResolution::Decimal(6),
                            tsoffset_seconds: 0,
                        });
                    let raw_timestamp = ((ts_hi as u64) << 32) | ts_lo as u64;
                    let capture_timestamp = interface
                        .timestamp_resolution
                        .capture_timestamp(raw_timestamp, interface.tsoffset_seconds)?;
                    let timestamp_seconds =
                        capture_timestamp.normalized_utc.timestamp().max(0) as u64;
                    let timestamp_nanos = capture_timestamp.normalized_utc.timestamp_subsec_nanos();
                    let mut one = build_packet(
                        id as usize,
                        timestamp_seconds,
                        timestamp_nanos,
                        &bytes[data_start..data_start + cap],
                        orig,
                        link,
                    );
                    one.packet_index = packets.len() + 1;
                    one.interface_id = Some(id);
                    one.capture_timestamp = Some(capture_timestamp);
                    one.physical_offset = Some(pos as u64);
                    one.packet_locator = format!(
                        "pcapng://offset/0x{pos:08X}/interface/{id}/packet/{}",
                        packets.len() + 1
                    );
                    packets.push(one);
                }
            }
            _ => {}
        }
        pos += len;
    }
    Ok(CaptureParseResult {
        packets,
        format: "pcapng".into(),
        partial,
        issues,
        interfaces: interfaces.into_values().collect(),
    })
}

fn build_packet(
    index: usize,
    ts_seconds: u64,
    ts_nanos: u32,
    data: &[u8],
    orig: u32,
    link: u16,
) -> ParsedPacket {
    // Reuse the canonical Ethernet decoder by wrapping one packet in a little-endian PCAP.
    let mut b = Vec::with_capacity(24 + 16 + data.len());
    b.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&4u16.to_le_bytes());
    b.extend_from_slice(&[0; 8]);
    b.extend_from_slice(&65535u32.to_le_bytes());
    b.extend_from_slice(&(link as u32).to_le_bytes());
    b.extend_from_slice(&(ts_seconds as u32).to_le_bytes());
    b.extend_from_slice(&(ts_nanos / 1_000).to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(&orig.to_le_bytes());
    b.extend_from_slice(data);
    let mut p = parse_binary_pcap(&b)
        .unwrap_or_default()
        .pop()
        .unwrap_or_else(|| ParsedPacket {
            packet_index: index,
            timestamp_epoch_sec: 0,
            timestamp_epoch_usec: 0,
            captured_len: 0,
            original_len: 0,
            ether_type: 0,
            src_ip: None,
            dst_ip: None,
            protocol: None,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            payload_len: 0,
            timestamp_epoch_nanos: 0,
            src_ipv6: None,
            dst_ipv6: None,
            vlan_id: None,
            tcp_sequence: None,
            tcp_acknowledgment: None,
            payload: Vec::new(),
            interface_id: None,
            physical_offset: None,
            packet_hash: String::new(),
            parse_quality: "FAILED".to_string(),
            packet_locator: format!("pcap://packet/{index}"),
            section_index: None,
            capture_timestamp: None,
        });
    p.packet_index = index;
    p
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub left: String,
    pub right: String,
    pub protocol: String,
}

pub fn flow_id(key: &FlowKey) -> String {
    let canonical = format!("{}|{}|{}", key.left, key.right, key.protocol);
    format!("flow://{}", blake3::hash(canonical.as_bytes()).to_hex())
}

pub fn flow_instance_id(artifact_identity: &str, key: &FlowKey, discriminator: &str) -> String {
    let artifact = ArtifactDigest {
        algorithm: DigestAlgorithm::Opaque,
        digest: artifact_identity.as_bytes().to_vec(),
    };
    flow_instance_id_from_digest(&artifact, key, discriminator)
}

pub fn flow_instance_id_from_digest(
    artifact: &ArtifactDigest,
    key: &FlowKey,
    discriminator: &str,
) -> String {
    format!(
        "flow-instance://{}",
        blake3::hash(&canonical_identity_bytes(artifact, key, discriminator)).to_hex()
    )
}

pub fn derivation_id(
    flow_instance_id: &str,
    parser_version: &str,
    normalization_version: &str,
) -> String {
    let mut canonical = Vec::new();
    put_field(&mut canonical, DERIVATION_SCHEMA.as_bytes());
    put_field(&mut canonical, flow_instance_id.as_bytes());
    put_field(&mut canonical, parser_version.as_bytes());
    put_field(&mut canonical, normalization_version.as_bytes());
    format!("derivation://{}", blake3::hash(&canonical).to_hex())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub key: FlowKey,
    pub flow_instance_id: String,
    pub discriminator: String,
    pub packets: u64,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub fin: bool,
    pub rst: bool,
    pub a_to_b_packets: u64,
    pub a_to_b_bytes: u64,
    pub b_to_a_packets: u64,
    pub b_to_a_bytes: u64,
    pub quality: String,
    pub flow_quality: FlowQuality,
}

fn finalize_flow_quality(flow: &mut Flow) {
    flow.flow_quality = if flow.key.protocol == "TCP" && flow.rst {
        FlowQuality::Truncated
    } else if flow.key.protocol == "TCP" && !flow.fin {
        FlowQuality::Partial
    } else {
        FlowQuality::Complete
    };
}

pub fn reconstruct_flows(packets: &[ParsedPacket]) -> Vec<Flow> {
    reconstruct_flows_with_artifact("", packets)
}

pub fn packet_flow_key(p: &ParsedPacket) -> FlowKey {
    let a = format!(
        "{}:{}",
        p.src_ip.as_deref().or(p.src_ipv6.as_deref()).unwrap_or("?"),
        p.src_port.unwrap_or(0)
    );
    let b = format!(
        "{}:{}",
        p.dst_ip.as_deref().or(p.dst_ipv6.as_deref()).unwrap_or("?"),
        p.dst_port.unwrap_or(0)
    );
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    FlowKey {
        left,
        right,
        protocol: p.protocol.clone().unwrap_or_else(|| "UNKNOWN".into()),
    }
}

pub fn reconstruct_flows_with_artifact(
    artifact_content_hash: &str,
    packets: &[ParsedPacket],
) -> Vec<Flow> {
    let mut active: BTreeMap<FlowKey, Flow> = BTreeMap::new();
    let mut completed = Vec::new();
    for p in packets {
        let k = packet_flow_key(p);
        let a = format!(
            "{}:{}",
            p.src_ip.as_deref().or(p.src_ipv6.as_deref()).unwrap_or("?"),
            p.src_port.unwrap_or(0)
        );
        let b = format!(
            "{}:{}",
            p.dst_ip.as_deref().or(p.dst_ipv6.as_deref()).unwrap_or("?"),
            p.dst_port.unwrap_or(0)
        );
        let a_to_b = a <= b;
        let is_new_syn = p.protocol.as_deref() == Some("TCP")
            && p.tcp_flags.as_deref().unwrap_or("").contains("SYN")
            && !p.tcp_flags.as_deref().unwrap_or("").contains("ACK");
        if is_new_syn && active.get(&k).is_some_and(|f| f.fin || f.rst) {
            if let Some(old) = active.remove(&k) {
                completed.push(old);
            }
        }
        let discriminator = active
            .get(&k)
            .map(|f| f.discriminator.clone())
            .unwrap_or_else(|| {
                p.tcp_sequence
                    .map(|seq| format!("syn:{}/seq:{seq}", p.packet_index))
                    .unwrap_or_else(|| format!("first-packet:{}", p.packet_index))
            });
        let instance_id = flow_instance_id(artifact_content_hash, &k, &discriminator);
        let f = active.entry(k.clone()).or_insert(Flow {
            key: k,
            flow_instance_id: instance_id,
            discriminator,
            packets: 0,
            bytes: 0,
            first_ts: u64::MAX,
            last_ts: 0,
            fin: false,
            rst: false,
            a_to_b_packets: 0,
            a_to_b_bytes: 0,
            b_to_a_packets: 0,
            b_to_a_bytes: 0,
            quality: "COMPLETE".to_string(),
            flow_quality: FlowQuality::Complete,
        });
        f.packets += 1;
        f.bytes += p.captured_len as u64;
        if a_to_b {
            f.a_to_b_packets += 1;
            f.a_to_b_bytes += p.captured_len as u64;
        } else {
            f.b_to_a_packets += 1;
            f.b_to_a_bytes += p.captured_len as u64;
        }
        let t = (p.timestamp_epoch_sec as u64) * 1_000_000 + p.timestamp_epoch_usec as u64;
        f.first_ts = f.first_ts.min(t);
        f.last_ts = f.last_ts.max(t);
        if p.tcp_flags.as_deref().unwrap_or("").contains("FIN") {
            f.fin = true
        }
        if p.tcp_flags.as_deref().unwrap_or("").contains("RST") {
            f.rst = true
        }
    }
    for mut flow in active.into_values() {
        finalize_flow_quality(&mut flow);
        completed.push(flow);
    }
    for flow in &mut completed {
        finalize_flow_quality(flow);
    }
    completed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReassemblyStatus {
    Complete,
    Partial,
    Truncated,
    Gapped,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReassemblyIssueKind {
    Gap,
    Duplicate,
    Retransmission,
    OverlapIdentical,
    OverlapConflict,
    ResourceLimit,
    TruncatedCapture,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassemblyIssue {
    pub kind: ReassemblyIssueKind,
    pub direction: Option<String>,
    pub seq_start: u32,
    pub seq_end: u32,
    pub first_packet: Option<u64>,
    pub second_packet: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassembledStream {
    pub bytes: Vec<u8>,
    pub status: ReassemblyStatus,
    pub retransmissions: u64,
    pub overlap_conflicts: u64,
    pub issues: Vec<ReassemblyIssue>,
}

pub fn reassemble_tcp(packets: &[ParsedPacket]) -> ReassembledStream {
    reassemble_tcp_bounded(packets, ReassemblyLimits::default())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReassemblyLimits {
    pub max_buffered_segments: usize,
    pub max_stream_bytes: usize,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_buffered_segments: 4096,
            max_stream_bytes: 4 * 1024 * 1024,
        }
    }
}

pub fn reassemble_tcp_bounded(
    packets: &[ParsedPacket],
    limits: ReassemblyLimits,
) -> ReassembledStream {
    let mut parts: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut retrans = 0;
    let mut overlap_conflicts = 0;
    let mut issues: Vec<ReassemblyIssue> = Vec::new();
    let mut expected = None;
    for p in packets
        .iter()
        .filter(|p| p.protocol.as_deref() == Some("TCP"))
    {
        if let Some(seq) = p.tcp_sequence {
            if parts.contains_key(&seq) {
                retrans += 1;
                issues.push(ReassemblyIssue {
                    kind: ReassemblyIssueKind::Retransmission,
                    direction: None,
                    seq_start: seq,
                    seq_end: seq.saturating_add(p.payload.len() as u32),
                    first_packet: None,
                    second_packet: Some(p.packet_index as u64),
                });
            } else {
                for (old_seq, old_data) in &parts {
                    let overlap_start = (*old_seq).max(seq);
                    let overlap_end = old_seq
                        .saturating_add(old_data.len() as u32)
                        .min(seq.saturating_add(p.payload.len() as u32));
                    if overlap_start < overlap_end {
                        let old_at = (overlap_start - *old_seq) as usize;
                        let new_at = (overlap_start - seq) as usize;
                        let len = (overlap_end - overlap_start) as usize;
                        if old_data[old_at..old_at + len] != p.payload[new_at..new_at + len] {
                            overlap_conflicts += 1;
                            issues.push(ReassemblyIssue {
                                kind: ReassemblyIssueKind::OverlapConflict,
                                direction: None,
                                seq_start: overlap_start,
                                seq_end: overlap_end,
                                first_packet: None,
                                second_packet: Some(p.packet_index as u64),
                            });
                        }
                    }
                }
                if parts.len() >= limits.max_buffered_segments {
                    issues.push(ReassemblyIssue {
                        kind: ReassemblyIssueKind::ResourceLimit,
                        direction: None,
                        seq_start: seq,
                        seq_end: seq.saturating_add(p.payload.len() as u32),
                        first_packet: None,
                        second_packet: Some(p.packet_index as u64),
                    });
                    continue;
                }
                parts.insert(seq, p.payload.clone());
            }
            expected = Some(expected.map_or(seq, |e: u32| e.min(seq)));
        }
    }
    let mut out = Vec::new();
    let mut status = ReassemblyStatus::Complete;
    let mut next = expected.unwrap_or(0);
    for (seq, data) in parts {
        if seq != next {
            status = ReassemblyStatus::Gapped;
            issues.push(ReassemblyIssue {
                kind: ReassemblyIssueKind::Gap,
                direction: None,
                seq_start: next,
                seq_end: seq,
                first_packet: None,
                second_packet: None,
            });
        }
        if seq >= next {
            if out.len() >= limits.max_stream_bytes {
                status = ReassemblyStatus::Truncated;
                issues.push(ReassemblyIssue {
                    kind: ReassemblyIssueKind::ResourceLimit,
                    direction: None,
                    seq_start: next,
                    seq_end: next,
                    first_packet: None,
                    second_packet: None,
                });
                break;
            }
            let remaining = limits.max_stream_bytes - out.len();
            out.extend_from_slice(&data[..data.len().min(remaining)]);
            next = seq.saturating_add(data.len() as u32);
        }
    }
    if overlap_conflicts > 0 && status == ReassemblyStatus::Complete {
        status = ReassemblyStatus::Gapped;
    }
    ReassembledStream {
        bytes: out,
        status,
        retransmissions: retrans,
        overlap_conflicts,
        issues,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMessage {
    pub method: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub status_code: Option<u16>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub content_length: Option<u64>,
    pub body_retained: bool,
}
pub fn extract_http(data: &[u8]) -> Option<HttpMessage> {
    let s = std::str::from_utf8(data).ok()?;
    let first = s.lines().next()?;
    let mut h = HttpMessage {
        method: None,
        host: None,
        uri: None,
        status_code: None,
        user_agent: None,
        content_type: None,
        server: None,
        content_length: None,
        body_retained: false,
    };
    if first.starts_with("HTTP/") {
        h.status_code = first.split_whitespace().nth(1).and_then(|x| x.parse().ok())
    } else {
        let mut x = first.split_whitespace();
        h.method = x.next().map(str::to_string);
        h.uri = x.next().map(str::to_string)
    }
    for l in s.lines().skip(1) {
        if let Some((k, v)) = l.split_once(':') {
            match k.to_ascii_lowercase().as_str() {
                "host" => h.host = Some(v.trim().into()),
                "user-agent" => h.user_agent = Some(v.trim().into()),
                "content-type" => h.content_type = Some(v.trim().into()),
                "server" => h.server = Some(v.trim().into()),
                "content-length" => h.content_length = v.trim().parse().ok(),
                _ => {}
            }
        }
    }
    Some(h)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub qname: Option<String>,
    pub qtype: Option<u16>,
    pub answers: Vec<DnsAnswer>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub rdata_len: u16,
    pub value: Option<String>,
    pub ttl: u32,
    pub rdata_hash: Option<String>,
}

pub const MAX_DNS_POINTER_JUMPS: usize = 32;
pub const MAX_DNS_LABEL_LEN: usize = 63;
pub const MAX_DNS_NAME_LEN: usize = 255;
pub const MAX_DNS_MESSAGE_BYTES: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsParseIssueKind {
    CompressionLoop,
    CompressionPointerOutOfBounds,
    CompressionJumpLimitExceeded,
    TruncatedName,
    InvalidLabelType,
    ExpandedNameTooLong,
    TruncatedRecord,
    InvalidTcpFrameLength,
    IncompleteTcpFrame,
    MessageTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsParseIssue {
    pub kind: DnsParseIssueKind,
    pub byte_offset: Option<usize>,
    pub recoverable: bool,
}

impl std::fmt::Display for DnsParseIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNS {:?} at {:?}", self.kind, self.byte_offset)
    }
}

impl std::error::Error for DnsParseIssue {}

fn dns_issue(kind: DnsParseIssueKind, offset: Option<usize>) -> DnsParseIssue {
    DnsParseIssue {
        kind,
        byte_offset: offset,
        recoverable: true,
    }
}

fn read_dns_name_checked(data: &[u8], start: usize) -> Result<(String, usize), DnsParseIssue> {
    let mut pos = start;
    let mut next = None;
    let mut labels = Vec::new();
    let mut visited_offsets = HashSet::new();
    let mut jumps = 0;
    loop {
        if pos >= data.len() {
            return Err(dns_issue(DnsParseIssueKind::TruncatedName, Some(pos)));
        }
        let n = data[pos];
        if n == 0 {
            let name = labels.join(".");
            if name.len() > MAX_DNS_NAME_LEN {
                return Err(dns_issue(
                    DnsParseIssueKind::ExpandedNameTooLong,
                    Some(start),
                ));
            }
            return Ok((name, next.unwrap_or(pos + 1)));
        }
        if n & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return Err(dns_issue(DnsParseIssueKind::TruncatedName, Some(pos)));
            }
            jumps += 1;
            if jumps > MAX_DNS_POINTER_JUMPS {
                return Err(dns_issue(
                    DnsParseIssueKind::CompressionJumpLimitExceeded,
                    Some(pos),
                ));
            }
            let target = ((n as usize & 0x3f) << 8) | data[pos + 1] as usize;
            if target >= data.len() {
                return Err(dns_issue(
                    DnsParseIssueKind::CompressionPointerOutOfBounds,
                    Some(pos),
                ));
            }
            if !visited_offsets.insert(target) {
                return Err(dns_issue(DnsParseIssueKind::CompressionLoop, Some(target)));
            }
            if next.is_none() {
                next = Some(pos + 2);
            }
            pos = target;
            continue;
        }
        if n & 0xc0 == 0x40 || n & 0xc0 == 0x80 {
            return Err(dns_issue(DnsParseIssueKind::InvalidLabelType, Some(pos)));
        }
        let len = n as usize;
        pos += 1;
        if pos + len > data.len() {
            return Err(dns_issue(DnsParseIssueKind::TruncatedName, Some(pos)));
        }
        labels.push(
            std::str::from_utf8(&data[pos..pos + len])
                .map_err(|_| dns_issue(DnsParseIssueKind::TruncatedName, Some(pos)))?
                .to_string(),
        );
        pos += len;
        if labels.join(".").len() + labels.len().saturating_sub(1) > MAX_DNS_NAME_LEN {
            return Err(dns_issue(
                DnsParseIssueKind::ExpandedNameTooLong,
                Some(start),
            ));
        }
    }
}

pub fn extract_dns_detailed(data: &[u8]) -> Result<DnsMessage, DnsParseIssue> {
    if data.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(dns_issue(
            DnsParseIssueKind::MessageTooLarge,
            Some(MAX_DNS_MESSAGE_BYTES),
        ));
    }
    if data.len() < 12 {
        return Err(dns_issue(
            DnsParseIssueKind::TruncatedRecord,
            Some(data.len()),
        ));
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let (qname, p) = read_dns_name_checked(data, 12)?;
    if p + 4 > data.len() {
        return Err(dns_issue(DnsParseIssueKind::TruncatedRecord, Some(p)));
    }
    let qtype = u16::from_be_bytes([data[p], data[p + 1]]);
    let mut answer_pos = p + 4;
    let answer_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut answers = Vec::with_capacity(answer_count);
    for _ in 0..answer_count {
        let (name, after_name) = read_dns_name_checked(data, answer_pos)?;
        if after_name + 10 > data.len() {
            return Err(dns_issue(
                DnsParseIssueKind::TruncatedRecord,
                Some(after_name),
            ));
        }
        let record_type = u16::from_be_bytes([data[after_name], data[after_name + 1]]);
        let record_class = u16::from_be_bytes([data[after_name + 2], data[after_name + 3]]);
        let ttl = u32::from_be_bytes([
            data[after_name + 4],
            data[after_name + 5],
            data[after_name + 6],
            data[after_name + 7],
        ]);
        let rdlen = u16::from_be_bytes([data[after_name + 8], data[after_name + 9]]) as usize;
        let rdata = after_name + 10;
        if rdata + rdlen > data.len() {
            return Err(dns_issue(DnsParseIssueKind::TruncatedRecord, Some(rdata)));
        }
        let value = match record_type {
            1 if rdlen == 4 => Some(format!(
                "{}.{}.{}.{}",
                data[rdata],
                data[rdata + 1],
                data[rdata + 2],
                data[rdata + 3]
            )),
            28 if rdlen == 16 => Some(
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[rdata..rdata + 16]).unwrap())
                    .to_string(),
            ),
            5 | 12 => Some(read_dns_name_checked(data, rdata)?.0),
            _ => None,
        };
        let rdata_hash = if record_type == 1 && rdlen != 4
            || record_type == 28 && rdlen != 16
            || (matches!(record_type, 5 | 12) && read_dns_name_checked(data, rdata).is_err())
        {
            None
        } else {
            Some(
                blake3::hash(&data[rdata..rdata + rdlen])
                    .to_hex()
                    .to_string(),
            )
        };
        answers.push(DnsAnswer {
            name,
            record_type,
            record_class,
            rdata_len: rdlen as u16,
            value,
            ttl,
            rdata_hash,
        });
        answer_pos = rdata + rdlen;
    }
    Ok(DnsMessage {
        id,
        response: flags & 0x8000 != 0,
        rcode: (flags & 15) as u8,
        qname: Some(qname),
        qtype: Some(qtype),
        answers,
    })
}

pub fn extract_dns_tcp_messages_detailed(
    mut data: &[u8],
) -> Result<Vec<DnsMessage>, DnsParseIssue> {
    let mut messages = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(dns_issue(
                DnsParseIssueKind::InvalidTcpFrameLength,
                Some(data.len()),
            ));
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if len < 12 {
            return Err(dns_issue(
                DnsParseIssueKind::InvalidTcpFrameLength,
                Some(data.len()),
            ));
        }
        if data.len() < len + 2 {
            return Err(dns_issue(
                DnsParseIssueKind::IncompleteTcpFrame,
                Some(data.len()),
            ));
        }
        messages.push(extract_dns_detailed(&data[2..2 + len])?);
        data = &data[2 + len..];
    }
    Ok(messages)
}

pub fn extract_dns_tcp(data: &[u8]) -> Option<DnsMessage> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < len + 2 {
        return None;
    }
    extract_dns(&data[2..2 + len])
}

pub fn extract_dns_tcp_messages(data: &[u8]) -> Result<Vec<DnsMessage>, String> {
    extract_dns_tcp_messages_detailed(data).map_err(|issue| issue.to_string())
}
pub fn extract_dns(data: &[u8]) -> Option<DnsMessage> {
    extract_dns_detailed(data).ok()
}

#[allow(dead_code)]
fn extract_dns_legacy(data: &[u8]) -> Option<DnsMessage> {
    if data.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let (qname, p) = read_dns_name(data, 12)?;
    if p + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[p], data[p + 1]]);
    let mut answer_pos = p + 4;
    let answer_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut answers = Vec::new();
    for _ in 0..answer_count {
        let (name, after_name) = read_dns_name(data, answer_pos)?;
        if after_name + 10 > data.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([data[after_name], data[after_name + 1]]);
        let ttl = u32::from_be_bytes([
            data[after_name + 4],
            data[after_name + 5],
            data[after_name + 6],
            data[after_name + 7],
        ]);
        let rdlen = u16::from_be_bytes([data[after_name + 8], data[after_name + 9]]) as usize;
        let rdata = after_name + 10;
        if rdata + rdlen > data.len() {
            return None;
        }
        let value = match record_type {
            1 if rdlen == 4 => Some(format!(
                "{}.{}.{}.{}",
                data[rdata],
                data[rdata + 1],
                data[rdata + 2],
                data[rdata + 3]
            )),
            28 if rdlen == 16 => Some(
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[rdata..rdata + 16]).ok()?)
                    .to_string(),
            ),
            5 | 12 => read_dns_name(data, rdata).map(|v| v.0),
            _ => None,
        };
        answers.push(DnsAnswer {
            name,
            record_type,
            record_class: u16::from_be_bytes([data[after_name + 2], data[after_name + 3]]),
            rdata_len: rdlen as u16,
            value,
            ttl,
            rdata_hash: Some(
                blake3::hash(&data[rdata..rdata + rdlen])
                    .to_hex()
                    .to_string(),
            ),
        });
        answer_pos = rdata + rdlen;
    }
    Some(DnsMessage {
        id,
        response: flags & 0x8000 != 0,
        rcode: (flags & 15) as u8,
        qname: Some(qname),
        qtype: Some(qtype),
        answers,
    })
}

fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut next = None;
    let mut labels = Vec::new();
    let mut jumps = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let n = data[pos];
        if n == 0 {
            return Some((labels.join("."), next.unwrap_or(pos + 1)));
        }
        if n & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return None;
            }
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            let target = ((n as usize & 0x3f) << 8) | data[pos + 1] as usize;
            if next.is_none() {
                next = Some(pos + 2);
            }
            pos = target;
            continue;
        }
        let len = n as usize;
        pos += 1;
        if len == 0 || pos + len > data.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&data[pos..pos + len]).ok()?.to_string());
        pos += len;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHello {
    pub client: bool,
    pub version: u16,
    pub offered_versions: Vec<u16>,
    pub selected_version: Option<u16>,
    pub selected_cipher: Option<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateVisibility {
    Observed,
    NotPresentInCapture,
    NotObservableEncryptedHandshake,
    Truncated,
    ParseError,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsFieldVisibility {
    Observed,
    NotPresentInCapture,
    NotObservableEncryptedHandshake,
    Truncated,
    ParseError,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshakeObservation {
    pub hello: TlsHello,
    pub selected_alpn: Option<String>,
    pub selected_alpn_visibility: TlsFieldVisibility,
    pub certificates: Vec<CertificateMetadata>,
    pub certificate_visibility: CertificateVisibility,
}

pub const MAX_TLS_RECORD_LEN: usize = 18_432;
pub const MAX_TLS_HANDSHAKE_LEN: usize = 16 * 1024 * 1024;
pub const MAX_TLS_CERTIFICATES: usize = 32;
pub const MAX_TLS_CERTIFICATE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TLS_EXTENSIONS: usize = 128;
pub const MAX_TLS_EXTENSION_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsParseIssueKind {
    TruncatedRecord,
    RecordLengthLimitExceeded,
    TruncatedHandshake,
    HandshakeLengthLimitExceeded,
    InvalidHandshake,
    CertificateChainLimitExceeded,
    CertificateBytesLimitExceeded,
    MalformedCertificate,
    InconsistentNegotiation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsParseIssue {
    pub kind: TlsParseIssueKind,
    pub offset: usize,
}

pub fn protocol_quality_from_tls_issue(issue: &TlsParseIssue) -> core_domain::ProtocolQuality {
    match issue.kind {
        TlsParseIssueKind::TruncatedRecord
        | TlsParseIssueKind::TruncatedHandshake
        | TlsParseIssueKind::HandshakeLengthLimitExceeded => core_domain::ProtocolQuality::Partial,
        _ => core_domain::ProtocolQuality::Degraded,
    }
}

pub fn protocol_quality_from_dns_issue(issue: &DnsParseIssue) -> core_domain::ProtocolQuality {
    match issue.kind {
        DnsParseIssueKind::IncompleteTcpFrame
        | DnsParseIssueKind::TruncatedName
        | DnsParseIssueKind::TruncatedRecord => core_domain::ProtocolQuality::Partial,
        _ => core_domain::ProtocolQuality::Degraded,
    }
}

fn validate_tls_negotiation(hello: &TlsHello) -> Result<(), TlsParseIssue> {
    if hello.selected_version == Some(0x0304)
        && !matches!(hello.selected_cipher, Some(0x1301..=0x1303))
    {
        return Err(TlsParseIssue {
            kind: TlsParseIssueKind::InconsistentNegotiation,
            offset: 0,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub sans: Vec<String>,
    pub serial_number: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub certificate_sha256: String,
}

pub fn parse_certificate_metadata(der: &[u8]) -> Result<CertificateMetadata, TlsParseIssue> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::parse_x509_certificate;

    let (_, certificate) = parse_x509_certificate(der).map_err(|_| TlsParseIssue {
        kind: TlsParseIssueKind::MalformedCertificate,
        offset: 0,
    })?;
    let mut sans = Vec::new();
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        for name in &extension.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(value) = name {
                sans.push((*value).to_string());
            }
        }
    }
    let digest = Sha256::digest(der);
    Ok(CertificateMetadata {
        subject: Some(certificate.subject().to_string()),
        issuer: Some(certificate.issuer().to_string()),
        sans,
        serial_number: Some(
            certificate
                .raw_serial()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        ),
        not_before: Some(
            certificate
                .validity()
                .not_before
                .to_rfc2822()
                .unwrap_or_default(),
        ),
        not_after: Some(
            certificate
                .validity()
                .not_after
                .to_rfc2822()
                .unwrap_or_default(),
        ),
        certificate_sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

pub fn parse_tls_records(data: &[u8]) -> Result<Vec<Vec<u8>>, TlsParseIssue> {
    let mut offset = 0;
    let mut records = Vec::new();
    while offset < data.len() {
        if data.len() - offset < 5 {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::TruncatedRecord,
                offset,
            });
        }
        let len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if len > MAX_TLS_RECORD_LEN {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::RecordLengthLimitExceeded,
                offset,
            });
        }
        let end = offset.checked_add(5 + len).ok_or(TlsParseIssue {
            kind: TlsParseIssueKind::TruncatedRecord,
            offset,
        })?;
        if end > data.len() {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::TruncatedRecord,
                offset,
            });
        }
        records.push(data[offset..end].to_vec());
        offset = end;
    }
    Ok(records)
}

pub fn parse_tls_handshake_observation(
    data: &[u8],
) -> Result<TlsHandshakeObservation, TlsParseIssue> {
    let records = parse_tls_records(data)?;
    let mut handshake = Vec::new();
    for record in records {
        if record[0] == 22 {
            handshake.extend_from_slice(&record[5..]);
            if handshake.len() > MAX_TLS_HANDSHAKE_LEN {
                return Err(TlsParseIssue {
                    kind: TlsParseIssueKind::HandshakeLengthLimitExceeded,
                    offset: handshake.len(),
                });
            }
        }
    }
    let mut offset = 0;
    let mut hello = None;
    let mut certificates = Vec::new();
    while offset < handshake.len() {
        if handshake.len() - offset < 4 {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::TruncatedHandshake,
                offset,
            });
        }
        let message_type = handshake[offset];
        let length = ((handshake[offset + 1] as usize) << 16)
            | ((handshake[offset + 2] as usize) << 8)
            | handshake[offset + 3] as usize;
        if length > MAX_TLS_HANDSHAKE_LEN {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::HandshakeLengthLimitExceeded,
                offset,
            });
        }
        let end = offset.checked_add(4 + length).ok_or(TlsParseIssue {
            kind: TlsParseIssueKind::TruncatedHandshake,
            offset,
        })?;
        if end > handshake.len() {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::TruncatedHandshake,
                offset,
            });
        }
        match message_type {
            1 | 2 if hello.is_none() => {
                let mut record = vec![22, 3, 3, 0, 0];
                record[3..5].copy_from_slice(&(length as u16).to_be_bytes());
                record.extend_from_slice(&handshake[offset..end]);
                hello = Some(extract_tls(&record).ok_or(TlsParseIssue {
                    kind: TlsParseIssueKind::InvalidHandshake,
                    offset,
                })?);
            }
            11 => {
                certificates.extend(parse_certificate_message(
                    &handshake[offset + 4..end],
                    offset + 4,
                )?);
            }
            _ => {}
        }
        offset = end;
    }
    let hello = hello.ok_or(TlsParseIssue {
        kind: TlsParseIssueKind::InvalidHandshake,
        offset: 0,
    })?;
    validate_tls_negotiation(&hello)?;

    let selected_alpn = if hello.client {
        None
    } else {
        hello.alpn.first().cloned()
    };
    let selected_alpn_visibility = if selected_alpn.is_some() {
        TlsFieldVisibility::Observed
    } else {
        TlsFieldVisibility::NotPresentInCapture
    };
    let certificate_visibility = if !certificates.is_empty() {
        CertificateVisibility::Observed
    } else if !hello.client && hello.selected_version == Some(0x0304) {
        CertificateVisibility::NotObservableEncryptedHandshake
    } else {
        CertificateVisibility::NotPresentInCapture
    };
    Ok(TlsHandshakeObservation {
        hello,
        selected_alpn,
        selected_alpn_visibility,
        certificates,
        certificate_visibility,
    })
}

pub fn tls13_encrypted_followup_observation(hello: TlsHello) -> TlsHandshakeObservation {
    TlsHandshakeObservation {
        hello,
        selected_alpn: None,
        selected_alpn_visibility: TlsFieldVisibility::NotPresentInCapture,
        certificates: Vec::new(),
        certificate_visibility: CertificateVisibility::NotObservableEncryptedHandshake,
    }
}

fn parse_u24(data: &[u8], offset: usize) -> Result<usize, TlsParseIssue> {
    if data.len() < 3 {
        return Err(TlsParseIssue {
            kind: TlsParseIssueKind::TruncatedHandshake,
            offset,
        });
    }
    Ok(((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize)
}

fn parse_certificate_message(
    body: &[u8],
    body_offset: usize,
) -> Result<Vec<CertificateMetadata>, TlsParseIssue> {
    let list_len = parse_u24(body, body_offset)?;
    let list_end = 3usize.checked_add(list_len).ok_or(TlsParseIssue {
        kind: TlsParseIssueKind::TruncatedHandshake,
        offset: body_offset,
    })?;
    if list_end > body.len() {
        return Err(TlsParseIssue {
            kind: TlsParseIssueKind::TruncatedHandshake,
            offset: body_offset,
        });
    }
    let mut pos = 3;
    let mut result = Vec::new();
    while pos < list_end {
        if result.len() >= MAX_TLS_CERTIFICATES {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::CertificateChainLimitExceeded,
                offset: body_offset + pos,
            });
        }
        let cert_len = parse_u24(&body[pos..list_end], body_offset + pos)?;
        pos += 3;
        if cert_len > MAX_TLS_CERTIFICATE_BYTES {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::CertificateBytesLimitExceeded,
                offset: body_offset + pos,
            });
        }
        let cert_end = pos.checked_add(cert_len).ok_or(TlsParseIssue {
            kind: TlsParseIssueKind::TruncatedHandshake,
            offset: body_offset + pos,
        })?;
        if cert_end > list_end || cert_end + 2 > list_end {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::TruncatedHandshake,
                offset: body_offset + pos,
            });
        }
        let metadata = parse_certificate_metadata(&body[pos..cert_end])?;
        pos = cert_end;
        let extension_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        let extension_end = pos.checked_add(extension_len).ok_or(TlsParseIssue {
            kind: TlsParseIssueKind::TruncatedHandshake,
            offset: body_offset + pos,
        })?;
        if extension_end > list_end {
            return Err(TlsParseIssue {
                kind: TlsParseIssueKind::TruncatedHandshake,
                offset: body_offset + pos,
            });
        }
        pos = extension_end;
        result.push(metadata);
    }
    if pos != list_end || result.is_empty() {
        return Err(TlsParseIssue {
            kind: TlsParseIssueKind::MalformedCertificate,
            offset: body_offset + pos,
        });
    }
    Ok(result)
}
pub fn extract_tls(data: &[u8]) -> Option<TlsHello> {
    if data.len() < 9 || data[0] != 22 {
        return None;
    }
    let hs = data[5];
    if hs != 1 && hs != 2 {
        return None;
    }
    let body = &data[9..];
    if body.len() < 34 {
        return None;
    }
    let client = hs == 1;
    let version = u16::from_be_bytes([body[0], body[1]]);
    let mut p = 34;
    if p >= body.len() {
        return None;
    }
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    let mut cipher_suites = Vec::new();
    if client {
        if p + 2 > body.len() {
            return None;
        }
        let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        if p + n > body.len() {
            return None;
        }
        for pair in body[p..p + n].as_chunks::<2>().0 {
            cipher_suites.push(u16::from_be_bytes(*pair));
        }
        p += n;
        if p >= body.len() {
            return Some(TlsHello {
                client,
                version,
                offered_versions: Vec::new(),
                selected_version: None,
                selected_cipher: None,
                sni: None,
                alpn: Vec::new(),
                cipher_suites,
            });
        }
        p += 1 + body[p] as usize;
    } else if p + 2 <= body.len() {
        cipher_suites.push(u16::from_be_bytes([body[p], body[p + 1]]));
        p += 2;
        if p < body.len() {
            p += 1;
        }
    }
    if p + 2 > body.len() {
        return Some(TlsHello {
            client,
            version,
            offered_versions: Vec::new(),
            selected_version: None,
            selected_cipher: None,
            sni: None,
            alpn: Vec::new(),
            cipher_suites,
        });
    }
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let end = (p + ext_len).min(body.len());
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut offered_versions = Vec::new();
    let mut selected_version = if client { None } else { Some(version) };
    while p + 4 <= end {
        let typ = u16::from_be_bytes([body[p], body[p + 1]]);
        let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + len > end {
            break;
        }
        let ext = &body[p..p + len];
        if typ == 0 && ext.len() >= 5 {
            let n = u16::from_be_bytes([ext[3], ext[4]]) as usize;
            if 5 + n <= ext.len() {
                sni = std::str::from_utf8(&ext[5..5 + n]).ok().map(str::to_string);
            }
        }
        if typ == 16 && ext.len() >= 2 {
            let mut q = 2;
            while q < ext.len() {
                let n = ext[q] as usize;
                q += 1;
                if q + n > ext.len() {
                    break;
                }
                if let Ok(v) = std::str::from_utf8(&ext[q..q + n]) {
                    alpn.push(v.to_string())
                }
                q += n;
            }
        }
        if typ == 43 {
            if client && !ext.is_empty() {
                let n = ext[0] as usize;
                if n < ext.len() {
                    for pair in ext[1..1 + n].as_chunks::<2>().0 {
                        offered_versions.push(u16::from_be_bytes(*pair));
                    }
                }
            } else if !client && ext.len() == 2 {
                selected_version = Some(u16::from_be_bytes([ext[0], ext[1]]));
            }
        }
        p += len;
    }
    Some(TlsHello {
        client,
        version,
        offered_versions,
        selected_version,
        selected_cipher: if client {
            None
        } else {
            cipher_suites.first().copied()
        },
        sni,
        alpn,
        cipher_suites,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(index: usize, seq: u32, flags: &str, payload: &[u8]) -> ParsedPacket {
        ParsedPacket {
            packet_index: index,
            timestamp_epoch_sec: index as u32,
            timestamp_epoch_usec: 0,
            captured_len: payload.len() as u32,
            original_len: payload.len() as u32,
            ether_type: 0x0800,
            src_ip: Some("10.0.0.1".into()),
            dst_ip: Some("10.0.0.2".into()),
            protocol: Some("TCP".into()),
            src_port: Some(50000),
            dst_port: Some(443),
            tcp_flags: Some(flags.into()),
            payload_len: payload.len(),
            timestamp_epoch_nanos: 0,
            src_ipv6: None,
            dst_ipv6: None,
            vlan_id: None,
            tcp_sequence: Some(seq),
            tcp_acknowledgment: None,
            payload: payload.to_vec(),
            interface_id: None,
            physical_offset: Some(index as u64),
            packet_hash: String::new(),
            parse_quality: "COMPLETE".into(),
            packet_locator: format!("pcap://packet/{index}"),
            section_index: None,
            capture_timestamp: None,
        }
    }

    #[test]
    fn flow_instances_split_after_rst_and_ids_are_deterministic() {
        let packets = vec![
            tcp(1, 100, "SYN", b"a"),
            tcp(2, 101, "RST", b""),
            tcp(3, 200, "SYN", b"b"),
        ];
        let first = reconstruct_flows(&packets);
        let second = reconstruct_flows(&packets);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].flow_instance_id, second[0].flow_instance_id);
        assert_ne!(first[0].flow_instance_id, first[1].flow_instance_id);
    }

    #[test]
    fn identity_and_derivation_versions_are_separate() {
        let key = FlowKey {
            left: "10.0.0.1:1".into(),
            right: "10.0.0.2:2".into(),
            protocol: "TCP".into(),
        };
        let flow = flow_instance_id("artifact-hash", &key, "syn:1/seq:10");
        assert_eq!(
            flow,
            flow_instance_id("artifact-hash", &key, "syn:1/seq:10")
        );
        assert_ne!(
            flow,
            flow_instance_id("artifact-hash-2", &key, "syn:1/seq:10")
        );
        assert_ne!(
            derivation_id(&flow, "parser-1", "norm-1"),
            derivation_id(&flow, "parser-2", "norm-1")
        );
        assert_eq!(FLOW_IDENTITY_SCHEMA, "flow-instance-v1");
        assert_eq!(DERIVATION_SCHEMA, "derivation-v1");
    }

    #[test]
    fn conflicting_overlap_is_reported() {
        let result = reassemble_tcp_bounded(
            &[tcp(1, 100, "ACK", b"abcd"), tcp(2, 102, "ACK", b"ZZ")],
            ReassemblyLimits::default(),
        );
        assert_eq!(result.overlap_conflicts, 1);
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn dns_tcp_multiple_messages_and_http_body_policy() {
        let dns = [
            0u8, 12, 0x12, 0x34, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
        ];
        let mut framed = Vec::new();
        let wire_len = dns.len() as u16;
        framed.extend_from_slice(&wire_len.to_be_bytes());
        framed.extend_from_slice(&dns);
        framed.extend_from_slice(&wire_len.to_be_bytes());
        framed.extend_from_slice(&dns);
        assert_eq!(extract_dns_tcp_messages(&framed).unwrap().len(), 2);
        let http = extract_http(
            b"GET /admin HTTP/1.1\r\nHost: example.org\r\nContent-Length: 100\r\n\r\nsecret",
        )
        .unwrap();
        assert_eq!(http.uri.as_deref(), Some("/admin"));
        assert_eq!(http.content_length, Some(100));
        assert!(!http.body_retained);
    }

    #[test]
    fn dns_adversarial_inputs_are_typed_and_isolated() {
        let mut self_pointer = vec![0u8; 12];
        self_pointer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        let issue = extract_dns_detailed(&self_pointer).unwrap_err();
        assert_eq!(issue.kind, DnsParseIssueKind::CompressionLoop);
        assert!(issue.recoverable);

        let mut out_of_bounds = vec![0u8; 12];
        out_of_bounds.extend_from_slice(&[0xc0, 0xff, 0, 1, 0, 1]);
        assert_eq!(
            extract_dns_detailed(&out_of_bounds).unwrap_err().kind,
            DnsParseIssueKind::CompressionPointerOutOfBounds
        );

        let mut invalid_label_type = vec![0u8; 12];
        invalid_label_type.extend_from_slice(&[0x40, 0, 0, 1, 0, 1]);
        assert_eq!(
            extract_dns_detailed(&invalid_label_type).unwrap_err().kind,
            DnsParseIssueKind::InvalidLabelType
        );

        let valid = [
            0u8, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 1, 2,
            3, 4,
        ];
        assert_eq!(extract_dns_detailed(&valid).unwrap().answers.len(), 1);
        assert_eq!(
            extract_dns_tcp_messages_detailed(&[0, 50, 1, 2, 3])
                .unwrap_err()
                .kind,
            DnsParseIssueKind::IncompleteTcpFrame
        );

        let mut cycle = vec![0u8; 52];
        cycle[12..14].copy_from_slice(&[0xc0, 0x1e]);
        cycle[30..32].copy_from_slice(&[0xc0, 0x32]);
        cycle[50..52].copy_from_slice(&[0xc0, 0x1e]);
        assert_eq!(
            extract_dns_detailed(&cycle).unwrap_err().kind,
            DnsParseIssueKind::CompressionLoop
        );

        let mut truncated_pointer = vec![0u8; 13];
        truncated_pointer[12] = 0xc0;
        assert_eq!(
            extract_dns_detailed(&truncated_pointer).unwrap_err().kind,
            DnsParseIssueKind::TruncatedName
        );

        let mut too_long_name = vec![0u8; 12];
        for _ in 0..4 {
            too_long_name.push(63);
            too_long_name.extend(std::iter::repeat_n(b'a', 63));
        }
        too_long_name.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert_eq!(
            extract_dns_detailed(&too_long_name).unwrap_err().kind,
            DnsParseIssueKind::ExpandedNameTooLong
        );

        let mut jump_limit = vec![0u8; 12 + 2 * 34 + 1];
        for offset in (12..12 + 2 * 34).step_by(2) {
            let target = offset + 2;
            jump_limit[offset..offset + 2]
                .copy_from_slice(&(0xc000u16 | target as u16).to_be_bytes());
        }
        assert_eq!(
            extract_dns_detailed(&jump_limit).unwrap_err().kind,
            DnsParseIssueKind::CompressionJumpLimitExceeded
        );

        let mut truncated_rr = vec![0u8; 12];
        truncated_rr[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        truncated_rr[4..6].copy_from_slice(&1u16.to_be_bytes());
        truncated_rr[6..8].copy_from_slice(&1u16.to_be_bytes());
        truncated_rr.extend_from_slice(&[0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 4, 1, 2]);
        assert_eq!(
            extract_dns_detailed(&truncated_rr).unwrap_err().kind,
            DnsParseIssueKind::TruncatedRecord
        );
    }

    #[test]
    fn timestamp_resolution_is_exact_and_preserves_raw_provenance() {
        let micros = TimestampResolution::Decimal(6)
            .capture_timestamp(1_700_000_000_123_456, 0)
            .unwrap();
        assert_eq!(micros.normalized_utc.timestamp(), 1_700_000_000);
        assert_eq!(micros.normalized_utc.timestamp_subsec_nanos(), 123_456_000);
        assert!(!micros.precision_loss);

        let nanos = TimestampResolution::Decimal(9)
            .capture_timestamp(1_700_000_000_123_456_789, 0)
            .unwrap();
        assert_eq!(nanos.normalized_utc.timestamp_subsec_nanos(), 123_456_789);
        assert_eq!(nanos.raw_value, 1_700_000_000_123_456_789);
        assert!(!nanos.precision_loss);

        let binary = TimestampResolution::Binary(10)
            .capture_timestamp((1u64 << 10) + 1, 3600)
            .unwrap();
        assert_eq!(binary.normalized_utc.timestamp(), 3601);
        assert!(binary.precision_loss);
        assert_eq!(binary.offset_seconds, 3600);
    }

    #[test]
    fn record_offset_arithmetic_is_checked() {
        assert_eq!(
            checked_record_end(u64::MAX - 2, 16),
            Err(CaptureParseIssueKind::RecordOffsetOverflow)
        );
        assert_eq!(checked_record_end(100, 16), Ok(116));
    }

    #[test]
    fn absent_resolution_defaults_to_decimal_microseconds() {
        let interface = InterfaceDescription {
            id: 0,
            linktype: 1,
            snaplen: 65535,
            section_index: 0,
            timestamp_resolution: TimestampResolution::Decimal(6),
            tsoffset_seconds: 0,
        };
        assert_eq!(
            interface.timestamp_resolution,
            TimestampResolution::Decimal(6)
        );
    }
}
