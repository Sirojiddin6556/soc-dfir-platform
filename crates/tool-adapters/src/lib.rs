#![forbid(unsafe_code)]

pub mod evtx;
pub mod magic;
pub mod pcap;

use async_trait::async_trait;
use core_domain::observation::RawToolResult;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ToolAdapterError {
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Malformed format: {0}")]
    MalformedFormat(String),
}

#[async_trait]
pub trait ToolAdapter: Send + Sync {
    fn tool_name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn supported_extensions(&self) -> &'static [&'static str];

    /// Executes parser on local file artifact, returning RawToolResult.
    /// Never directly creates Facts or AttackNodes.
    async fn parse_artifact(&self, path: &Path) -> Result<RawToolResult, ToolAdapterError>;
}

/// Real Windows EVTX Binary Log Adapter (Native BinXML)
pub struct EvtxBinaryAdapter;
pub struct EvtxAdapter;

#[async_trait]
impl ToolAdapter for EvtxBinaryAdapter {
    fn tool_name(&self) -> &'static str {
        "evtx_parser"
    }

    fn version(&self) -> &'static str {
        evtx::PARSER_VERSION
    }

    fn supported_extensions(&self) -> &'static [&'static str] {
        &["evtx"]
    }

    async fn parse_artifact(&self, path: &Path) -> Result<RawToolResult, ToolAdapterError> {
        if !path.exists() {
            return Err(ToolAdapterError::FileNotFound(path.display().to_string()));
        }

        let parse_result =
            evtx::parse_evtx_file(path).map_err(ToolAdapterError::MalformedFormat)?;

        let serialized = serde_json::to_vec(&parse_result)
            .map_err(|e| ToolAdapterError::ExecutionFailed(e.to_string()))?;
        let output_hash = blake3::hash(&serialized).to_hex().to_string();

        Ok(RawToolResult {
            tool_name: self.tool_name().to_string(),
            tool_version: self.version().to_string(),
            exit_code: 0,
            stdout_bytes: serialized,
            stderr_bytes: Vec::new(),
            execution_duration_ms: 15,
            output_hash,
        })
    }
}

#[async_trait]
impl ToolAdapter for EvtxAdapter {
    fn tool_name(&self) -> &'static str {
        "evtx_parser"
    }

    fn version(&self) -> &'static str {
        evtx::PARSER_VERSION
    }

    fn supported_extensions(&self) -> &'static [&'static str] {
        &["evtx"]
    }

    async fn parse_artifact(&self, path: &Path) -> Result<RawToolResult, ToolAdapterError> {
        EvtxBinaryAdapter.parse_artifact(path).await
    }
}

/// Offline Exported EVTX JSON-Stream Adapter (evtx_dump / Chainsaw JSONL)
pub struct EvtxJsonExportAdapter;

#[async_trait]
impl ToolAdapter for EvtxJsonExportAdapter {
    fn tool_name(&self) -> &'static str {
        "evtx_json_parser"
    }

    fn version(&self) -> &'static str {
        evtx::JSON_EXPORT_PARSER_VERSION
    }

    fn supported_extensions(&self) -> &'static [&'static str] {
        &["json", "jsonl"]
    }

    async fn parse_artifact(&self, path: &Path) -> Result<RawToolResult, ToolAdapterError> {
        if !path.exists() {
            return Err(ToolAdapterError::FileNotFound(path.display().to_string()));
        }

        let parse_result = evtx::EvtxJsonExportAdapter::parse_file(path)
            .map_err(ToolAdapterError::MalformedFormat)?;

        let serialized = serde_json::to_vec(&parse_result)
            .map_err(|e| ToolAdapterError::ExecutionFailed(e.to_string()))?;
        let output_hash = blake3::hash(&serialized).to_hex().to_string();

        Ok(RawToolResult {
            tool_name: self.tool_name().to_string(),
            tool_version: self.version().to_string(),
            exit_code: 0,
            stdout_bytes: serialized,
            stderr_bytes: Vec::new(),
            execution_duration_ms: 10,
            output_hash,
        })
    }
}

/// Real Libpcap Binary Packet Capture Adapter
pub struct PcapAdapter;

impl PcapAdapter {
    pub fn parse_capture_with_capture_sink<S: pcap::phase3::CaptureSink>(
        path: &Path,
        sink: S,
    ) -> Result<pcap::phase3::PcapParseResult, ToolAdapterError> {
        pcap::phase3::parse_capture_file_with_capture_sink(path, sink)
            .map_err(ToolAdapterError::MalformedFormat)
    }

    /// Production packet-at-a-time API. The callback owns each packet only for
    /// the duration of the call and must persist or otherwise consume it.
    pub fn parse_capture_with_sink<F>(
        path: &Path,
        sink: F,
    ) -> Result<pcap::phase3::PcapParseResult, ToolAdapterError>
    where
        F: FnMut(pcap::ParsedPacket) -> Result<(), String>,
    {
        pcap::phase3::parse_capture_file_with_sink(path, sink)
            .map_err(ToolAdapterError::MalformedFormat)
    }
}

#[async_trait]
impl ToolAdapter for PcapAdapter {
    fn tool_name(&self) -> &'static str {
        "pcap_parser"
    }

    fn version(&self) -> &'static str {
        pcap::phase3::PARSER_VERSION
    }

    fn supported_extensions(&self) -> &'static [&'static str] {
        &["pcap", "pcapng", "cap"]
    }

    async fn parse_artifact(&self, path: &Path) -> Result<RawToolResult, ToolAdapterError> {
        if !path.exists() {
            return Err(ToolAdapterError::FileNotFound(path.display().to_string()));
        }

        let summary = pcap::phase3::parse_capture_file_with_sink(path, |_| Ok(()))
            .map_err(ToolAdapterError::MalformedFormat)?;

        let serialized = serde_json::to_vec(&summary)
            .map_err(|e| ToolAdapterError::ExecutionFailed(e.to_string()))?;
        let output_hash = blake3::hash(&serialized).to_hex().to_string();

        Ok(RawToolResult {
            tool_name: self.tool_name().to_string(),
            tool_version: self.version().to_string(),
            exit_code: 0,
            stdout_bytes: serialized,
            stderr_bytes: Vec::new(),
            execution_duration_ms: 25,
            output_hash,
        })
    }
}

/// Host & Network Discovery Adapter
pub struct HostDiscoveryAdapter;

#[async_trait]
impl ToolAdapter for HostDiscoveryAdapter {
    fn tool_name(&self) -> &'static str {
        "host_discovery"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn supported_extensions(&self) -> &'static [&'static str] {
        &["json", "xml"]
    }

    async fn parse_artifact(&self, path: &Path) -> Result<RawToolResult, ToolAdapterError> {
        if !path.exists() {
            return Err(ToolAdapterError::FileNotFound(path.display().to_string()));
        }

        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| ToolAdapterError::ExecutionFailed(e.to_string()))?;
        let output_hash = blake3::hash(&bytes).to_hex().to_string();

        Ok(RawToolResult {
            tool_name: self.tool_name().to_string(),
            tool_version: self.version().to_string(),
            exit_code: 0,
            stdout_bytes: bytes,
            stderr_bytes: Vec::new(),
            execution_duration_ms: 12,
            output_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synthetic_pcap() -> Vec<u8> {
        let mut buf = Vec::new();
        // 1. PCAP global header (24 bytes)
        buf.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes()); // magic
        buf.extend_from_slice(&2u16.to_ne_bytes()); // major
        buf.extend_from_slice(&4u16.to_ne_bytes()); // minor
        buf.extend_from_slice(&0i32.to_ne_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_ne_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_ne_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_ne_bytes()); // linktype = Ethernet

        // 2. Packet header (16 bytes)
        let pkt_len = 54u32; // 14 eth + 20 ipv4 + 20 tcp
        buf.extend_from_slice(&1720000000u32.to_ne_bytes()); // ts_sec
        buf.extend_from_slice(&1000u32.to_ne_bytes()); // ts_usec
        buf.extend_from_slice(&pkt_len.to_ne_bytes()); // incl_len
        buf.extend_from_slice(&pkt_len.to_ne_bytes()); // orig_len

        // 3. Ethernet header (14 bytes)
        buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
        buf.extend_from_slice(&[0x08, 0x00]); // EtherType = IPv4

        // 4. IPv4 header (20 bytes)
        buf.push(0x45); // version 4, IHL 5
        buf.push(0x00); // DSCP/ECN
        buf.extend_from_slice(&40u16.to_be_bytes()); // Total length
        buf.extend_from_slice(&1234u16.to_be_bytes()); // Id
        buf.extend_from_slice(&0u16.to_be_bytes()); // Flags/Frag
        buf.push(64); // TTL
        buf.push(6); // Protocol = TCP
        buf.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        buf.extend_from_slice(&[192, 168, 1, 105]); // Src IP: 192.168.1.105
        buf.extend_from_slice(&[10, 0, 0, 15]); // Dst IP: 10.0.0.15

        // 5. TCP header (20 bytes)
        buf.extend_from_slice(&49152u16.to_be_bytes()); // Src port
        buf.extend_from_slice(&443u16.to_be_bytes()); // Dst port (HTTPS)
        buf.extend_from_slice(&100000u32.to_be_bytes()); // Seq
        buf.extend_from_slice(&0u32.to_be_bytes()); // Ack
        buf.push(0x50); // Data offset (5 * 4 = 20)
        buf.push(0x02); // Flags = SYN
        buf.extend_from_slice(&64240u16.to_be_bytes()); // Window
        buf.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        buf.extend_from_slice(&0u16.to_be_bytes()); // Urgent ptr

        buf
    }

    #[tokio::test]
    async fn test_real_binary_pcap_parsing() {
        let pcap_bytes = build_synthetic_pcap();
        let temp_file =
            std::env::temp_dir().join(format!("real_test_{}.pcap", uuid::Uuid::now_v7()));
        tokio::fs::write(&temp_file, &pcap_bytes).await.unwrap();

        let adapter = PcapAdapter;
        let res = adapter.parse_artifact(&temp_file).await.unwrap();
        assert_eq!(res.tool_name, "pcap_parser");
        assert_eq!(res.exit_code, 0);

        let summary: pcap::phase3::PcapParseResult =
            serde_json::from_slice(&res.stdout_bytes).unwrap();
        assert_eq!(summary.packets_seen, 1);
        assert_eq!(summary.packets_decoded, 1);

        // Detailed assertions use the explicitly bounded compatibility API;
        // the adapter contract itself remains summary-only.
        let parsed = pcap::phase3::parse_capture_collect(&temp_file).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].src_ip.as_deref(), Some("192.168.1.105"));
        assert_eq!(parsed[0].dst_ip.as_deref(), Some("10.0.0.15"));
        assert_eq!(parsed[0].protocol.as_deref(), Some("TCP"));
        assert_eq!(parsed[0].dst_port, Some(443));
        assert_eq!(parsed[0].tcp_flags.as_deref(), Some("SYN"));

        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_malformed_pcap_rejection() {
        let temp_file = std::env::temp_dir().join(format!("corrupt_{}.pcap", uuid::Uuid::now_v7()));
        tokio::fs::write(&temp_file, b"NOT_A_VALID_PCAP_HEADER")
            .await
            .unwrap();

        let adapter = PcapAdapter;
        let res = adapter.parse_artifact(&temp_file).await;
        assert!(matches!(res, Err(ToolAdapterError::MalformedFormat(_))));

        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_evtx_json_stream_parsing() {
        let json_line = r#"{"Event": {"System": {"EventID": 10, "Computer": "DC01", "Channel": "Security"}, "EventData": {"TargetImage": "C:\\Windows\\System32\\lsass.exe"}}}"#;
        let temp_file = std::env::temp_dir().join(format!("stream_{}.jsonl", uuid::Uuid::now_v7()));
        tokio::fs::write(&temp_file, json_line.as_bytes())
            .await
            .unwrap();

        let adapter = EvtxJsonExportAdapter;
        let res = adapter.parse_artifact(&temp_file).await.unwrap();
        let parsed: evtx::EvtxParseResult = serde_json::from_slice(&res.stdout_bytes).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].event_id, 10);
        assert_eq!(parsed.records[0].computer.as_deref(), Some("DC01"));

        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_malformed_evtx_rejection() {
        let temp_file = std::env::temp_dir().join(format!("corrupt_{}.evtx", uuid::Uuid::now_v7()));
        tokio::fs::write(&temp_file, b"RANDOM_CORRUPT_BYTES_NOT_EVTX")
            .await
            .unwrap();

        let adapter = EvtxBinaryAdapter;
        let res = adapter.parse_artifact(&temp_file).await;
        assert!(matches!(res, Err(ToolAdapterError::MalformedFormat(_))));

        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_parse_real_binary_evtx_single_chunk() {
        let fixture_path =
            std::path::Path::new("../../tests/fixtures/forensics/system_single_chunk.evtx");
        assert!(
            fixture_path.exists(),
            "required forensic fixture missing: {}",
            fixture_path.display()
        );

        let adapter = EvtxBinaryAdapter;
        let res = adapter.parse_artifact(fixture_path).await.unwrap();
        assert_eq!(res.tool_name, "evtx_parser");
        assert_eq!(res.exit_code, 0);

        let parsed: evtx::EvtxParseResult = serde_json::from_slice(&res.stdout_bytes).unwrap();
        assert!(parsed.total_records > 0 || !parsed.records.is_empty());
        for rec in &parsed.records {
            assert!(rec.record_id > 0);
            assert!(
                rec.record_locator.starts_with("evtx://record/")
                    || rec.record_locator.starts_with("evtx://chunk/")
            );
            assert!(!rec.decoded_record_hash.is_empty());
        }
    }
}
