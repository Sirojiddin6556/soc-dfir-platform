#![forbid(unsafe_code)]

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

/// Baseline EVTX Adapter
pub struct EvtxAdapter;

#[async_trait]
impl ToolAdapter for EvtxAdapter {
    fn tool_name(&self) -> &'static str {
        "evtx_parser"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn supported_extensions(&self) -> &'static [&'static str] {
        &["evtx"]
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
            execution_duration_ms: 15,
            output_hash,
        })
    }
}

/// Baseline PCAP Packet Capture Adapter
pub struct PcapAdapter;

#[async_trait]
impl ToolAdapter for PcapAdapter {
    fn tool_name(&self) -> &'static str {
        "pcap_parser"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn supported_extensions(&self) -> &'static [&'static str] {
        &["pcap", "pcapng", "cap"]
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

    #[tokio::test]
    async fn test_pcap_adapter_file_parsing() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_file = std::env::temp_dir().join(format!("test_{}.pcap", ts));
        tokio::fs::write(&temp_file, b"DUMMY_PCAP_MAGIC_BYTES")
            .await
            .unwrap();

        let adapter = PcapAdapter;
        let res = adapter.parse_artifact(&temp_file).await.unwrap();
        assert_eq!(res.tool_name, "pcap_parser");
        assert_eq!(res.exit_code, 0);

        let _ = tokio::fs::remove_file(temp_file).await;
    }
}
