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

        let bytes = tokio::fs::read(path).await.map_err(|e| ToolAdapterError::ExecutionFailed(e.to_string()))?;
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
