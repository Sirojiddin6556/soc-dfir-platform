use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureQuality {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolQuality {
    Complete,
    Degraded,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkObservationQuality {
    pub capture: CaptureQuality,
    pub flow: Option<FlowQuality>,
    pub protocol: Option<ProtocolQuality>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDiagnosticProvenance {
    pub artifact_digest: String,
    pub packet_index: Option<u64>,
    pub packet_locator: Option<String>,
    pub flow_instance_id: Option<String>,
    pub direction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRun {
    pub id: EntityId,
    pub case_id: EntityId,
    pub adapter_name: String,
    pub adapter_version: String,
    pub tool_version: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub input_hash: String,
    pub output_hash: String,
    pub exit_status: i32,
    pub timeout_triggered: bool,
    pub workflow_task_id: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawToolResult {
    pub tool_name: String,
    pub tool_version: String,
    pub exit_code: i32,
    pub stdout_bytes: Vec<u8>,
    pub stderr_bytes: Vec<u8>,
    pub execution_duration_ms: u64,
    pub output_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: EntityId,
    pub case_id: EntityId,
    pub artifact_id: Option<EntityId>,
    pub tool_run_id: Option<EntityId>,
    pub source_tool: String,
    pub raw_event_type: String,
    pub source_timestamp: Option<DateTime<Utc>>,
    pub ingest_timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
    #[serde(default)]
    pub network_quality: Option<NetworkObservationQuality>,
    #[serde(default)]
    pub network_provenance: Option<NetworkDiagnosticProvenance>,
}
