#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanJobId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ToolRunId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: ScanJobId,
    pub target: ScanTarget,
    pub profile: ScanProfile,
    pub created_at: DateTime<Utc>,
    pub status: ScanJobStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTarget {
    SingleIp(Ipv4Addr),
    Cidr { base: Ipv4Addr, prefix_len: u8 },
    Range { start: Ipv4Addr, end: Ipv4Addr },
    Hostname(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanProfile {
    Quick,
    Standard,
    Deep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanJobStatus {
    Pending,
    Running,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Timeout,
    Unreachable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub extra: serde_json::Value,
    pub confidence: f32,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: TransportProto,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveHost {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub discovery_method: DiscoveryMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    ArpCache,
    TcpProbe,
    PingEcho,
    Combined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanObservation {
    pub tool_run_id: String,
    pub collector: String,
    pub collector_version: String,
    pub method: String,
    pub source_target: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub confidence: f32,
    pub privilege_level: String,
    pub raw_result_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCoverage {
    pub targets_total: u32,
    pub targets_responsive: u32,
    pub tcp_ports_attempted: u32,
    pub tcp_ports_open: u32,
    pub tcp_ports_filtered: u32,
    pub tcp_ports_timeout: u32,
    pub tcp_ports_closed: u32,
    pub tcp_ports_error: u32,
    pub udp_ports_attempted: u32,
    pub services_identified: u32,
    pub services_unknown: u32,
    pub os_identified: u32,
    pub errors: u32,
    pub quality: CoverageQuality,
    pub confidence: f32,
    pub scan_duration_ms: u64,
    pub privilege_level: String,
    pub nmap_available: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageQuality {
    Full,
    Partial,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub target: String,
    pub stage: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRun {
    pub id: String,
    pub tool: String,
    pub tool_version: String,
    pub args: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub stdout_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAssetObservation {
    pub ip: Option<Ipv4Addr>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub cert_names: Vec<String>,
    pub smb_hostname: Option<String>,
    pub source: String,
}
