use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrokerCapability {
    ReadProcesses,
    ReadFirewall,
    CapturePcap,
    AcquireMemory,
    ReadRegistry,
    NetworkScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryTarget {
    FullPhysical,
    ProcessPid(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryHive {
    HkeyLocalMachine,
    HkeyCurrentUser,
    HkeyUsers,
}

/// Typed, strictly bounded operations executed by the privileged daemon.
/// UI is prohibited from sending arbitrary commands or raw argv arrays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedOperation {
    CapturePcap {
        interface_id: String,
        duration_secs: u32,
        max_bytes: u64,
        bpf_filter: Option<String>,
    },
    ReadFirewallRules {
        direction: Option<RuleDirection>,
    },
    CollectProcessMetadata {
        pid: u32,
    },
    AcquireMemorySample {
        target: MemoryTarget,
        chunk_size_mb: u32,
    },
    CollectRegistryKeys {
        hive: RegistryHive,
        subpath: String,
    },
    RunTargetedScan {
        target_ip: String,
        ports: Vec<u16>,
        rate_limit: u32,
    },
}

impl PrivilegedOperation {
    pub fn required_capability(&self) -> BrokerCapability {
        match self {
            PrivilegedOperation::CapturePcap { .. } => BrokerCapability::CapturePcap,
            PrivilegedOperation::ReadFirewallRules { .. } => BrokerCapability::ReadFirewall,
            PrivilegedOperation::CollectProcessMetadata { .. } => BrokerCapability::ReadProcesses,
            PrivilegedOperation::AcquireMemorySample { .. } => BrokerCapability::AcquireMemory,
            PrivilegedOperation::CollectRegistryKeys { .. } => BrokerCapability::ReadRegistry,
            PrivilegedOperation::RunTargetedScan { .. } => BrokerCapability::NetworkScan,
        }
    }
}
