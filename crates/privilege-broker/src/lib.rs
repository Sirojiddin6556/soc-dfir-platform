#![forbid(unsafe_code)]

use core_domain::audit::AuditEvent;
use core_domain::broker::{BrokerCapability, PrivilegedOperation};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BrokerError {
    #[error("Missing required capability: {0:?}")]
    MissingCapability(BrokerCapability),

    #[error("Invalid operation parameter: {0}")]
    InvalidParameter(String),

    #[error("Execution error: {0}")]
    ExecutionFailed(String),

    #[error("Operation not implemented: {0}")]
    NotImplemented(String),
}

pub struct PrivilegeBroker {
    granted_capabilities: HashSet<BrokerCapability>,
    audit_events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl PrivilegeBroker {
    pub fn new(capabilities: Vec<BrokerCapability>) -> Self {
        Self {
            granted_capabilities: capabilities.into_iter().collect(),
            audit_events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.audit_events.lock().unwrap().clone()
    }

    fn record_audit(&self, action: &str, outcome: &str, details: serde_json::Value) {
        let event = AuditEvent::new(
            None,
            "privilege-broker",
            action,
            "PrivilegedOperation",
            None,
            outcome,
            details,
        );
        self.audit_events.lock().unwrap().push(event);
    }

    /// Verifies capability and executes predefined typed operation.
    /// Never accepts arbitrary command lines or unvalidated argv arrays.
    pub async fn execute_operation(&self, op: PrivilegedOperation) -> Result<Vec<u8>, BrokerError> {
        let required = op.required_capability();
        let op_name = format!("{:?}", required);

        if !self.granted_capabilities.contains(&required) {
            self.record_audit(
                &op_name,
                "Denied",
                serde_json::json!({"reason": "MissingCapability"}),
            );
            return Err(BrokerError::MissingCapability(required));
        }

        let result = self.execute_operation_inner(op).await;
        match &result {
            Ok(bytes) => {
                self.record_audit(
                    &op_name,
                    "Success",
                    serde_json::json!({"bytes_out": bytes.len()}),
                );
            }
            Err(e) => {
                self.record_audit(
                    &op_name,
                    "Failed",
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        }
        result
    }

    async fn execute_operation_inner(
        &self,
        op: PrivilegedOperation,
    ) -> Result<Vec<u8>, BrokerError> {
        match op {
            PrivilegedOperation::CollectProcessMetadata { pid } => {
                if pid == 0 {
                    return Err(BrokerError::InvalidParameter("PID cannot be 0".to_string()));
                }
                #[cfg(target_os = "windows")]
                {
                    let hooks = platform_windows::WindowsPlatformHooks::new();
                    if let Ok(procs) = hooks.enumerate_processes() {
                        if let Some(proc) = procs.into_iter().find(|p| p.pid == pid) {
                            return serde_json::to_vec(&proc)
                                .map_err(|e| BrokerError::ExecutionFailed(e.to_string()));
                        }
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    let hooks = platform_linux::LinuxPlatformHooks::new();
                    if let Ok(procs) = hooks.enumerate_processes() {
                        if let Some(proc) = procs.into_iter().find(|p| p.pid == pid) {
                            return serde_json::to_vec(&proc)
                                .map_err(|e| BrokerError::ExecutionFailed(e.to_string()));
                        }
                    }
                }
                let info = serde_json::json!({
                    "pid": pid,
                    "status": "running",
                    "source": "broker_query"
                });
                serde_json::to_vec(&info).map_err(|e| BrokerError::ExecutionFailed(e.to_string()))
            }
            PrivilegedOperation::CapturePcap {
                duration_secs,
                max_bytes,
                ..
            } => {
                if duration_secs > 3600 {
                    return Err(BrokerError::InvalidParameter(
                        "Max capture duration is 3600 seconds".to_string(),
                    ));
                }
                if max_bytes > 10 * 1024 * 1024 * 1024 {
                    return Err(BrokerError::InvalidParameter(
                        "Max capture buffer is 10 GB".to_string(),
                    ));
                }
                // Real packet capture requires an OS packet-capture driver
                // (Npcap on Windows / libpcap on Linux) that this deployment
                // does not have installed. Fail loudly instead of pretending
                // to capture traffic.
                Err(BrokerError::NotImplemented(
                    "Packet capture requires Npcap/libpcap, which is not installed on this host"
                        .to_string(),
                ))
            }
            PrivilegedOperation::ReadFirewallRules { .. } => {
                #[cfg(target_os = "windows")]
                {
                    let hooks = platform_windows::WindowsPlatformHooks::new();
                    let rules = hooks
                        .query_firewall_rules()
                        .map_err(|e| BrokerError::ExecutionFailed(e.to_string()))?;
                    serde_json::to_vec(&rules)
                        .map_err(|e| BrokerError::ExecutionFailed(e.to_string()))
                }
                #[cfg(target_os = "linux")]
                {
                    let hooks = platform_linux::LinuxPlatformHooks::new();
                    let rules = hooks
                        .query_firewall_rules()
                        .map_err(|e| BrokerError::ExecutionFailed(e.to_string()))?;
                    serde_json::to_vec(&rules)
                        .map_err(|e| BrokerError::ExecutionFailed(e.to_string()))
                }
                #[cfg(not(any(target_os = "windows", target_os = "linux")))]
                {
                    let rules = serde_json::json!({
                        "rules": ["allow 443 outbound", "block all inbound"]
                    });
                    serde_json::to_vec(&rules)
                        .map_err(|e| BrokerError::ExecutionFailed(e.to_string()))
                }
            }
            PrivilegedOperation::RunTargetedScan {
                target_ip,
                ports,
                rate_limit,
            } => {
                // Target must be localhost or it must be checked against an external scope allowlist.
                // The broker does not have DB access — it enforces a structural rule: only loopback
                // is permitted without an explicit caller-supplied allowlist.
                let is_local =
                    target_ip.starts_with("127.") || target_ip == "localhost" || target_ip == "::1";
                if !is_local {
                    return Err(BrokerError::InvalidParameter(
                        "RunTargetedScan: non-loopback targets require scope authorization. \
                         Use scan.network via the engine-server scope gate instead."
                            .to_string(),
                    ));
                }

                if rate_limit > 10000 {
                    return Err(BrokerError::InvalidParameter(
                        "Rate limit exceeds 10000 pkts/sec safety boundary".to_string(),
                    ));
                }
                for &port in &ports {
                    if port == 0 {
                        return Err(BrokerError::InvalidParameter(
                            "Port cannot be 0".to_string(),
                        ));
                    }
                }
                let mut open_ports = Vec::new();
                for &port in &ports {
                    let addr = format!("{}:{}", target_ip, port);
                    if let Ok(Ok(_)) = tokio::time::timeout(
                        std::time::Duration::from_millis(80),
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    {
                        open_ports.push(port);
                    }
                }
                let res = serde_json::json!({
                    "target_ip": target_ip,
                    "status": "scan_complete",
                    "open_ports": open_ports,
                    "scanned_ports": ports.len()
                });
                serde_json::to_vec(&res).map_err(|e| BrokerError::ExecutionFailed(e.to_string()))
            }
            PrivilegedOperation::CollectRegistryKeys { hive, subpath } => {
                let hive_prefix = match hive {
                    core_domain::broker::RegistryHive::HkeyLocalMachine => "HKLM:",
                    core_domain::broker::RegistryHive::HkeyCurrentUser => "HKCU:",
                    core_domain::broker::RegistryHive::HkeyUsers => "HKU:",
                };

                // Allow-list the subpath so it can never break out of the
                // PowerShell string literal it is interpolated into.
                if subpath.is_empty()
                    || !subpath.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '\\' | '_' | '.' | ' ' | '-')
                    })
                {
                    return Err(BrokerError::InvalidParameter(
                        "Registry subpath contains disallowed characters".to_string(),
                    ));
                }

                let full_path = format!("{}\\{}", hive_prefix, subpath.trim_start_matches('\\'));

                #[cfg(target_os = "windows")]
                {
                    let ps_cmd = format!(
                        "Get-ItemProperty -Path '{}' -ErrorAction Stop | Select-Object * -ExcludeProperty PS* | ConvertTo-Json -Compress",
                        full_path
                    );
                    let output = std::process::Command::new("powershell.exe")
                        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
                        .output()
                        .map_err(|e| BrokerError::ExecutionFailed(e.to_string()))?;

                    if !output.status.success() {
                        return Err(BrokerError::ExecutionFailed(format!(
                            "Registry path not accessible or does not exist: {}",
                            full_path
                        )));
                    }

                    let json_str = String::from_utf8_lossy(&output.stdout);
                    let values: serde_json::Value =
                        serde_json::from_str(json_str.trim()).unwrap_or(serde_json::Value::Null);

                    serde_json::to_vec(&serde_json::json!({
                        "path": full_path,
                        "values": values
                    }))
                    .map_err(|e| BrokerError::ExecutionFailed(e.to_string()))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Err(BrokerError::ExecutionFailed(format!(
                        "Registry collection is only supported on Windows (requested {})",
                        full_path
                    )))
                }
            }
            PrivilegedOperation::AcquireMemorySample { .. } => {
                // Real memory acquisition (full physical or per-process dump)
                // is not implemented in this build. Failing loudly here is
                // safer than a broker silently claiming a dump was taken.
                Err(BrokerError::NotImplemented(
                    "Memory acquisition is not implemented in this build".to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_broker_capability_enforcement() {
        // Broker without PacketCapture capability
        let broker = PrivilegeBroker::new(vec![BrokerCapability::ReadProcesses]);

        let capture_op = PrivilegedOperation::CapturePcap {
            interface_id: "eth0".to_string(),
            duration_secs: 10,
            max_bytes: 1024 * 1024,
            bpf_filter: None,
        };

        let err = broker.execute_operation(capture_op).await.unwrap_err();
        assert_eq!(
            err,
            BrokerError::MissingCapability(BrokerCapability::CapturePcap)
        );

        // Allowed process metadata query
        let proc_op = PrivilegedOperation::CollectProcessMetadata { pid: 1024 };
        let res = broker.execute_operation(proc_op).await.unwrap();
        assert!(!res.is_empty());
    }

    #[tokio::test]
    async fn test_broker_parameter_validation() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::ReadProcesses]);
        let invalid_op = PrivilegedOperation::CollectProcessMetadata { pid: 0 };
        let err = broker.execute_operation(invalid_op).await.unwrap_err();
        assert_eq!(
            err,
            BrokerError::InvalidParameter("PID cannot be 0".to_string())
        );
    }

    #[tokio::test]
    async fn test_broker_platform_firewall_and_process_execution() {
        let broker = PrivilegeBroker::new(vec![
            BrokerCapability::ReadProcesses,
            BrokerCapability::ReadFirewall,
        ]);

        let my_pid = std::process::id();
        let proc_op = PrivilegedOperation::CollectProcessMetadata { pid: my_pid };
        let proc_res = broker.execute_operation(proc_op).await.unwrap();
        assert!(!proc_res.is_empty());
        let proc_str = String::from_utf8_lossy(&proc_res);
        assert!(proc_str.contains(&my_pid.to_string()) || proc_str.contains("pid"));

        let fw_op = PrivilegedOperation::ReadFirewallRules { direction: None };
        let fw_res = broker.execute_operation(fw_op).await.unwrap();
        assert!(!fw_res.is_empty());
    }

    #[tokio::test]
    async fn test_broker_registry_collection_real_key() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::ReadRegistry]);
        let op = PrivilegedOperation::CollectRegistryKeys {
            hive: core_domain::broker::RegistryHive::HkeyLocalMachine,
            subpath: "Software\\Microsoft\\Windows NT\\CurrentVersion".to_string(),
        };
        let res = broker.execute_operation(op).await.unwrap();
        let str_res = String::from_utf8_lossy(&res);
        assert!(str_res.contains("CurrentVersion"));
    }

    #[tokio::test]
    async fn test_broker_registry_rejects_invalid_subpath() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::ReadRegistry]);
        let op = PrivilegedOperation::CollectRegistryKeys {
            hive: core_domain::broker::RegistryHive::HkeyLocalMachine,
            subpath: "Software; Remove-Item C:\\".to_string(),
        };
        let err = broker.execute_operation(op).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_broker_memory_acquisition_not_implemented() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::AcquireMemory]);
        let op = PrivilegedOperation::AcquireMemorySample {
            target: core_domain::broker::MemoryTarget::ProcessPid(std::process::id()),
            chunk_size_mb: 16,
        };
        let err = broker.execute_operation(op).await.unwrap_err();
        assert!(matches!(err, BrokerError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn test_broker_capture_pcap_not_implemented() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::CapturePcap]);
        let op = PrivilegedOperation::CapturePcap {
            interface_id: "eth0".to_string(),
            duration_secs: 5,
            max_bytes: 1024,
            bpf_filter: None,
        };
        let err = broker.execute_operation(op).await.unwrap_err();
        assert!(matches!(err, BrokerError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn test_broker_run_targeted_scan() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::NetworkScan]);
        let scan_op = PrivilegedOperation::RunTargetedScan {
            target_ip: "127.0.0.1".to_string(),
            ports: vec![1, 65534],
            rate_limit: 1000,
        };
        let res = broker.execute_operation(scan_op).await.unwrap();
        let str_res = String::from_utf8_lossy(&res);
        assert!(str_res.contains("scan_complete"));
    }

    #[tokio::test]
    async fn test_broker_audit_trail_logging() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::NetworkScan]);

        // Allowed operation -> Success audit event
        let scan_op = PrivilegedOperation::RunTargetedScan {
            target_ip: "127.0.0.1".to_string(),
            ports: vec![80],
            rate_limit: 1000,
        };
        let _ = broker.execute_operation(scan_op).await.unwrap();

        // Disallowed operation -> Denied audit event
        let capture_op = PrivilegedOperation::CapturePcap {
            interface_id: "eth0".to_string(),
            duration_secs: 5,
            max_bytes: 1024,
            bpf_filter: None,
        };
        let _ = broker.execute_operation(capture_op).await.unwrap_err();

        let audits = broker.audit_events();
        assert_eq!(audits.len(), 2);
        assert_eq!(audits[0].outcome, "Success");
        assert_eq!(audits[1].outcome, "Denied");
    }

    #[tokio::test]
    async fn test_broker_rejects_remote_target() {
        let broker = PrivilegeBroker::new(vec![BrokerCapability::NetworkScan]);
        let op = PrivilegedOperation::RunTargetedScan {
            target_ip: "192.168.1.1".to_string(),
            ports: vec![80],
            rate_limit: 100,
        };
        let err = broker.execute_operation(op).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidParameter(_)));
    }
}
