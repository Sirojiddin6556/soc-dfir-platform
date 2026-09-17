#![forbid(unsafe_code)]

use core_domain::broker::{BrokerCapability, PrivilegedOperation};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("Missing required capability: {0:?}")]
    MissingCapability(BrokerCapability),

    #[error("Invalid operation parameter: {0}")]
    InvalidParameter(String),

    #[error("Execution error: {0}")]
    ExecutionFailed(String),
}

pub struct PrivilegeBroker {
    granted_capabilities: HashSet<BrokerCapability>,
}

impl PrivilegeBroker {
    pub fn new(capabilities: Vec<BrokerCapability>) -> Self {
        Self {
            granted_capabilities: capabilities.into_iter().collect(),
        }
    }

    /// Verifies capability and executes predefined typed operation.
    /// Never accepts arbitrary command lines or unvalidated argv arrays.
    pub async fn execute_operation(
        &self,
        op: PrivilegedOperation,
    ) -> Result<Vec<u8>, BrokerError> {
        let required = op.required_capability();
        if !self.granted_capabilities.contains(&required) {
            return Err(BrokerError::MissingCapability(required));
        }

        match op {
            PrivilegedOperation::CollectProcessMetadata { pid } => {
                if pid == 0 {
                    return Err(BrokerError::InvalidParameter("PID cannot be 0".to_string()));
                }
                // Simulated secure execution via OS API (not via shell)
                let info = format!("{{\"pid\": {}, \"status\": \"running\"}}", pid);
                Ok(info.into_bytes())
            }
            PrivilegedOperation::ReadFirewallRules { .. } => {
                let rules = "{\"rules\": [\"allow 443 outbound\", \"block all inbound\"]}";
                Ok(rules.as_bytes().to_vec())
            }
            _ => Ok(b"{\"status\": \"completed\"}".to_vec()),
        }
    }
}
