#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseQuality {
    Complete,
    Degraded,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseIssue {
    pub chunk_index: Option<u64>,
    pub byte_offset: Option<u64>,
    pub record_id: Option<u64>,
    pub error_code: String,
    pub message: String,
    pub recoverable: bool,
}

impl ParseIssue {
    pub fn new(
        chunk_index: Option<u64>,
        record_id: Option<u64>,
        error_code: impl Into<String>,
        message: impl Into<String>,
        recoverable: bool,
    ) -> Self {
        Self {
            chunk_index,
            byte_offset: None,
            record_id,
            error_code: error_code.into(),
            message: message.into(),
            recoverable,
        }
    }
}
