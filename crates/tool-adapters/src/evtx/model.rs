#![forbid(unsafe_code)]

use super::issues::{ParseIssue, ParseQuality};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical forensic record extracted from Windows EVTX.
/// Missing fields are represented strictly as `None` -- never fabricated defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxRecord {
    pub record_id: u64,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub event_id: u32,
    pub version: Option<u8>,
    pub level: Option<u8>,
    pub computer: Option<String>,
    pub user_sid: Option<String>,

    pub source_timestamp: Option<DateTime<Utc>>,
    pub ingest_timestamp: DateTime<Utc>,

    pub event_data: serde_json::Value,
    pub user_data: serde_json::Value,
    pub system_data: serde_json::Value,

    pub chunk_index: u64,
    pub record_offset: u64,
    pub record_locator: String,
    pub raw_record_hash: String,
    pub parser_version: String,
}

impl EvtxRecord {
    /// Builds a deterministic canonical record locator
    pub fn format_locator(chunk_index: u64, record_id: u64) -> String {
        format!("evtx://chunk/{chunk_index}/record/{record_id}")
    }
}

/// Comprehensive result of parsing an EVTX artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxParseResult {
    pub records: Vec<EvtxRecord>,
    pub issues: Vec<ParseIssue>,
    pub total_chunks: u64,
    pub damaged_chunks: u64,
    pub total_records: u64,
    pub corrupted_records: u64,
    pub quality: ParseQuality,
}

impl EvtxParseResult {
    pub fn new(
        records: Vec<EvtxRecord>,
        issues: Vec<ParseIssue>,
        total_chunks: u64,
        damaged_chunks: u64,
        corrupted_records: u64,
    ) -> Self {
        let total_records = records.len() as u64 + corrupted_records;
        let quality = if records.is_empty() && (damaged_chunks > 0 || corrupted_records > 0) {
            ParseQuality::Failed
        } else if damaged_chunks > 0 {
            ParseQuality::Partial
        } else if corrupted_records > 0 {
            ParseQuality::Degraded
        } else {
            ParseQuality::Complete
        };

        Self {
            records,
            issues,
            total_chunks,
            damaged_chunks,
            total_records,
            corrupted_records,
            quality,
        }
    }
}

/// Backwards compatibility record format for tests/consumers expecting ParsedEvtxRecord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEvtxRecord {
    pub record_id: u64,
    pub event_id: u32,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub computer: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub data: serde_json::Value,
}

impl From<&EvtxRecord> for ParsedEvtxRecord {
    fn from(r: &EvtxRecord) -> Self {
        Self {
            record_id: r.record_id,
            event_id: r.event_id,
            provider: r.provider.clone(),
            channel: r.channel.clone(),
            computer: r.computer.clone(),
            timestamp: r.source_timestamp,
            data: if r.event_data.is_null() {
                r.system_data.clone()
            } else {
                r.event_data.clone()
            },
        }
    }
}
