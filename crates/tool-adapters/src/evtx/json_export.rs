#![forbid(unsafe_code)]

use super::issues::ParseIssue;
use super::model::{EvtxParseResult, EvtxRecord};
use chrono::{DateTime, Utc};
use std::path::Path;

pub const JSON_EXPORT_PARSER_VERSION: &str = "evtx-json-export/socdfir-1.0";

/// Adapter for offline exported JSON-lines format (from external tools like evtx_dump or Chainsaw).
/// Strictly kept isolated from binary EVTX format to prevent accidental misinterpretation.
pub struct EvtxJsonExportAdapter;

impl EvtxJsonExportAdapter {
    pub fn parse_file(path: &Path) -> Result<EvtxParseResult, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read JSON stream file: {e}"))?;
        Self::parse_str(&content)
    }

    pub fn parse_bytes(bytes: &[u8]) -> Result<EvtxParseResult, String> {
        let content =
            std::str::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in JSON stream: {e}"))?;
        Self::parse_str(content)
    }

    pub fn parse_str(content: &str) -> Result<EvtxParseResult, String> {
        let mut records = Vec::new();
        let mut issues = Vec::new();
        let ingest_timestamp = Utc::now();
        let mut record_offset = 0u64;
        let mut corrupted_records = 0u64;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(val) => {
                    let raw_record_hash = blake3::hash(trimmed.as_bytes()).to_hex().to_string();
                    let event_root = val.get("Event").unwrap_or(&val);
                    let system = event_root
                        .get("System")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    let record_id = system
                        .get("EventRecordID")
                        .and_then(|v| v.as_u64())
                        .or_else(|| val.get("record_id").and_then(|v| v.as_u64()))
                        .unwrap_or((idx + 1) as u64);

                    let event_id = system
                        .get("EventID")
                        .and_then(|v| v.as_u64())
                        .or_else(|| val.get("event_id").and_then(|v| v.as_u64()))
                        .unwrap_or(0) as u32;

                    let provider = system
                        .pointer("/Provider/@Name")
                        .or_else(|| system.get("Provider"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let channel = system
                        .get("Channel")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let computer = system
                        .get("Computer")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let user_sid = system
                        .pointer("/Security/@UserID")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let version = system
                        .get("Version")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as u8);
                    let level = system
                        .get("Level")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as u8);

                    let source_timestamp = system
                        .pointer("/TimeCreated/@SystemTime")
                        .or_else(|| system.get("TimeCreated"))
                        .and_then(|v| v.as_str())
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc));

                    let event_data = event_root
                        .get("EventData")
                        .cloned()
                        .unwrap_or_else(|| val.clone());
                    let user_data = event_root
                        .get("UserData")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    let chunk_index = (idx / 100) as u64;
                    let record_locator = EvtxRecord::format_locator(chunk_index, record_id);

                    records.push(EvtxRecord {
                        record_id,
                        provider,
                        channel,
                        event_id,
                        version,
                        level,
                        computer,
                        user_sid,
                        source_timestamp,
                        ingest_timestamp,
                        event_data,
                        user_data,
                        system_data: system,
                        chunk_index,
                        record_offset,
                        record_locator,
                        raw_record_hash,
                        parser_version: JSON_EXPORT_PARSER_VERSION.to_string(),
                    });

                    record_offset += trimmed.len() as u64;
                }
                Err(e) => {
                    corrupted_records += 1;
                    issues.push(ParseIssue::new(
                        Some((idx / 100) as u64),
                        None,
                        "JSON_LINE_PARSE_ERROR",
                        e.to_string(),
                        true,
                    ));
                }
            }
        }

        let total_chunks = ((records.len() + corrupted_records as usize) / 100).max(1) as u64;

        Ok(EvtxParseResult::new(
            records,
            issues,
            total_chunks,
            0,
            corrupted_records,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_stream_parsing_and_corrupt_line_handling() {
        let stream = r#"
{"Event": {"System": {"EventID": 4624, "Computer": "DC01", "Channel": "Security"}}}
{"THIS IS NOT VALID JSON
{"Event": {"System": {"EventID": 4688, "Computer": "DC02", "Channel": "Security"}}}
"#;

        let result = EvtxJsonExportAdapter::parse_str(stream).unwrap();
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.corrupted_records, 1);
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].error_code, "JSON_LINE_PARSE_ERROR");
        assert_eq!(result.records[0].event_id, 4624);
        assert_eq!(result.records[1].event_id, 4688);
        assert_eq!(result.quality, super::super::issues::ParseQuality::Degraded);
    }

    #[test]
    fn test_missing_fields_are_none_not_fabricated() {
        let stream = r#"{"Event": {"System": {"EventID": 1}}}"#;
        let result = EvtxJsonExportAdapter::parse_str(stream).unwrap();
        assert_eq!(result.records.len(), 1);
        let rec = &result.records[0];
        assert_eq!(rec.event_id, 1);
        assert!(rec.computer.is_none());
        assert!(rec.provider.is_none());
        assert!(rec.channel.is_none());
        assert!(rec.source_timestamp.is_none());
    }
}
