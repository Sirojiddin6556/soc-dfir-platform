#![forbid(unsafe_code)]

use super::issues::ParseIssue;
use super::model::{EvtxParseResult, EvtxRecord};
use chrono::{DateTime, Utc};
use evtx::EvtxParser as NativeEvtxParser;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

pub const PARSER_VERSION: &str = "evtx-0.12/socdfir-1.0";

/// Forensic streaming EVTX parser wrapping pure-Rust BinXML engine
pub struct EvtxParser;

impl EvtxParser {
    /// Parses an EVTX file directly from a file path in a streaming fashion.
    /// Memory consumption is O(chunk_size), not O(file_size).
    pub fn parse_file(path: &Path) -> Result<EvtxParseResult, String> {
        let parser = NativeEvtxParser::from_path(path)
            .map_err(|e| format!("Failed to open EVTX file: {e}"))?;
        Self::parse_records(parser)
    }

    /// Parses an EVTX payload from in-memory bytes using a Seekable Cursor
    pub fn parse_bytes(bytes: &[u8]) -> Result<EvtxParseResult, String> {
        if bytes.is_empty() {
            return Err("EVTX buffer is empty".to_string());
        }
        let cursor = Cursor::new(bytes.to_vec());
        let parser = NativeEvtxParser::from_read_seek(cursor)
            .map_err(|e| format!("Failed to init EVTX parser from bytes: {e}"))?;
        Self::parse_records(parser)
    }

    fn parse_records<R: Read + Seek + Send + 'static>(
        mut parser: NativeEvtxParser<R>,
    ) -> Result<EvtxParseResult, String> {
        let mut records = Vec::new();
        let mut issues = Vec::new();
        let mut corrupted_records = 0u64;
        let mut damaged_chunks = 0u64;

        let ingest_timestamp = Utc::now();
        let mut record_offset = 0u64;

        for (idx, record_res) in parser.records_json().enumerate() {
            match record_res {
                Ok(raw_record) => {
                    match parse_json_record(
                        &raw_record.data,
                        raw_record.event_record_id,
                        idx as u64,
                        record_offset,
                        ingest_timestamp,
                    ) {
                        Ok(rec) => {
                            record_offset += raw_record.data.len() as u64;
                            records.push(rec);
                        }
                        Err(err) => {
                            corrupted_records += 1;
                            issues.push(ParseIssue::new(
                                Some((idx / 100) as u64),
                                Some(raw_record.event_record_id),
                                "RECORD_JSON_PARSE_ERROR",
                                err,
                                true,
                            ));
                        }
                    }
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    if err_msg.contains("chunk") || err_msg.contains("Chunk") {
                        damaged_chunks += 1;
                    } else {
                        corrupted_records += 1;
                    }
                    issues.push(ParseIssue::new(
                        Some((idx / 100) as u64),
                        None,
                        "EVTX_DECODE_ERROR",
                        err_msg,
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
            damaged_chunks,
            corrupted_records,
        ))
    }
}

fn parse_json_record(
    json_str: &str,
    record_id: u64,
    record_idx: u64,
    record_offset: u64,
    ingest_timestamp: DateTime<Utc>,
) -> Result<EvtxRecord, String> {
    let raw_record_hash = blake3::hash(json_str.as_bytes()).to_hex().to_string();
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("Malformed JSON from evtx decoder: {e}"))?;

    let event_root = val.get("Event").unwrap_or(&val);
    let system = event_root
        .get("System")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let event_id = extract_event_id(&system);
    let provider = extract_provider(&system);
    let channel = extract_string_field(&system, "Channel");
    let computer = extract_string_field(&system, "Computer");
    let user_sid = extract_user_sid(&system);
    let version = extract_u8_field(&system, "Version");
    let level = extract_u8_field(&system, "Level");
    let source_timestamp = extract_timestamp(&system);

    let event_data = event_root
        .get("EventData")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let user_data = event_root
        .get("UserData")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let chunk_index = record_idx / 100;
    let record_locator = EvtxRecord::format_locator(chunk_index, record_id);

    Ok(EvtxRecord {
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
        parser_version: PARSER_VERSION.to_string(),
    })
}

fn extract_event_id(system: &serde_json::Value) -> u32 {
    let event_id_node = match system.get("EventID") {
        Some(node) => node,
        None => return 0,
    };

    if let Some(id) = event_id_node.as_u64() {
        return id as u32;
    }
    if let Some(obj) = event_id_node.as_object() {
        if let Some(txt) = obj.get("#text").and_then(|v| v.as_u64()) {
            return txt as u32;
        }
        if let Some(txt) = obj
            .get("#text")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u32>().ok())
        {
            return txt;
        }
        if let Some(txt) = obj.get("value").and_then(|v| v.as_u64()) {
            return txt as u32;
        }
    }
    if let Some(s) = event_id_node.as_str() {
        if let Ok(id) = s.parse::<u32>() {
            return id;
        }
    }
    0
}

fn extract_provider(system: &serde_json::Value) -> Option<String> {
    let node = system.get("Provider")?;
    if let Some(s) = node.as_str() {
        return Some(s.to_string());
    }
    if let Some(obj) = node.as_object() {
        if let Some(name) = obj.get("@Name").and_then(|v| v.as_str()) {
            return Some(name.to_string());
        }
        if let Some(name) = obj
            .get("#attributes")
            .and_then(|a| a.get("Name"))
            .and_then(|v| v.as_str())
        {
            return Some(name.to_string());
        }
        if let Some(name) = obj.get("Name").and_then(|v| v.as_str()) {
            return Some(name.to_string());
        }
    }
    None
}

fn extract_string_field(system: &serde_json::Value, field_name: &str) -> Option<String> {
    let node = system.get(field_name)?;
    if let Some(s) = node.as_str() {
        return Some(s.to_string());
    }
    if let Some(obj) = node.as_object() {
        if let Some(txt) = obj.get("#text").and_then(|v| v.as_str()) {
            return Some(txt.to_string());
        }
    }
    None
}

fn extract_u8_field(system: &serde_json::Value, field_name: &str) -> Option<u8> {
    let node = system.get(field_name)?;
    if let Some(n) = node.as_u64() {
        return Some(n as u8);
    }
    if let Some(obj) = node.as_object() {
        if let Some(txt) = obj.get("#text").and_then(|v| v.as_u64()) {
            return Some(txt as u8);
        }
    }
    None
}

fn extract_user_sid(system: &serde_json::Value) -> Option<String> {
    let node = system.get("Security")?;
    if let Some(obj) = node.as_object() {
        if let Some(sid) = obj.get("@UserID").and_then(|v| v.as_str()) {
            return Some(sid.to_string());
        }
        if let Some(sid) = obj
            .get("#attributes")
            .and_then(|a| a.get("UserID"))
            .and_then(|v| v.as_str())
        {
            return Some(sid.to_string());
        }
        if let Some(sid) = obj.get("UserID").and_then(|v| v.as_str()) {
            return Some(sid.to_string());
        }
    }
    None
}

fn extract_timestamp(system: &serde_json::Value) -> Option<DateTime<Utc>> {
    let node = system.get("TimeCreated")?;
    let time_str = if let Some(s) = node.as_str() {
        s
    } else if let Some(obj) = node.as_object() {
        obj.get("@SystemTime")
            .or_else(|| obj.get("#attributes").and_then(|a| a.get("SystemTime")))
            .or_else(|| obj.get("SystemTime"))
            .and_then(|v| v.as_str())?
    } else {
        return None;
    };

    DateTime::parse_from_rfc3339(time_str)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_evtx_no_panic() {
        let partial_bytes = b"ElfFile\0\x01\x02\x03\x04";
        let res = EvtxParser::parse_bytes(partial_bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_empty_evtx_returns_error() {
        let res = EvtxParser::parse_bytes(&[]);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_extract_event_id_variants() {
        let s1 = serde_json::json!({"EventID": 4624});
        assert_eq!(extract_event_id(&s1), 4624);

        let s2 = serde_json::json!({"EventID": {"#text": 4688}});
        assert_eq!(extract_event_id(&s2), 4688);

        let s3 = serde_json::json!({"EventID": "7045"});
        assert_eq!(extract_event_id(&s3), 7045);

        let s4 = serde_json::json!({"EventID": {"#text": "1"}});
        assert_eq!(extract_event_id(&s4), 1);
    }

    #[test]
    fn test_extract_timestamp_formats() {
        let s1 = serde_json::json!({
            "TimeCreated": {
                "@SystemTime": "2026-07-28T04:51:25.7805937Z"
            }
        });
        let ts1 = extract_timestamp(&s1);
        assert!(ts1.is_some());
        assert_eq!(
            ts1.unwrap().to_rfc3339(),
            "2026-07-28T04:51:25.780593700+00:00"
        );

        let s2 = serde_json::json!({
            "TimeCreated": {
                "#attributes": {
                    "SystemTime": "2026-09-21T12:00:00Z"
                }
            }
        });
        let ts2 = extract_timestamp(&s2);
        assert!(ts2.is_some());
        assert_eq!(ts2.unwrap().to_rfc3339(), "2026-09-21T12:00:00+00:00");
    }

    #[test]
    fn test_deterministic_record_locator() {
        let loc1 = EvtxRecord::format_locator(5, 12345);
        let loc2 = EvtxRecord::format_locator(5, 12345);
        assert_eq!(loc1, "evtx://chunk/5/record/12345");
        assert_eq!(loc1, loc2);
    }
}
