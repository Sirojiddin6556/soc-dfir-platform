#![forbid(unsafe_code)]

use super::issues::ParseIssue;
use super::model::{EvtxParseResult, EvtxParseSummary, EvtxRecord};
use chrono::{DateTime, Utc};
use evtx::EvtxParser as NativeEvtxParser;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

pub const PARSER_VERSION: &str = "evtx-0.12/socdfir-1.0";

/// Forensic streaming EVTX parser wrapping pure-Rust BinXML engine
pub struct EvtxParser;

impl EvtxParser {
    /// Parses an EVTX file with a streaming sink callback invoked per record.
    /// Does NOT accumulate records into RAM, ensuring O(chunk_size) memory usage.
    pub fn parse_file_with_sink<F>(path: &Path, sink: F) -> Result<EvtxParseSummary, String>
    where
        F: FnMut(EvtxRecord) -> Result<(), String>,
    {
        let file_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if file_len < 4096 || !(file_len - 4096).is_multiple_of(65536) {
            return Err(format!("EVTX file is truncated: {file_len} bytes is not a 4096-byte header plus 64 KiB chunks"));
        }
        let parser = NativeEvtxParser::from_path(path)
            .map_err(|e| format!("Failed to open EVTX file: {e}"))?;
        Self::parse_reader_with_sink(parser, file_len, sink)
    }

    /// Parses an EVTX file in fixed batches, reducing call overhead while maintaining bounded memory.
    pub fn parse_file_in_batches<F>(
        path: &Path,
        batch_size: usize,
        mut handler: F,
    ) -> Result<EvtxParseSummary, String>
    where
        F: FnMut(Vec<EvtxRecord>) -> Result<(), String>,
    {
        let batch_size = batch_size.max(1);
        let mut batch = Vec::with_capacity(batch_size);
        let summary = Self::parse_file_with_sink(path, |rec| {
            batch.push(rec);
            if batch.len() >= batch_size {
                let to_send = std::mem::replace(&mut batch, Vec::with_capacity(batch_size));
                handler(to_send)?;
            }
            Ok(())
        })?;

        if !batch.is_empty() {
            handler(batch)?;
        }

        Ok(summary)
    }

    /// Parses an EVTX file directly from a file path into an in-memory EvtxParseResult.
    pub fn parse_file(path: &Path) -> Result<EvtxParseResult, String> {
        let mut records = Vec::new();
        let summary = Self::parse_file_with_sink(path, |rec| {
            records.push(rec);
            Ok(())
        })?;

        Ok(EvtxParseResult {
            records,
            issues: summary.issues,
            total_chunks: summary.total_chunks,
            damaged_chunks: summary.damaged_chunks,
            total_records: summary.records_parsed + summary.corrupt_records,
            corrupted_records: summary.corrupt_records,
            quality: summary.quality,
        })
    }

    /// Parses an EVTX payload from in-memory bytes using a Seekable Cursor
    pub fn parse_bytes(bytes: &[u8]) -> Result<EvtxParseResult, String> {
        if bytes.is_empty() {
            return Err("EVTX buffer is empty".to_string());
        }
        let file_len = bytes.len() as u64;
        let cursor = Cursor::new(bytes.to_vec());
        let parser = NativeEvtxParser::from_read_seek(cursor)
            .map_err(|e| format!("Failed to init EVTX parser from bytes: {e}"))?;

        let mut records = Vec::new();
        let summary = Self::parse_reader_with_sink(parser, file_len, |rec| {
            records.push(rec);
            Ok(())
        })?;

        Ok(EvtxParseResult {
            records,
            issues: summary.issues,
            total_chunks: summary.total_chunks,
            damaged_chunks: summary.damaged_chunks,
            total_records: summary.records_parsed + summary.corrupt_records,
            corrupted_records: summary.corrupt_records,
            quality: summary.quality,
        })
    }

    fn parse_reader_with_sink<R: Read + Seek + Send + 'static, F>(
        mut parser: NativeEvtxParser<R>,
        file_len: u64,
        mut sink: F,
    ) -> Result<EvtxParseSummary, String>
    where
        F: FnMut(EvtxRecord) -> Result<(), String>,
    {
        let mut issues = Vec::new();
        let mut corrupted_records = 0u64;
        let mut damaged_chunks = 0u64;
        let mut records_parsed = 0u64;

        let ingest_timestamp = Utc::now();

        for record_res in parser.records_json() {
            match record_res {
                Ok(raw_record) => {
                    match parse_json_record(
                        &raw_record.data,
                        raw_record.event_record_id,
                        ingest_timestamp,
                    ) {
                        Ok(rec) => {
                            records_parsed += 1;
                            if let Err(e) = sink(rec) {
                                return Err(format!("EVTX sink error: {e}"));
                            }
                        }
                        Err(err) => {
                            corrupted_records += 1;
                            issues.push(ParseIssue::new(
                                None,
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
                    if err_msg.to_lowercase().contains("chunk") {
                        damaged_chunks += 1;
                    } else {
                        corrupted_records += 1;
                    }
                    issues.push(ParseIssue::new(
                        None,
                        None,
                        "EVTX_DECODE_ERROR",
                        err_msg,
                        true,
                    ));
                }
            }
        }

        let total_chunks = if file_len > 4096 {
            (file_len - 4096).div_ceil(65536).max(1)
        } else if records_parsed > 0 || damaged_chunks > 0 {
            1
        } else {
            0
        };

        Ok(EvtxParseSummary::new(
            records_parsed,
            corrupted_records,
            total_chunks,
            damaged_chunks,
            issues,
        ))
    }
}

fn parse_json_record(
    json_str: &str,
    record_id: u64,
    ingest_timestamp: DateTime<Utc>,
) -> Result<EvtxRecord, String> {
    let decoded_record_hash = blake3::hash(json_str.as_bytes()).to_hex().to_string();
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

    let record_locator = EvtxRecord::format_locator(None, record_id);

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
        chunk_index: None,
        physical_offset: None,
        record_locator,
        decoded_record_hash,
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
        let loc1 = EvtxRecord::format_locator(Some(5), 12345);
        let loc2 = EvtxRecord::format_locator(Some(5), 12345);
        assert_eq!(loc1, "evtx://chunk/5/record/12345");
        assert_eq!(loc1, loc2);
    }
}
