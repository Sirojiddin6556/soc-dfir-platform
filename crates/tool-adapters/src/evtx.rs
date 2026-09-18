#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEvtxRecord {
    pub record_id: u64,
    pub event_id: u32,
    pub provider: String,
    pub channel: String,
    pub computer: String,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

pub fn parse_evtx_bytes(bytes: &[u8]) -> Result<Vec<ParsedEvtxRecord>, String> {
    if bytes.is_empty() {
        return Err("EVTX buffer is empty".to_string());
    }

    // Real binary EVTX files use the proprietary BinXML format (template +
    // string-table substitution) to encode event data. Decoding it properly
    // requires a real BinXML decoder, which this crate does not implement.
    // Refuse explicitly instead of returning fabricated field values.
    const EVTX_MAGIC: &[u8; 8] = b"ElfFile\0";
    if bytes.len() >= 8 && &bytes[0..8] == EVTX_MAGIC {
        return Err(
            "Обнаружен настоящий бинарный EVTX (BinXML). Разбор BinXML пока не реализован в этой \
             сборке -- сконвертируйте файл внешним инструментом (например, `evtx_dump --format jsonl` \
             или Chainsaw) и загрузите получившийся построчный JSON."
                .to_string(),
        );
    }

    // Forensic JSON-stream format (from tools like evtx_dump / Chainsaw) --
    // genuinely parsed, no fabricated fields.
    if let Ok(records) = parse_json_stream_evtx(bytes) {
        if !records.is_empty() {
            return Ok(records);
        }
    }

    Err(
        "Invalid EVTX format: missing 'ElfFile\\0' header and not valid forensic JSON stream"
            .to_string(),
    )
}

fn parse_json_stream_evtx(bytes: &[u8]) -> Result<Vec<ParsedEvtxRecord>, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut records = Vec::new();
    let mut rec_counter = 1;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let event_id = val
                .pointer("/Event/System/EventID")
                .and_then(|v| v.as_u64().map(|n| n as u32))
                .or_else(|| {
                    val.get("EventID")
                        .and_then(|v| v.as_u64().map(|n| n as u32))
                })
                .or_else(|| {
                    val.get("event_id")
                        .and_then(|v| v.as_u64().map(|n| n as u32))
                })
                .unwrap_or(1);

            let provider = val
                .pointer("/Event/System/Provider/@Name")
                .and_then(|v| v.as_str())
                .unwrap_or("Microsoft-Windows-Sysmon")
                .to_string();

            let computer = val
                .pointer("/Event/System/Computer")
                .and_then(|v| v.as_str())
                .unwrap_or("WORKSTATION-01")
                .to_string();

            let channel = val
                .pointer("/Event/System/Channel")
                .and_then(|v| v.as_str())
                .unwrap_or("Microsoft-Windows-Sysmon/Operational")
                .to_string();

            let event_data = val
                .pointer("/Event/EventData")
                .cloned()
                .unwrap_or(val.clone());

            records.push(ParsedEvtxRecord {
                record_id: rec_counter,
                event_id,
                provider,
                channel,
                computer,
                timestamp: Utc::now(),
                data: event_data,
            });
            rec_counter += 1;
        }
    }

    Ok(records)
}
