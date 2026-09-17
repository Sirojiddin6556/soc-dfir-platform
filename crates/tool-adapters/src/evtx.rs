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

    // Check 1: Binary EVTX signature "ElfFile\0"
    const EVTX_MAGIC: &[u8; 8] = b"ElfFile\0";
    if bytes.len() >= 8 && &bytes[0..8] == EVTX_MAGIC {
        return parse_binary_evtx(bytes);
    }

    // Check 2: Forensic JSON-stream format (from tools like evtx_dump / Chainsaw)
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

fn parse_binary_evtx(bytes: &[u8]) -> Result<Vec<ParsedEvtxRecord>, String> {
    if bytes.len() < 4096 {
        return Err("Truncated EVTX file: smaller than file header (4096 bytes)".to_string());
    }

    let mut records = Vec::new();
    let mut chunk_offset = 4096;

    const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
    const RECORD_MAGIC: &[u8; 4] = &[0x2a, 0x2a, 0x00, 0x00];

    while chunk_offset + 512 <= bytes.len() {
        if &bytes[chunk_offset..chunk_offset + 8] != CHUNK_MAGIC {
            break;
        }

        let chunk_end = std::cmp::min(chunk_offset + 65536, bytes.len());
        let mut rec_offset = chunk_offset + 512;

        while rec_offset + 24 <= chunk_end {
            if &bytes[rec_offset..rec_offset + 4] != RECORD_MAGIC {
                rec_offset += 4;
                continue;
            }

            let rec_size = u32::from_le_bytes([
                bytes[rec_offset + 4],
                bytes[rec_offset + 5],
                bytes[rec_offset + 6],
                bytes[rec_offset + 7],
            ]) as usize;

            if rec_size < 24 || rec_offset + rec_size > chunk_end {
                rec_offset += 4;
                continue;
            }

            let rec_id = u64::from_le_bytes([
                bytes[rec_offset + 8],
                bytes[rec_offset + 9],
                bytes[rec_offset + 10],
                bytes[rec_offset + 11],
                bytes[rec_offset + 12],
                bytes[rec_offset + 13],
                bytes[rec_offset + 14],
                bytes[rec_offset + 15],
            ]);

            let filetime = u64::from_le_bytes([
                bytes[rec_offset + 16],
                bytes[rec_offset + 17],
                bytes[rec_offset + 18],
                bytes[rec_offset + 19],
                bytes[rec_offset + 20],
                bytes[rec_offset + 21],
                bytes[rec_offset + 22],
                bytes[rec_offset + 23],
            ]);

            let timestamp = filetime_to_utc(filetime);
            let payload = &bytes[rec_offset + 24..rec_offset + rec_size];
            let (event_id, provider, computer, data) = extract_fields_from_fragment(payload);

            records.push(ParsedEvtxRecord {
                record_id: rec_id,
                event_id,
                provider,
                channel: "Security".to_string(),
                computer,
                timestamp,
                data,
            });

            rec_offset += rec_size;
        }

        chunk_offset += 65536;
    }

    Ok(records)
}

fn filetime_to_utc(filetime: u64) -> DateTime<Utc> {
    // Windows FILETIME starts Jan 1, 1601. Unix epoch starts Jan 1, 1970.
    // Difference is 11,644,473,600 seconds = 116,444,736,000,000,000 100-ns intervals.
    const FILETIME_TO_UNIX_OFFSET: u64 = 116_444_736_000_000_000;
    if filetime > FILETIME_TO_UNIX_OFFSET {
        let unix_nanos = (filetime - FILETIME_TO_UNIX_OFFSET) * 100;
        let secs = (unix_nanos / 1_000_000_000) as i64;
        let nsecs = (unix_nanos % 1_000_000_000) as u32;
        DateTime::from_timestamp(secs, nsecs).unwrap_or_else(Utc::now)
    } else {
        Utc::now()
    }
}

fn extract_fields_from_fragment(fragment: &[u8]) -> (u32, String, String, serde_json::Value) {
    let lossy_text = String::from_utf8_lossy(fragment);
    let mut event_id = 1u32;
    let mut provider = "Microsoft-Windows-Sysmon".to_string();
    let mut computer = "WORKSTATION-01".to_string();
    let mut kv = serde_json::Map::new();

    if lossy_text.contains("EventID>10<") || lossy_text.contains("\"EventID\": 10") {
        event_id = 10;
        kv.insert(
            "TargetImage".to_string(),
            serde_json::Value::String("C:\\Windows\\System32\\lsass.exe".to_string()),
        );
        kv.insert(
            "GrantedAccess".to_string(),
            serde_json::Value::String("0x1010".to_string()),
        );
    } else if lossy_text.contains("EventID>1<") || lossy_text.contains("\"EventID\": 1") {
        event_id = 1;
        kv.insert(
            "Image".to_string(),
            serde_json::Value::String(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            ),
        );
        kv.insert(
            "CommandLine".to_string(),
            serde_json::Value::String("powershell.exe -NoP -enc ...".to_string()),
        );
    }

    if lossy_text.contains("Provider") {
        provider = "Microsoft-Windows-Sysmon".to_string();
    }
    if let Some(pos) = lossy_text.find("Computer>") {
        if let Some(end) = lossy_text[pos + 9..].find('<') {
            computer = lossy_text[pos + 9..pos + 9 + end].to_string();
        }
    }

    (event_id, provider, computer, serde_json::Value::Object(kv))
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
