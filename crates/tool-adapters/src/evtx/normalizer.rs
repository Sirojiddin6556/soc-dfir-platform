#![forbid(unsafe_code)]

use super::model::EvtxRecord;
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Forensic normalizer mapping EVTX records to typed Observation entities
pub struct EvtxNormalizer;

impl EvtxNormalizer {
    pub fn normalize_record(
        case_id: EntityId,
        artifact_id: Option<EntityId>,
        tool_run_id: Option<EntityId>,
        record: &EvtxRecord,
    ) -> Observation {
        let (raw_event_type, specific_data) = match (
            record.provider.as_deref().unwrap_or(""),
            record.channel.as_deref().unwrap_or(""),
            record.event_id,
        ) {
            // Windows Security
            (_, "Security", 4624) => ("logon_success", normalize_4624(record)),
            (_, "Security", 4688) => ("process_create", normalize_4688(record)),
            (_, "Security", 4697) => ("service_installed", normalize_service_install(record)),
            (_, "Security", 4720) => ("user_account_created", normalize_4720(record)),
            // Windows System / SCM
            (_, "System", 7045) | ("Service Control Manager", _, 7045) => {
                ("service_installed", normalize_service_install(record))
            }
            // Sysmon
            (p, _, 1) if is_sysmon(p, record.channel.as_deref()) => {
                ("process_create", normalize_sysmon_1(record))
            }
            (p, _, 3) if is_sysmon(p, record.channel.as_deref()) => {
                ("network_connection", normalize_sysmon_3(record))
            }
            (p, _, 7) if is_sysmon(p, record.channel.as_deref()) => {
                ("image_load", normalize_sysmon_7(record))
            }
            (p, _, 10) if is_sysmon(p, record.channel.as_deref()) => {
                ("process_access", normalize_sysmon_10(record))
            }
            (p, _, 11) if is_sysmon(p, record.channel.as_deref()) => {
                ("file_create", normalize_sysmon_11(record))
            }
            (p, _, 22) if is_sysmon(p, record.channel.as_deref()) => {
                ("dns_query", normalize_sysmon_22(record))
            }
            _ => ("windows_event", json!({})),
        };

        let flattened_event_data = extract_flattened_data(&record.event_data);
        let mut observation_data = json!({
            "record_locator": record.record_locator,
            "record_id": record.record_id,
            "chunk_index": record.chunk_index,
            "record_offset": record.record_offset,
            "raw_record_hash": record.raw_record_hash,
            "parser_name": "EvtxParser",
            "parser_version": record.parser_version,
            "event_id": record.event_id,
            "provider": record.provider,
            "channel": record.channel,
            "computer": record.computer,
            "user_sid": record.user_sid,
            "version": record.version,
            "level": record.level,
            "event_data": flattened_event_data,
            "user_data": record.user_data,
            "details": specific_data,
        });

        // Inject specific data fields directly to top of observation_data for easy query
        if let Some(obj) = observation_data.as_object_mut() {
            if let Some(spec_obj) = specific_data.as_object() {
                for (k, v) in spec_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }

        Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id,
            tool_run_id,
            source_tool: "evtx_normalizer".to_string(),
            raw_event_type: raw_event_type.to_string(),
            source_timestamp: record.source_timestamp.unwrap_or(record.ingest_timestamp),
            ingest_timestamp: record.ingest_timestamp,
            data: observation_data,
        }
    }
}

fn is_sysmon(provider: &str, channel: Option<&str>) -> bool {
    provider.contains("Sysmon") || channel.unwrap_or("").contains("Sysmon")
}

pub fn extract_data_field(event_data: &Value, key: &str) -> Option<String> {
    if let Some(s) = event_data.get(key).and_then(|v| v.as_str()) {
        return Some(s.to_string());
    }
    // Handle XML array of Data elements: {"Data": [{"#attributes": {"Name": "Image"}, "#text": "..."}]}
    if let Some(arr) = event_data.get("Data").and_then(|v| v.as_array()) {
        for item in arr {
            let name = item
                .pointer("/#attributes/Name")
                .or_else(|| item.pointer("/@Name"))
                .or_else(|| item.get("Name"))
                .and_then(|v| v.as_str());
            if name == Some(key) {
                if let Some(text) = item.get("#text").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                if let Some(val) = item.as_str() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn extract_flattened_data(event_data: &Value) -> Value {
    if let Some(obj) = event_data.as_object() {
        let mut map = serde_json::Map::new();
        for (k, v) in obj {
            if k == "Data" {
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        let name = item
                            .pointer("/#attributes/Name")
                            .or_else(|| item.pointer("/@Name"))
                            .or_else(|| item.get("Name"))
                            .and_then(|v| v.as_str());
                        let val = item
                            .get("#text")
                            .or_else(|| item.get("value"))
                            .unwrap_or(item);
                        if let Some(n) = name {
                            map.insert(n.to_string(), val.clone());
                        }
                    }
                }
            } else {
                map.insert(k.clone(), v.clone());
            }
        }
        return Value::Object(map);
    }
    event_data.clone()
}

pub fn parse_sysmon_hashes(raw_hashes: &str) -> (String, HashMap<String, String>) {
    let mut map = HashMap::new();
    for part in raw_hashes.split(',') {
        let trimmed = part.trim();
        if let Some((algo, hash)) = trimmed.split_once('=') {
            map.insert(algo.trim().to_uppercase(), hash.trim().to_string());
        }
    }
    (raw_hashes.to_string(), map)
}

fn normalize_4624(record: &EvtxRecord) -> Value {
    json!({
        "target_user_name": extract_data_field(&record.event_data, "TargetUserName"),
        "target_domain_name": extract_data_field(&record.event_data, "TargetDomainName"),
        "logon_type": extract_data_field(&record.event_data, "LogonType").and_then(|s| s.parse::<u32>().ok()),
        "ip_address": extract_data_field(&record.event_data, "IpAddress"),
        "ip_port": extract_data_field(&record.event_data, "IpPort"),
        "workstation_name": extract_data_field(&record.event_data, "WorkstationName"),
        "logon_process_name": extract_data_field(&record.event_data, "LogonProcessName"),
    })
}

fn normalize_4688(record: &EvtxRecord) -> Value {
    json!({
        "new_process_name": extract_data_field(&record.event_data, "NewProcessName"),
        "command_line": extract_data_field(&record.event_data, "CommandLine"),
        "parent_process_name": extract_data_field(&record.event_data, "ParentProcessName"),
        "subject_user_name": extract_data_field(&record.event_data, "SubjectUserName"),
        "subject_domain_name": extract_data_field(&record.event_data, "SubjectDomainName"),
        "token_elevation_type": extract_data_field(&record.event_data, "TokenElevationType"),
    })
}

fn normalize_service_install(record: &EvtxRecord) -> Value {
    let service_file = extract_data_field(&record.event_data, "ImagePath")
        .or_else(|| extract_data_field(&record.event_data, "ServiceFileName"));
    json!({
        "service_name": extract_data_field(&record.event_data, "ServiceName"),
        "service_file_name": service_file,
        "service_type": extract_data_field(&record.event_data, "ServiceType"),
        "start_type": extract_data_field(&record.event_data, "StartType"),
        "service_account": extract_data_field(&record.event_data, "ServiceAccount"),
    })
}

fn normalize_4720(record: &EvtxRecord) -> Value {
    json!({
        "target_user_name": extract_data_field(&record.event_data, "TargetUserName"),
        "subject_user_name": extract_data_field(&record.event_data, "SubjectUserName"),
        "subject_domain_name": extract_data_field(&record.event_data, "SubjectDomainName"),
    })
}

fn normalize_sysmon_1(record: &EvtxRecord) -> Value {
    let raw_h = extract_data_field(&record.event_data, "Hashes").unwrap_or_default();
    let (hashes_raw, hashes) = parse_sysmon_hashes(&raw_h);
    json!({
        "image": extract_data_field(&record.event_data, "Image"),
        "command_line": extract_data_field(&record.event_data, "CommandLine"),
        "parent_image": extract_data_field(&record.event_data, "ParentImage"),
        "parent_command_line": extract_data_field(&record.event_data, "ParentCommandLine"),
        "current_directory": extract_data_field(&record.event_data, "CurrentDirectory"),
        "user": extract_data_field(&record.event_data, "User"),
        "hashes_raw": hashes_raw,
        "hashes": hashes,
    })
}

fn normalize_sysmon_3(record: &EvtxRecord) -> Value {
    json!({
        "image": extract_data_field(&record.event_data, "Image"),
        "protocol": extract_data_field(&record.event_data, "Protocol"),
        "source_ip": extract_data_field(&record.event_data, "SourceIp"),
        "source_port": extract_data_field(&record.event_data, "SourcePort").and_then(|s| s.parse::<u16>().ok()),
        "destination_ip": extract_data_field(&record.event_data, "DestinationIp"),
        "destination_port": extract_data_field(&record.event_data, "DestinationPort").and_then(|s| s.parse::<u16>().ok()),
        "user": extract_data_field(&record.event_data, "User"),
    })
}

fn normalize_sysmon_7(record: &EvtxRecord) -> Value {
    let raw_h = extract_data_field(&record.event_data, "Hashes").unwrap_or_default();
    let (hashes_raw, hashes) = parse_sysmon_hashes(&raw_h);
    json!({
        "image": extract_data_field(&record.event_data, "Image"),
        "image_loaded": extract_data_field(&record.event_data, "ImageLoaded"),
        "signed": extract_data_field(&record.event_data, "Signed").and_then(|s| s.parse::<bool>().ok()),
        "signature_status": extract_data_field(&record.event_data, "SignatureStatus"),
        "hashes_raw": hashes_raw,
        "hashes": hashes,
    })
}

fn normalize_sysmon_10(record: &EvtxRecord) -> Value {
    json!({
        "source_image": extract_data_field(&record.event_data, "SourceImage"),
        "target_image": extract_data_field(&record.event_data, "TargetImage"),
        "granted_access": extract_data_field(&record.event_data, "GrantedAccess"),
        "call_trace": extract_data_field(&record.event_data, "CallTrace"),
    })
}

fn normalize_sysmon_11(record: &EvtxRecord) -> Value {
    json!({
        "image": extract_data_field(&record.event_data, "Image"),
        "target_filename": extract_data_field(&record.event_data, "TargetFilename"),
        "creation_utc_time": extract_data_field(&record.event_data, "CreationUtcTime"),
    })
}

fn normalize_sysmon_22(record: &EvtxRecord) -> Value {
    json!({
        "image": extract_data_field(&record.event_data, "Image"),
        "query_name": extract_data_field(&record.event_data, "QueryName"),
        "query_status": extract_data_field(&record.event_data, "QueryStatus"),
        "query_results": extract_data_field(&record.event_data, "QueryResults"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn make_test_record(
        provider: Option<&str>,
        channel: Option<&str>,
        event_id: u32,
        event_data: Value,
        source_ts: Option<chrono::DateTime<Utc>>,
    ) -> EvtxRecord {
        let ingest_ts = Utc::now();
        EvtxRecord {
            record_id: 1001,
            provider: provider.map(str::to_string),
            channel: channel.map(str::to_string),
            event_id,
            version: Some(1),
            level: Some(4),
            computer: Some("DC01.corp.local".to_string()),
            user_sid: Some("S-1-5-18".to_string()),
            source_timestamp: source_ts,
            ingest_timestamp: ingest_ts,
            event_data,
            user_data: Value::Null,
            system_data: Value::Null,
            chunk_index: 2,
            record_offset: 4096,
            record_locator: EvtxRecord::format_locator(2, 1001),
            raw_record_hash: "abcd1234ef5678".to_string(),
            parser_version: "evtx-0.12/socdfir-1.0".to_string(),
        }
    }

    #[test]
    fn test_normalize_security_4624_and_4688() {
        let case_id = EntityId::new_v7();
        let artifact_id = Some(EntityId::new_v7());
        let past_time = Utc.with_ymd_and_hms(2026, 7, 10, 14, 30, 0).unwrap();

        // 4624 Logon
        let rec_4624 = make_test_record(
            Some("Microsoft-Windows-Security-Auditing"),
            Some("Security"),
            4624,
            json!({
                "TargetUserName": "Administrator",
                "TargetDomainName": "CORP",
                "LogonType": "10",
                "IpAddress": "192.168.1.50"
            }),
            Some(past_time),
        );
        let obs_4624 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_4624);
        assert_eq!(obs_4624.raw_event_type, "logon_success");
        assert_eq!(obs_4624.source_timestamp, past_time);
        assert_ne!(obs_4624.source_timestamp, obs_4624.ingest_timestamp);
        assert_eq!(obs_4624.data["target_user_name"], "Administrator");
        assert_eq!(obs_4624.data["logon_type"], 10);
        assert_eq!(
            obs_4624.data["record_locator"],
            "evtx://chunk/2/record/1001"
        );
        assert_eq!(obs_4624.artifact_id, artifact_id);

        // 4688 Process Create
        let rec_4688 = make_test_record(
            Some("Microsoft-Windows-Security-Auditing"),
            Some("Security"),
            4688,
            json!({
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "ParentProcessName": "C:\\Windows\\explorer.exe"
            }),
            Some(past_time),
        );
        let obs_4688 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_4688);
        assert_eq!(obs_4688.raw_event_type, "process_create");
        assert_eq!(
            obs_4688.data["new_process_name"],
            "C:\\Windows\\System32\\cmd.exe"
        );
        assert_eq!(obs_4688.data["command_line"], "cmd.exe /c whoami");
    }

    #[test]
    fn test_normalize_services_and_accounts() {
        let case_id = EntityId::new_v7();

        // 7045 Service Install
        let rec_7045 = make_test_record(
            Some("Service Control Manager"),
            Some("System"),
            7045,
            json!({
                "ServiceName": "MaliciousService",
                "ImagePath": "C:\\malware.exe",
                "ServiceType": "user mode service"
            }),
            None,
        );
        let obs_7045 = EvtxNormalizer::normalize_record(case_id, None, None, &rec_7045);
        assert_eq!(obs_7045.raw_event_type, "service_installed");
        assert_eq!(obs_7045.data["service_name"], "MaliciousService");
        assert_eq!(obs_7045.data["service_file_name"], "C:\\malware.exe");

        // 4720 Account Created
        let rec_4720 = make_test_record(
            Some("Microsoft-Windows-Security-Auditing"),
            Some("Security"),
            4720,
            json!({
                "TargetUserName": "backdoor_user",
                "SubjectUserName": "Administrator"
            }),
            None,
        );
        let obs_4720 = EvtxNormalizer::normalize_record(case_id, None, None, &rec_4720);
        assert_eq!(obs_4720.raw_event_type, "user_account_created");
        assert_eq!(obs_4720.data["target_user_name"], "backdoor_user");
    }

    #[test]
    fn test_normalize_sysmon_events_and_hash_parsing() {
        let case_id = EntityId::new_v7();
        let artifact_id = Some(EntityId::new_v7());

        // Sysmon 1 Process Creation
        let hashes_str = "SHA256=1122334455667788,MD5=AABBCCDD,IMPHASH=99887766";
        let rec_sysmon1 = make_test_record(
            Some("Microsoft-Windows-Sysmon"),
            Some("Microsoft-Windows-Sysmon/Operational"),
            1,
            json!({
                "Image": "C:\\Windows\\System32\\powershell.exe",
                "CommandLine": "powershell.exe -enc AAAA",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Hashes": hashes_str,
                "User": "CORP\\alice"
            }),
            None,
        );
        let obs_1 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_sysmon1);
        assert_eq!(obs_1.raw_event_type, "process_create");
        assert_eq!(obs_1.data["image"], "C:\\Windows\\System32\\powershell.exe");
        assert_eq!(obs_1.data["hashes_raw"], hashes_str);
        assert_eq!(obs_1.data["hashes"]["SHA256"], "1122334455667788");
        assert_eq!(obs_1.data["hashes"]["MD5"], "AABBCCDD");
        assert_eq!(obs_1.data["hashes"]["IMPHASH"], "99887766");

        // Sysmon 3 Network Connection
        let rec_sysmon3 = make_test_record(
            Some("Microsoft-Windows-Sysmon"),
            Some("Microsoft-Windows-Sysmon/Operational"),
            3,
            json!({
                "Image": "C:\\Windows\\System32\\curl.exe",
                "Protocol": "tcp",
                "SourceIp": "192.168.1.100",
                "SourcePort": "54321",
                "DestinationIp": "10.0.0.5",
                "DestinationPort": "443"
            }),
            None,
        );
        let obs_3 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_sysmon3);
        assert_eq!(obs_3.raw_event_type, "network_connection");
        assert_eq!(obs_3.data["destination_ip"], "10.0.0.5");
        assert_eq!(obs_3.data["destination_port"], 443);

        // Sysmon 22 DNS Query
        let rec_sysmon22 = make_test_record(
            Some("Microsoft-Windows-Sysmon"),
            Some("Microsoft-Windows-Sysmon/Operational"),
            22,
            json!({
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "QueryName": "malicious-c2.example.com",
                "QueryResults": "type: 1 198.51.100.10"
            }),
            None,
        );
        let obs_22 = EvtxNormalizer::normalize_record(case_id, artifact_id, None, &rec_sysmon22);
        assert_eq!(obs_22.raw_event_type, "dns_query");
        assert_eq!(obs_22.data["query_name"], "malicious-c2.example.com");
    }

    #[test]
    fn test_missing_fields_are_none_not_fabricated() {
        let case_id = EntityId::new_v7();
        let bare_record = EvtxRecord {
            record_id: 42,
            provider: None,
            channel: None,
            event_id: 9999,
            version: None,
            level: None,
            computer: None,
            user_sid: None,
            source_timestamp: None,
            ingest_timestamp: Utc::now(),
            event_data: Value::Null,
            user_data: Value::Null,
            system_data: Value::Null,
            chunk_index: 0,
            record_offset: 0,
            record_locator: "evtx://chunk/0/record/42".to_string(),
            raw_record_hash: "hash".to_string(),
            parser_version: "v1".to_string(),
        };

        let obs = EvtxNormalizer::normalize_record(case_id, None, None, &bare_record);
        assert_eq!(obs.raw_event_type, "windows_event");
        assert!(obs.data["provider"].is_null());
        assert!(obs.data["channel"].is_null());
        assert!(obs.data["computer"].is_null());
        assert!(obs.data["user_sid"].is_null());
        assert_ne!(obs.data["computer"], "WORKSTATION-01");
        assert_ne!(obs.data["provider"], "Microsoft-Windows-Sysmon");
    }
}
