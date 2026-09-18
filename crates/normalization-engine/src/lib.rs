#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use core_domain::observation::{Observation, RawToolResult};
use thiserror::Error;

pub mod cpe;
pub mod importer;
pub mod vuln;

pub use cpe::{resolve_cpe_and_purl, NormalizedSoftwareId};
pub use importer::{parse_epss_csv, parse_kev_json, parse_nvd_json, ImportError, ImportedCve};
pub use vuln::{VulnerabilityDatabase, VulnerabilityRecord};

#[derive(Error, Debug)]
pub enum NormalizationError {
    #[error("Failed to parse tool output: {0}")]
    ParseFailure(String),

    #[error("Unsupported tool format: {0}")]
    UnsupportedTool(String),
}

pub trait Normalizer: Send + Sync {
    fn tool_name(&self) -> &'static str;
    fn normalize(
        &self,
        case_id: EntityId,
        raw: &RawToolResult,
    ) -> Result<Vec<Observation>, NormalizationError>;
}

/// Generic log line normalizer
pub struct GenericLogNormalizer;

impl Normalizer for GenericLogNormalizer {
    fn tool_name(&self) -> &'static str {
        "generic_log"
    }

    fn normalize(
        &self,
        case_id: EntityId,
        raw: &RawToolResult,
    ) -> Result<Vec<Observation>, NormalizationError> {
        let text = String::from_utf8_lossy(&raw.stdout_bytes);
        let trimmed = text.trim();
        let mut observations = Vec::new();
        let now = chrono::Utc::now();

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if let Ok(records) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                for rec in records {
                    let mut data = rec.clone();
                    if let Some(inner) = rec.get("data").and_then(|d| d.as_object()) {
                        if let Some(obj) = data.as_object_mut() {
                            for (k, v) in inner {
                                obj.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    observations.push(Observation {
                        id: EntityId::new_v7(),
                        case_id,
                        artifact_id: None,
                        tool_run_id: None,
                        source_tool: raw.tool_name.clone(),
                        raw_event_type: "log_entry".to_string(),
                        source_timestamp: now,
                        ingest_timestamp: now,
                        data,
                    });
                }
                return Ok(observations);
            }
        }

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let data = serde_json::from_str(line)
                .unwrap_or_else(|_| serde_json::json!({ "raw_message": line }));

            observations.push(Observation {
                id: EntityId::new_v7(),
                case_id,
                artifact_id: None,
                tool_run_id: None,
                source_tool: raw.tool_name.clone(),
                raw_event_type: "log_entry".to_string(),
                source_timestamp: now,
                ingest_timestamp: now,
                data,
            });
        }

        Ok(observations)
    }
}

/// Windows EVTX Event Log Normalizer
pub struct EvtxSecurityNormalizer;

impl Normalizer for EvtxSecurityNormalizer {
    fn tool_name(&self) -> &'static str {
        "evtx_security"
    }

    fn normalize(
        &self,
        case_id: EntityId,
        raw: &RawToolResult,
    ) -> Result<Vec<Observation>, NormalizationError> {
        let text = String::from_utf8_lossy(&raw.stdout_bytes);
        let mut observations = Vec::new();
        let now = chrono::Utc::now();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                let event_id = val.get("EventID").and_then(|id| id.as_u64()).unwrap_or(0);
                let raw_type = match event_id {
                    4688 => "process_create",
                    4624 => "logon_success",
                    4625 => "logon_failure",
                    4672 => "special_privilege_logon",
                    7045 => "service_installed",
                    _ => "security_event",
                };

                observations.push(Observation {
                    id: EntityId::new_v7(),
                    case_id,
                    artifact_id: None,
                    tool_run_id: None,
                    source_tool: self.tool_name().to_string(),
                    raw_event_type: raw_type.to_string(),
                    source_timestamp: now,
                    ingest_timestamp: now,
                    data: val,
                });
            }
        }

        Ok(observations)
    }
}

/// Sysmon Event Normalizer
pub struct SysmonNormalizer;

impl Normalizer for SysmonNormalizer {
    fn tool_name(&self) -> &'static str {
        "sysmon"
    }

    fn normalize(
        &self,
        case_id: EntityId,
        raw: &RawToolResult,
    ) -> Result<Vec<Observation>, NormalizationError> {
        let text = String::from_utf8_lossy(&raw.stdout_bytes);
        let mut observations = Vec::new();
        let now = chrono::Utc::now();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                let event_id = val.get("EventID").and_then(|id| id.as_u64()).unwrap_or(0);
                let raw_type = match event_id {
                    1 => "sysmon_process_create",
                    3 => "sysmon_network_connect",
                    7 => "sysmon_image_loaded",
                    11 => "sysmon_file_created",
                    13 => "sysmon_registry_value_set",
                    _ => "sysmon_event",
                };

                observations.push(Observation {
                    id: EntityId::new_v7(),
                    case_id,
                    artifact_id: None,
                    tool_run_id: None,
                    source_tool: self.tool_name().to_string(),
                    raw_event_type: raw_type.to_string(),
                    source_timestamp: now,
                    ingest_timestamp: now,
                    data: val,
                });
            }
        }

        Ok(observations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evtx_normalizer_event_id_mapping() {
        let normalizer = EvtxSecurityNormalizer;
        let case_id = EntityId::new_v7();
        let raw = RawToolResult {
            tool_name: "evtx_parser".to_string(),
            tool_version: "1.0".to_string(),
            exit_code: 0,
            stdout_bytes: br#"{"EventID": 4688, "command_line": "cmd.exe /c whoami"}"#.to_vec(),
            stderr_bytes: Vec::new(),
            execution_duration_ms: 10,
            output_hash: "hash".to_string(),
        };

        let obs = normalizer.normalize(case_id, &raw).unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].raw_event_type, "process_create");
    }
}
