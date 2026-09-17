#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use core_domain::observation::{Observation, RawToolResult};
use thiserror::Error;

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

/// Baseline JSON/Log normalizer
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
        let mut observations = Vec::new();
        let now = chrono::Utc::now();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let data = serde_json::from_str(line).unwrap_or_else(|_| {
                serde_json::json!({ "raw_message": line })
            });

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
