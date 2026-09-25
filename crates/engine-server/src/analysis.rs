#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use correlation_engine::correlate_in_batches;
use std::collections::BTreeMap;
use storage_sqlite::{SqliteStorage, SqliteStorageError};
use thiserror::Error;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AnalysisProcessingResult {
    pub observations_processed: u64,
    pub timeline_events_created: u64,
    pub correlations_created: u64,
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("storage error: {0}")]
    Storage(#[from] SqliteStorageError),
    #[error("correlation error: {0}")]
    Correlation(#[from] correlation_engine::CorrelationError),
}

fn string_field(data: &serde_json::Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        data.get(*name)
            .and_then(|value| value.as_str())
            .map(ToString::to_string)
    })
}

/// Applies only explicit host/interface evidence. A network endpoint is never
/// attributed from time proximity or domain equality alone.
fn apply_explicit_host_attribution(
    observations: &[core_domain::observation::Observation],
) -> Vec<core_domain::observation::Observation> {
    let mut address_to_host = BTreeMap::new();
    for observation in observations {
        let Some(host) = string_field(&observation.data, &["host", "computer"]) else {
            continue;
        };
        if let Some(address) = string_field(
            &observation.data,
            &["host_ip", "interface_ip", "interface_address", "source_ip"],
        ) {
            address_to_host.insert(address, host);
        }
    }

    observations
        .iter()
        .cloned()
        .map(|mut observation| {
            if string_field(&observation.data, &["host", "computer"]).is_none() {
                let address = string_field(&observation.data, &["source_ip"]);
                if let Some(host) = address.and_then(|value| address_to_host.get(&value)) {
                    if let Some(object) = observation.data.as_object_mut() {
                        object.insert("host".to_string(), serde_json::json!(host));
                    }
                }
            }
            observation
        })
        .collect()
}

/// Rebuilds the case-scoped forensic projections from persisted observations.
/// The operation is intentionally idempotent: semantic event/correlation IDs
/// are primary keys and storage uses INSERT OR REPLACE.
pub fn process_persisted_observations(
    storage: &SqliteStorage,
    case_id: EntityId,
) -> Result<AnalysisProcessingResult, AnalysisError> {
    let persisted_observations = storage.list_observations_for_case(case_id)?;
    let observations = apply_explicit_host_attribution(&persisted_observations);
    let timeline = timeline_engine::project_observations(&observations);
    for event in &timeline {
        storage.insert_timeline_event(event)?;
    }

    let correlations = correlate_in_batches(&observations, 512)?;
    storage.clear_correlations_for_case(case_id)?;
    for result in &correlations {
        storage.insert_correlation(result, case_id)?;
    }

    Ok(AnalysisProcessingResult {
        observations_processed: observations.len() as u64,
        timeline_events_created: timeline.len() as u64,
        correlations_created: correlations.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::observation::Observation;

    fn observation(
        case_id: EntityId,
        event_type: &str,
        timestamp: chrono::DateTime<chrono::Utc>,
        data: serde_json::Value,
    ) -> Observation {
        Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: if event_type == "process_create" {
                "sysmon_parser".to_string()
            } else {
                "pcap_parser".to_string()
            },
            raw_event_type: event_type.to_string(),
            source_timestamp: Some(timestamp),
            ingest_timestamp: timestamp + chrono::Duration::seconds(1),
            data,
            network_quality: if event_type == "process_create" {
                None
            } else {
                Some(core_domain::NetworkObservationQuality {
                    capture: core_domain::CaptureQuality::Complete,
                    flow: Some(core_domain::FlowQuality::Complete),
                    protocol: Some(core_domain::ProtocolQuality::Complete),
                })
            },
            network_provenance: None,
        }
    }

    #[test]
    fn analysis_is_case_scoped_order_independent_and_idempotent() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let case_id = EntityId::new_v7();
        storage.insert_case(case_id, "Phase 4", None).unwrap();
        let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let observations = [
            observation(
                case_id,
                "process_create",
                base,
                serde_json::json!({"host": "WS-01", "process_name": "powershell.exe"}),
            ),
            observation(
                case_id,
                "dns_message",
                base + chrono::Duration::seconds(10),
                serde_json::json!({"host": "WS-01", "qname": "example.test"}),
            ),
            observation(
                case_id,
                "tls_handshake",
                base + chrono::Duration::seconds(20),
                serde_json::json!({"host": "WS-01", "sni": "example.test"}),
            ),
        ];
        for observation in observations.iter().rev() {
            storage.insert_observation(observation).unwrap();
        }

        let first = process_persisted_observations(&storage, case_id).unwrap();
        let timeline_a = storage.list_timeline_events_for_case(case_id).unwrap();
        let correlations_a = storage.list_correlations_for_case(case_id).unwrap();
        let second = process_persisted_observations(&storage, case_id).unwrap();
        let timeline_b = storage.list_timeline_events_for_case(case_id).unwrap();
        let correlations_b = storage.list_correlations_for_case(case_id).unwrap();

        assert_eq!(first, second);
        assert_eq!(timeline_a, timeline_b);
        assert_eq!(correlations_a, correlations_b);
        assert_eq!(timeline_a.len(), 3);
        assert_eq!(correlations_a.len(), 1);
    }

    #[test]
    fn analysis_uses_explicit_source_ip_host_binding() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let case_id = EntityId::new_v7();
        storage.insert_case(case_id, "Host binding", None).unwrap();
        let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let observations = [
            observation(
                case_id,
                "process_create",
                base,
                serde_json::json!({"computer": "WS-01", "process_name": "powershell.exe"}),
            ),
            observation(
                case_id,
                "network_connection",
                base + chrono::Duration::seconds(1),
                serde_json::json!({"computer": "WS-01", "source_ip": "10.10.10.25"}),
            ),
            observation(
                case_id,
                "dns_message",
                base + chrono::Duration::seconds(2),
                serde_json::json!({"source_ip": "10.10.10.25", "qname": "example.test"}),
            ),
            observation(
                case_id,
                "tls_handshake",
                base + chrono::Duration::seconds(3),
                serde_json::json!({"source_ip": "10.10.10.25", "sni": "example.test"}),
            ),
        ];
        for item in observations {
            storage.insert_observation(&item).unwrap();
        }

        let result = process_persisted_observations(&storage, case_id).unwrap();
        assert_eq!(result.correlations_created, 1);
        assert_eq!(
            storage.list_correlations_for_case(case_id).unwrap()[0]
                .provenance
                .matched_host
                .as_deref(),
            Some("WS-01")
        );
    }
}
