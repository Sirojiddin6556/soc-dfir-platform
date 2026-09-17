#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use core_domain::fact::Fact;
use core_domain::id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineLane {
    pub lane_id: String,
    pub title: String,
    pub host_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub fact_id: EntityId,
    pub timestamp: DateTime<Utc>,
    pub lane_id: String,
    pub label: String,
    pub severity: core_domain::Severity,
}

pub struct TimelineEngine;

impl TimelineEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn build_timeline(&self, facts: &[Fact]) -> Vec<TimelineEntry> {
        let mut entries: Vec<TimelineEntry> = facts
            .iter()
            .map(|f| {
                let lane_id = f
                    .data
                    .get("host_ip")
                    .and_then(|h| h.as_str())
                    .unwrap_or("General")
                    .to_string();

                TimelineEntry {
                    fact_id: f.id,
                    timestamp: f.created_at,
                    lane_id,
                    label: format!("{}: {}", f.fact_type, f.entity_key),
                    severity: f.severity,
                }
            })
            .collect();

        entries.sort_by_key(|e| e.timestamp);
        entries
    }
}

impl Default for TimelineEngine {
    fn default() -> Self {
        Self::new()
    }
}
