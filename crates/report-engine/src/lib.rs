#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use core_domain::fact::Fact;
use core_domain::graph::AttackGraph;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReport {
    pub case_id: String,
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub total_facts: usize,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub containment_recommendations: Vec<String>,
}

pub struct ReportEngine;

impl ReportEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_report(
        &self,
        case_id: &str,
        title: &str,
        facts: &[Fact],
        graph: &AttackGraph,
    ) -> IncidentReport {
        let mut recommendations = Vec::new();

        for fact in facts {
            if fact.severity >= core_domain::Severity::High {
                recommendations.push(format!(
                    "Isolate asset '{}' exhibiting high risk indicator '{}'",
                    fact.entity_key, fact.fact_type
                ));
            }
        }

        IncidentReport {
            case_id: case_id.to_string(),
            title: title.to_string(),
            generated_at: Utc::now(),
            total_facts: facts.len(),
            total_nodes: graph.nodes.len(),
            total_edges: graph.edges.len(),
            containment_recommendations: recommendations,
        }
    }
}

impl Default for ReportEngine {
    fn default() -> Self {
        Self::new()
    }
}
