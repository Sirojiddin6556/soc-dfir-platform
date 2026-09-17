#![forbid(unsafe_code)]

use core_domain::epistemic::Confidence;
use core_domain::fact::{EntityType, Fact};
use core_domain::graph::{AttackEdge, AttackGraph, AttackNode};
use core_domain::id::EntityId;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GraphError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),
}

pub struct DeterministicGraphEngine;

impl DeterministicGraphEngine {
    pub fn new() -> Self {
        Self
    }

    /// Derives reproducible Attack Graph nodes and edges from factual evidence.
    /// Every edge explicitly links back to supporting fact IDs.
    pub fn build_graph_from_facts(&self, case_id: EntityId, facts: &[Fact]) -> AttackGraph {
        let mut nodes_map: HashMap<String, AttackNode> = HashMap::new();
        let mut pending_edges: Vec<(String, String, EntityId, chrono::DateTime<chrono::Utc>)> = Vec::new();

        for fact in facts {
            let node_key = format!("{:?}:{}", fact.entity_type, fact.entity_key);
            let node = nodes_map.entry(node_key.clone()).or_insert_with(|| AttackNode {
                id: EntityId::new_v7(),
                case_id,
                node_type: fact.entity_type,
                label: fact.entity_key.clone(),
                properties: fact.data.clone(),
                first_seen: fact.created_at,
                last_seen: fact.created_at,
            });

            if fact.created_at < node.first_seen {
                node.first_seen = fact.created_at;
            }
            if fact.created_at > node.last_seen {
                node.last_seen = fact.created_at;
            }

            // Queue edge if process execution is linked to a host
            if fact.entity_type == EntityType::Process {
                if let Some(host_key) = fact.data.get("host_ip").and_then(|h| h.as_str()) {
                    let host_node_key = format!("{:?}:{}", EntityType::Host, host_key);
                    pending_edges.push((host_node_key, node_key, fact.id, fact.created_at));
                }
            }
        }

        let mut edges = Vec::new();
        for (host_key, proc_key, fact_id, ts) in pending_edges {
            let host_id = nodes_map.entry(host_key.clone()).or_insert_with(|| AttackNode {
                id: EntityId::new_v7(),
                case_id,
                node_type: EntityType::Host,
                label: host_key.clone(),
                properties: serde_json::json!({}),
                first_seen: ts,
                last_seen: ts,
            }).id;

            if let Some(proc_node) = nodes_map.get(&proc_key) {
                edges.push(AttackEdge {
                    id: EntityId::new_v7(),
                    case_id,
                    source_node_id: host_id,
                    target_node_id: proc_node.id,
                    relation_type: "SPAWNED_PROCESS".to_string(),
                    confidence: Confidence::new(1.0),
                    supported_by: vec![fact_id],
                    first_seen: ts,
                    last_seen: ts,
                });
            }
        }

        AttackGraph {
            case_id,
            nodes: nodes_map.into_values().collect(),
            edges,
        }
    }
}

impl Default for DeterministicGraphEngine {
    fn default() -> Self {
        Self::new()
    }
}
