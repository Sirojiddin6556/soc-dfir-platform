use crate::epistemic::Confidence;
use crate::fact::EntityType;
use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: EntityId,
    pub case_id: EntityId,
    pub node_type: EntityType,
    pub label: String,
    pub properties: serde_json::Value,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub id: EntityId,
    pub case_id: EntityId,
    pub source_node_id: EntityId,
    pub target_node_id: EntityId,
    pub relation_type: String,
    pub confidence: Confidence,
    pub supported_by: Vec<EntityId>, // Exact Fact IDs proving this edge
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackGraph {
    pub case_id: EntityId,
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphDelta {
    pub case_id: EntityId,
    pub added_nodes: Vec<AttackNode>,
    pub updated_nodes: Vec<AttackNode>,
    pub removed_node_ids: Vec<EntityId>,
    pub added_edges: Vec<AttackEdge>,
    pub cursor: String,
}
