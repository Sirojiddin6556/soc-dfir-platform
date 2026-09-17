#![forbid(unsafe_code)]

use core_domain::fact::EntityType;
use core_domain::graph::AttackGraph;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeShape {
    Circle,   // Host
    Hexagon,  // Process
    Diamond,  // Network Socket
    Square,   // Identity / User
    Octagon,  // Threat / Tactic
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagramNode {
    pub id: String,
    pub label: String,
    pub shape: NodeShape,
    pub color_accent: String,
    pub x: f32,
    pub y: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagramEdge {
    pub source: String,
    pub target: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagramView {
    pub nodes: Vec<DiagramNode>,
    pub edges: Vec<DiagramEdge>,
}

pub struct DiagramEngine;

impl DiagramEngine {
    pub fn new() -> Self {
        Self
    }

    /// Projects an AttackGraph into a 2D layout model with multi-dimensional shape encoding
    pub fn project_attack_graph(&self, graph: &AttackGraph) -> DiagramView {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        for (i, node) in graph.nodes.iter().enumerate() {
            let (shape, color) = match node.node_type {
                EntityType::Host => (NodeShape::Circle, "#58a6ff".to_string()),
                EntityType::Process => (NodeShape::Hexagon, "#2ea043".to_string()),
                EntityType::NetworkSocket => (NodeShape::Diamond, "#bc8cff".to_string()),
                EntityType::Identity => (NodeShape::Square, "#39c5bb".to_string()),
                _ => (NodeShape::Octagon, "#f85149".to_string()),
            };

            nodes.push(DiagramNode {
                id: node.id.to_string(),
                label: node.label.clone(),
                shape,
                color_accent: color,
                x: (i as f32) * 120.0,
                y: 100.0,
            });
        }

        for edge in &graph.edges {
            edges.push(DiagramEdge {
                source: edge.source_node_id.to_string(),
                target: edge.target_node_id.to_string(),
                label: edge.relation_type.clone(),
            });
        }

        DiagramView { nodes, edges }
    }
}

impl Default for DiagramEngine {
    fn default() -> Self {
        Self::new()
    }
}
