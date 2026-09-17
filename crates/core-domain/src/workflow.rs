use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Ready,
    Queued,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Blocked,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub cpu: u32,
    pub io: u32,
    pub net: u32,
    pub mem_mb: u32,
    pub forensic: u32,
    pub target_load: u32,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            cpu: 1,
            io: 1,
            net: 0,
            mem_mb: 512,
            forensic: 0,
            target_load: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalEdge {
    pub source_task_id: EntityId,
    pub target_task_id: EntityId,
    pub condition_dsl: Option<String>, // Restricted internal DSL
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkflowProfileType {
    Quick,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTask {
    pub id: EntityId,
    pub case_id: EntityId,
    pub task_name: String,
    pub status: TaskStatus,
    pub budget: ResourceBudget,
    pub priority: i32,
    pub dependencies: Vec<EntityId>,
    pub condition_dsl: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
