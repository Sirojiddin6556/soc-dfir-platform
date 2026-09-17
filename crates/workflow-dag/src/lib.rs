#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use core_domain::workflow::{TaskStatus, WorkflowTask};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};

#[derive(Error, Debug)]
pub enum WorkflowError {
    #[error("Task not found: {0}")]
    TaskNotFound(String),

    #[error("Dependency cycle detected")]
    CycleDetected,

    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("Task cancelled")]
    Cancelled,
}

pub struct ResourceLimiter {
    pub cpu_sem: Arc<Semaphore>,
    pub io_sem: Arc<Semaphore>,
    pub net_sem: Arc<Semaphore>,
    pub forensic_sem: Arc<Semaphore>,
    pub target_load_sem: Arc<Semaphore>,
}

impl ResourceLimiter {
    pub fn new(max_cpu: usize, max_io: usize, max_net: usize, max_forensic: usize, max_target_load: usize) -> Self {
        Self {
            cpu_sem: Arc::new(Semaphore::new(max_cpu)),
            io_sem: Arc::new(Semaphore::new(max_io)),
            net_sem: Arc::new(Semaphore::new(max_net)),
            forensic_sem: Arc::new(Semaphore::new(max_forensic)),
            target_load_sem: Arc::new(Semaphore::new(max_target_load)),
        }
    }
}

pub struct WorkflowScheduler {
    pub limiter: ResourceLimiter,
    tasks: Arc<Mutex<HashMap<EntityId, WorkflowTask>>>,
}

impl WorkflowScheduler {
    pub fn new(limiter: ResourceLimiter) -> Self {
        Self {
            limiter,
            tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn submit_task(&self, task: WorkflowTask) -> Result<EntityId, WorkflowError> {
        let id = task.id;
        let mut tasks = self.tasks.lock().await;
        tasks.insert(id, task);
        Ok(id)
    }

    pub async fn set_task_status(&self, task_id: &EntityId, status: TaskStatus) -> Result<(), WorkflowError> {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = status;
            Ok(())
        } else {
            Err(WorkflowError::TaskNotFound(task_id.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::workflow::ResourceBudget;

    #[tokio::test]
    async fn test_workflow_task_submission() {
        let limiter = ResourceLimiter::new(4, 2, 2, 1, 1);
        let scheduler = WorkflowScheduler::new(limiter);

        let task = WorkflowTask {
            id: EntityId::new_v7(),
            case_id: EntityId::new_v7(),
            task_name: "ParseEvtxSecurityLogs".to_string(),
            status: TaskStatus::Pending,
            budget: ResourceBudget::default(),
            priority: 10,
            dependencies: vec![],
            condition_dsl: None,
            error_message: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        let task_id = scheduler.submit_task(task).await.unwrap();
        scheduler.set_task_status(&task_id, TaskStatus::Running).await.unwrap();
    }
}
