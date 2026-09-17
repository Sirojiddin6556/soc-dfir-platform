#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use core_domain::workflow::{TaskStatus, WorkflowTask};
use std::collections::{HashMap, HashSet};
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
    pub fn new(
        max_cpu: usize,
        max_io: usize,
        max_net: usize,
        max_forensic: usize,
        max_target_load: usize,
    ) -> Self {
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

    pub async fn set_task_status(
        &self,
        task_id: &EntityId,
        status: TaskStatus,
    ) -> Result<(), WorkflowError> {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = status;
            if status == TaskStatus::Succeeded || status == TaskStatus::Failed {
                task.completed_at = Some(chrono::Utc::now());
            }
            Ok(())
        } else {
            Err(WorkflowError::TaskNotFound(task_id.to_string()))
        }
    }

    /// Finds all tasks whose dependencies are SUCCEEDED and can be marked READY
    pub async fn get_ready_tasks(&self) -> Vec<WorkflowTask> {
        let tasks = self.tasks.lock().await;
        let succeeded_ids: HashSet<EntityId> = tasks
            .values()
            .filter(|t| t.status == TaskStatus::Succeeded)
            .map(|t| t.id)
            .collect();

        let mut ready = Vec::new();
        for task in tasks.values() {
            if task.status == TaskStatus::Pending {
                let deps_satisfied = task
                    .dependencies
                    .iter()
                    .all(|dep| succeeded_ids.contains(dep));
                if deps_satisfied {
                    ready.push(task.clone());
                }
            }
        }

        // Sort by priority descending
        ready.sort_by_key(|b| std::cmp::Reverse(b.priority));
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::workflow::ResourceBudget;

    #[tokio::test]
    async fn test_workflow_dag_dependency_resolution() {
        let limiter = ResourceLimiter::new(4, 2, 2, 1, 1);
        let scheduler = WorkflowScheduler::new(limiter);

        let case_id = EntityId::new_v7();
        let task1_id = EntityId::new_v7();
        let task2_id = EntityId::new_v7();

        let task1 = WorkflowTask {
            id: task1_id,
            case_id,
            task_name: "NetworkDiscovery".to_string(),
            status: TaskStatus::Pending,
            budget: ResourceBudget::default(),
            priority: 10,
            dependencies: vec![],
            condition_dsl: None,
            error_message: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        let task2 = WorkflowTask {
            id: task2_id,
            case_id,
            task_name: "DeepInspection".to_string(),
            status: TaskStatus::Pending,
            budget: ResourceBudget::default(),
            priority: 20,
            dependencies: vec![task1_id],
            condition_dsl: None,
            error_message: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        scheduler.submit_task(task1).await.unwrap();
        scheduler.submit_task(task2).await.unwrap();

        // Initially only task1 is ready (task2 depends on task1)
        let ready = scheduler.get_ready_tasks().await;
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, task1_id);

        // Mark task1 succeeded
        scheduler
            .set_task_status(&task1_id, TaskStatus::Succeeded)
            .await
            .unwrap();

        // Now task2 is ready
        let ready2 = scheduler.get_ready_tasks().await;
        assert_eq!(ready2.len(), 1);
        assert_eq!(ready2[0].id, task2_id);
    }
}
