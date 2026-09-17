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

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Task timed out")]
    Timeout,

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
            if status == TaskStatus::Succeeded
                || status == TaskStatus::Failed
                || status == TaskStatus::Cancelled
            {
                task.completed_at = Some(chrono::Utc::now());
            }
            Ok(())
        } else {
            Err(WorkflowError::TaskNotFound(task_id.to_string()))
        }
    }

    pub async fn cancel_task(&self, task_id: &EntityId) -> Result<(), WorkflowError> {
        self.set_task_status(task_id, TaskStatus::Cancelled).await
    }

    /// Executes task with real resource permits and timeout protection
    pub async fn execute_task<F, Fut>(
        &self,
        task_id: &EntityId,
        timeout_ms: u64,
        executor: F,
    ) -> Result<(), WorkflowError>
    where
        F: FnOnce(EntityId) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        // 1. Fetch task and check condition DSL
        let budget = {
            let mut tasks = self.tasks.lock().await;
            let task = tasks
                .get_mut(task_id)
                .ok_or_else(|| WorkflowError::TaskNotFound(task_id.to_string()))?;
            if let Some(ref dsl) = task.condition_dsl {
                if dsl == "skip" || dsl == "false" {
                    task.status = TaskStatus::Skipped;
                    task.completed_at = Some(chrono::Utc::now());
                    return Ok(());
                }
            }
            task.status = TaskStatus::Running;
            task.budget
        };

        // 2. Acquire real resource permits
        let _cpu_permit = self
            .limiter
            .cpu_sem
            .acquire_many(budget.cpu.max(1))
            .await
            .map_err(|e| WorkflowError::ResourceLimit(e.to_string()))?;
        let _io_permit = self
            .limiter
            .io_sem
            .acquire_many(budget.io.max(1))
            .await
            .map_err(|e| WorkflowError::ResourceLimit(e.to_string()))?;

        // 3. Execute with timeout
        let fut = executor(*task_id);
        let exec_result =
            tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await;

        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.completed_at = Some(chrono::Utc::now());
            match exec_result {
                Ok(Ok(())) => {
                    task.status = TaskStatus::Succeeded;
                    Ok(())
                }
                Ok(Err(e)) => {
                    task.status = TaskStatus::Failed;
                    task.error_message = Some(e.clone());
                    Err(WorkflowError::ExecutionFailed(e))
                }
                Err(_) => {
                    task.status = TaskStatus::TimedOut;
                    task.error_message = Some("Task execution timed out".to_string());
                    Err(WorkflowError::Timeout)
                }
            }
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

    #[tokio::test]
    async fn test_task_execution_with_resource_permits() {
        let limiter = ResourceLimiter::new(2, 2, 1, 1, 1);
        let scheduler = WorkflowScheduler::new(limiter);
        let case_id = EntityId::new_v7();
        let task_id = EntityId::new_v7();

        let task = WorkflowTask {
            id: task_id,
            case_id,
            task_name: "Correlate".to_string(),
            status: TaskStatus::Pending,
            budget: ResourceBudget {
                cpu: 2,
                io: 1,
                net: 0,
                mem_mb: 256,
                forensic: 0,
                target_load: 0,
            },
            priority: 10,
            dependencies: vec![],
            condition_dsl: None,
            error_message: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        scheduler.submit_task(task).await.unwrap();

        let res = scheduler
            .execute_task(&task_id, 1000, |_tid| async { Ok(()) })
            .await;

        assert!(res.is_ok());
        let ready = scheduler.get_ready_tasks().await;
        assert!(ready.is_empty()); // Already Succeeded
    }

    #[tokio::test]
    async fn test_task_execution_timeout() {
        let limiter = ResourceLimiter::new(2, 2, 1, 1, 1);
        let scheduler = WorkflowScheduler::new(limiter);
        let case_id = EntityId::new_v7();
        let task_id = EntityId::new_v7();

        let task = WorkflowTask {
            id: task_id,
            case_id,
            task_name: "HangingTask".to_string(),
            status: TaskStatus::Pending,
            budget: ResourceBudget::default(),
            priority: 5,
            dependencies: vec![],
            condition_dsl: None,
            error_message: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        scheduler.submit_task(task).await.unwrap();

        let res = scheduler
            .execute_task(&task_id, 50, |_tid| async {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                Ok(())
            })
            .await;

        assert!(matches!(res, Err(WorkflowError::Timeout)));
    }

    #[tokio::test]
    async fn test_task_condition_dsl_skip() {
        let limiter = ResourceLimiter::new(2, 2, 1, 1, 1);
        let scheduler = WorkflowScheduler::new(limiter);
        let case_id = EntityId::new_v7();
        let task_id = EntityId::new_v7();

        let task = WorkflowTask {
            id: task_id,
            case_id,
            task_name: "ConditionalTask".to_string(),
            status: TaskStatus::Pending,
            budget: ResourceBudget::default(),
            priority: 5,
            dependencies: vec![],
            condition_dsl: Some("skip".to_string()),
            error_message: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        scheduler.submit_task(task).await.unwrap();

        let res = scheduler
            .execute_task(&task_id, 1000, |_tid| async { Ok(()) })
            .await;

        assert!(res.is_ok());
    }
}
