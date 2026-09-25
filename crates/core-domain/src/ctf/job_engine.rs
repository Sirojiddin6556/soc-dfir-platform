use super::pipeline_entities::*;
use super::ring_buffer::BoundedOutputBuffer;
use super::traits::JobEngineService;
use crate::error::DomainError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::{oneshot, Mutex};
use tokio::time::Duration;

const DANGEROUS_ENVS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "NODE_OPTIONS",
    "PERL5LIB",
    "RUBYOPT",
    "BASH_ENV",
];

pub fn validate_zero_shell_argv(argv: &[String]) -> Result<(), DomainError> {
    if argv.is_empty() {
        return Err(DomainError::Validation("argv cannot be empty".to_string()));
    }
    for (idx, arg) in argv.iter().enumerate() {
        if arg.contains('\0') {
            return Err(DomainError::SecurityViolation(format!(
                "Null byte detected in argv[{}]",
                idx
            )));
        }
    }
    Ok(())
}

pub struct ActiveJobHandle {
    pub state: JobRuntimeState,
    pub stdout_buf: BoundedOutputBuffer,
    pub stderr_buf: BoundedOutputBuffer,
    cancel_tx: Option<oneshot::Sender<()>>,
}

#[derive(Clone, Default)]
pub struct LocalJobEngine {
    jobs: Arc<Mutex<HashMap<JobId, ActiveJobHandle>>>,
}

impl LocalJobEngine {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl JobEngineService for LocalJobEngine {
    async fn submit_job(&self, spec: JobSpec) -> Result<JobId, DomainError> {
        validate_zero_shell_argv(&spec.argv)?;

        let job_id = format!("job-{}", uuid::Uuid::now_v7());
        let program = spec.argv[0].clone();
        let args = spec.argv[1..].to_vec();

        let initial_state = JobRuntimeState {
            id: job_id.clone(),
            challenge_id: spec.challenge_id.clone(),
            tool_id: spec.tool_id.clone(),
            status: JobStatus::Running,
            exit_code: None,
            elapsed_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };

        let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

        {
            let mut lock = self.jobs.lock().await;
            lock.insert(
                job_id.clone(),
                ActiveJobHandle {
                    state: initial_state,
                    stdout_buf: BoundedOutputBuffer::default(),
                    stderr_buf: BoundedOutputBuffer::default(),
                    cancel_tx: Some(cancel_tx),
                },
            );
        }

        let jobs_map = Arc::clone(&self.jobs);
        let spawned_job_id = job_id.clone();
        let timeout_ms = spec.timeout_ms.unwrap_or(60_000);

        tokio::spawn(async move {
            let start_time = std::time::Instant::now();
            let mut cmd = tokio::process::Command::new(&program);
            cmd.args(&args);
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            // Sanitize dangerous environment variables
            for env in DANGEROUS_ENVS {
                cmd.env_remove(env);
            }

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let mut lock = jobs_map.lock().await;
                    if let Some(h) = lock.get_mut(&spawned_job_id) {
                        h.state.status = JobStatus::Failed;
                        h.state.elapsed_ms = start_time.elapsed().as_millis() as u64;
                        h.stderr_buf
                            .write(format!("Failed to spawn process: {}", e).as_bytes());
                    }
                    return;
                }
            };

            let mut stdout = child.stdout.take();
            let mut stderr = child.stderr.take();

            let stdout_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut collected = Vec::new();
                if let Some(ref mut out) = stdout {
                    while let Ok(n) = out.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        collected.extend_from_slice(&buf[..n]);
                    }
                }
                collected
            });

            let stderr_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut collected = Vec::new();
                if let Some(ref mut err) = stderr {
                    while let Ok(n) = err.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        collected.extend_from_slice(&buf[..n]);
                    }
                }
                collected
            });

            let sleep_fut = tokio::time::sleep(Duration::from_millis(timeout_ms));
            tokio::pin!(sleep_fut);

            let mut final_status = JobStatus::Succeeded;
            let mut exit_code = None;

            tokio::select! {
                res = child.wait() => {
                    match res {
                        Ok(status) => {
                            exit_code = status.code();
                            if !status.success() {
                                final_status = JobStatus::Failed;
                            }
                        }
                        Err(_) => {
                            final_status = JobStatus::Failed;
                        }
                    }
                }
                _ = &mut sleep_fut => {
                    let _ = child.kill().await;
                    final_status = JobStatus::TimedOut;
                }
                _ = &mut cancel_rx => {
                    let _ = child.kill().await;
                    final_status = JobStatus::Cancelled;
                }
            }

            let stdout_bytes = stdout_task.await.unwrap_or_default();
            let stderr_bytes = stderr_task.await.unwrap_or_default();

            let mut lock = jobs_map.lock().await;
            if let Some(h) = lock.get_mut(&spawned_job_id) {
                h.state.status = final_status;
                h.state.exit_code = exit_code;
                h.state.elapsed_ms = start_time.elapsed().as_millis() as u64;
                h.stdout_buf.write(&stdout_bytes);
                h.stderr_buf.write(&stderr_bytes);
                h.state.stdout_bytes = h.stdout_buf.total_bytes();
                h.state.stderr_bytes = h.stderr_buf.total_bytes();
            }
        });

        Ok(job_id)
    }

    async fn cancel_job(&self, id: &JobId, _reason: Option<String>) -> Result<(), DomainError> {
        let mut lock = self.jobs.lock().await;
        if let Some(h) = lock.get_mut(id) {
            if let Some(tx) = h.cancel_tx.take() {
                let _ = tx.send(());
            }
            h.state.status = JobStatus::Cancelled;
            Ok(())
        } else {
            Err(DomainError::not_found("Job", id))
        }
    }

    async fn get_job_state(&self, id: &JobId) -> Result<JobRuntimeState, DomainError> {
        let lock = self.jobs.lock().await;
        lock.get(id)
            .map(|h| h.state.clone())
            .ok_or_else(|| DomainError::not_found("Job", id))
    }

    async fn get_output_tail(
        &self,
        id: &JobId,
        max_bytes: usize,
    ) -> Result<OutputTail, DomainError> {
        let lock = self.jobs.lock().await;
        lock.get(id)
            .map(|h| h.stdout_buf.get_tail(max_bytes))
            .ok_or_else(|| DomainError::not_found("Job", id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_zero_shell_validation() {
        let bad_argv = vec!["strings".to_string(), "arg\0inject".to_string()];
        let err = validate_zero_shell_argv(&bad_argv).unwrap_err();
        assert!(matches!(err, DomainError::SecurityViolation(_)));

        let empty_argv: Vec<String> = vec![];
        let err = validate_zero_shell_argv(&empty_argv).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[tokio::test]
    async fn test_job_submission_and_execution() {
        let engine = LocalJobEngine::new();
        let spec = JobSpec {
            challenge_id: "chal-test".to_string(),
            tool_id: "cargo".to_string(),
            adapter: Some("rust".to_string()),
            argv: vec!["cargo".to_string(), "--version".to_string()],
            input_refs: None,
            timeout_ms: Some(10_000),
            runtime: Some(JobRuntime::Native),
            limits: None,
        };

        let job_id = engine.submit_job(spec).await.unwrap();

        // Wait a moment for command execution
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let state = engine.get_job_state(&job_id).await.unwrap();
            if state.status == JobStatus::Succeeded || state.status == JobStatus::Failed {
                break;
            }
        }

        let state = engine.get_job_state(&job_id).await.unwrap();
        assert_eq!(state.status, JobStatus::Succeeded);
        assert_eq!(state.exit_code, Some(0));

        let tail = engine.get_output_tail(&job_id, 1024).await.unwrap();
        assert!(tail.head.contains("cargo"));
    }

    #[tokio::test]
    async fn test_job_cancellation() {
        let engine = LocalJobEngine::new();
        // Run cargo help or something that would be running
        let spec = JobSpec {
            challenge_id: "chal-cancel".to_string(),
            tool_id: "cargo".to_string(),
            adapter: None,
            argv: vec!["cargo".to_string(), "help".to_string()],
            input_refs: None,
            timeout_ms: Some(30_000),
            runtime: None,
            limits: None,
        };

        let job_id = engine.submit_job(spec).await.unwrap();
        engine
            .cancel_job(&job_id, Some("User cancelled".into()))
            .await
            .unwrap();
        let state = engine.get_job_state(&job_id).await.unwrap();
        assert_eq!(state.status, JobStatus::Cancelled);
    }
}
