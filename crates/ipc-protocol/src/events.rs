#![forbid(unsafe_code)]

use crate::jsonrpc::JsonRpcNotification;
use core_domain::ctf::JobStatus;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const DEFAULT_STREAM_THROTTLE_MS: u64 = 16; // ~60 FPS
pub const MAX_CHUNK_BYTES: usize = 16 * 1024; // 16 KB per output chunk

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobOutputEvent {
    pub job_id: String,
    pub stream: String, // "stdout" | "stderr"
    pub data: String,
    pub offset: usize,
    pub is_eof: bool,
}

impl JobOutputEvent {
    pub fn stdout(
        job_id: impl Into<String>,
        data: impl Into<String>,
        offset: usize,
        is_eof: bool,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            stream: "stdout".to_string(),
            data: data.into(),
            offset,
            is_eof,
        }
    }

    pub fn stderr(
        job_id: impl Into<String>,
        data: impl Into<String>,
        offset: usize,
        is_eof: bool,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            stream: "stderr".to_string(),
            data: data.into(),
            offset,
            is_eof,
        }
    }

    pub fn to_notification(&self) -> JsonRpcNotification<Self> {
        JsonRpcNotification::new("job.output", self.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobStatusEvent {
    pub job_id: String,
    pub previous_status: Option<JobStatus>,
    pub new_status: JobStatus,
    pub exit_code: Option<i32>,
    pub elapsed_ms: u64,
}

impl JobStatusEvent {
    pub fn new(
        job_id: impl Into<String>,
        previous_status: Option<JobStatus>,
        new_status: JobStatus,
        exit_code: Option<i32>,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            previous_status,
            new_status,
            exit_code,
            elapsed_ms,
        }
    }

    pub fn to_notification(&self) -> JsonRpcNotification<Self> {
        JsonRpcNotification::new("job.status_changed", self.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobProgressEvent {
    pub job_id: String,
    pub stage: String,
    pub percentage: f32,
    pub bytes_processed: u64,
}

impl JobProgressEvent {
    pub fn new(
        job_id: impl Into<String>,
        stage: impl Into<String>,
        percentage: f32,
        bytes_processed: u64,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            stage: stage.into(),
            percentage,
            bytes_processed,
        }
    }

    pub fn to_notification(&self) -> JsonRpcNotification<Self> {
        JsonRpcNotification::new("job.progress", self.clone())
    }
}

/// Token bucket / time gate throttler to ensure ~60 FPS (16ms) message rate
pub struct EventThrottler {
    throttle_interval: Duration,
    last_flush: Instant,
    pending_buffer: String,
}

impl EventThrottler {
    pub fn new(throttle_interval_ms: u64) -> Self {
        Self {
            throttle_interval: Duration::from_millis(throttle_interval_ms),
            last_flush: Instant::now() - Duration::from_millis(throttle_interval_ms),
            pending_buffer: String::new(),
        }
    }

    pub fn default_60fps() -> Self {
        Self::new(DEFAULT_STREAM_THROTTLE_MS)
    }

    /// Appends incoming text. If throttle period has elapsed or buffer exceeds max chunk,
    /// flushes and returns `Some(chunk)`. Otherwise buffers and returns `None`.
    pub fn push(&mut self, text: &str) -> Option<String> {
        self.pending_buffer.push_str(text);
        if self.should_flush() {
            Some(self.flush())
        } else {
            None
        }
    }

    pub fn should_flush(&self) -> bool {
        !self.pending_buffer.is_empty()
            && (self.last_flush.elapsed() >= self.throttle_interval
                || self.pending_buffer.len() >= MAX_CHUNK_BYTES)
    }

    pub fn flush(&mut self) -> String {
        self.last_flush = Instant::now();
        std::mem::take(&mut self.pending_buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_output_notification_serialization() {
        let ev = JobOutputEvent::stdout("job-42", "Found flag snippet\n", 0, false);
        let notif = ev.to_notification();
        assert_eq!(notif.method, "job.output");
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("Found flag snippet"));
        assert!(json.contains("\"method\":\"job.output\""));
    }

    #[test]
    fn test_job_status_notification() {
        let ev = JobStatusEvent::new(
            "job-42",
            Some(JobStatus::Running),
            JobStatus::Succeeded,
            Some(0),
            120,
        );
        let notif = ev.to_notification();
        assert_eq!(notif.method, "job.status_changed");
        assert_eq!(notif.params.new_status, JobStatus::Succeeded);
    }

    #[test]
    fn test_event_throttler() {
        let mut throttler = EventThrottler::new(50);
        // First push immediately flushes because last_flush was initialized in the past
        let chunk1 = throttler.push("First batch");
        assert_eq!(chunk1.as_deref(), Some("First batch"));

        // Immediate next push should be buffered
        let chunk2 = throttler.push("Second batch");
        assert_eq!(chunk2, None);

        // Explicit flush returns the buffered data
        let flushed = throttler.flush();
        assert_eq!(flushed, "Second batch");
    }
}
