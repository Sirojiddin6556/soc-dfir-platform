use super::entities::{BlockedReason, Challenge, ChallengeStatus};
use super::pipeline_entities::{Job, JobStatus};
use crate::error::DomainError;

impl ChallengeStatus {
    pub fn can_transition_to(&self, next: &ChallengeStatus) -> bool {
        match (self, next) {
            (Self::New, Self::InProgress) | (Self::New, Self::Archived) => true,
            (Self::InProgress, Self::Blocked)
            | (Self::InProgress, Self::Solved)
            | (Self::InProgress, Self::Archived) => true,
            (Self::Blocked, Self::InProgress) | (Self::Blocked, Self::Archived) => true,
            (Self::Solved, Self::Archived) | (Self::Solved, Self::InProgress) => true,
            (Self::Archived, Self::InProgress) => true,
            (s, n) if s == n => true, // idempotent no-op
            _ => false,
        }
    }
}

pub fn transition_challenge(
    challenge: &mut Challenge,
    next: ChallengeStatus,
    reason: Option<BlockedReason>,
) -> Result<(), DomainError> {
    if !challenge.status.can_transition_to(&next) {
        return Err(DomainError::Conflict(format!(
            "Invalid challenge state transition from '{}' to '{}'",
            challenge.status, next
        )));
    }

    if next == ChallengeStatus::Blocked && reason.is_none() {
        return Err(DomainError::Validation(
            "Blocked reason is required when transitioning challenge to 'blocked' status"
                .to_string(),
        ));
    }

    challenge.status = next;
    if next == ChallengeStatus::Blocked {
        challenge.blocked_reason = reason;
    } else if next == ChallengeStatus::InProgress {
        challenge.blocked_reason = None;
    }
    challenge.updated_at = chrono::Utc::now();
    Ok(())
}

impl JobStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Interrupted
        )
    }

    pub fn can_transition_to(&self, next: &JobStatus) -> bool {
        if self == next {
            return true;
        }
        if self.is_terminal() {
            return false;
        }

        matches!(
            (self, next),
            (Self::Queued, Self::Preparing)
                | (Self::Queued, Self::Cancelled)
                | (Self::Preparing, Self::Running)
                | (Self::Preparing, Self::Failed)
                | (Self::Preparing, Self::Cancelled)
                | (Self::Running, Self::Succeeded)
                | (Self::Running, Self::Failed)
                | (Self::Running, Self::Cancelled)
                | (Self::Running, Self::TimedOut)
                | (Self::Running, Self::Interrupted)
        )
    }
}

pub fn transition_job(job: &mut Job, next: JobStatus) -> Result<(), DomainError> {
    if !job.state.can_transition_to(&next) {
        return Err(DomainError::Conflict(format!(
            "Invalid job state transition from '{}' to '{}'",
            job.state, next
        )));
    }

    job.state = next;
    let now = chrono::Utc::now();
    if next == JobStatus::Running && job.started_at.is_none() {
        job.started_at = Some(now);
    }
    if next.is_terminal() && job.completed_at.is_none() {
        job.completed_at = Some(now);
        if next == JobStatus::TimedOut {
            job.timeout_triggered = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctf::*;

    fn dummy_challenge() -> Challenge {
        Challenge {
            id: "chal-1".to_string(),
            competition_id: "comp-1".to_string(),
            name: "Test Pwn".to_string(),
            category: "pwn".to_string(),
            points: 100,
            status: ChallengeStatus::New,
            blocked_reason: None,
            target_scope: None,
            case_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn dummy_job() -> Job {
        Job {
            id: "job-1".to_string(),
            challenge_id: "chal-1".to_string(),
            tool_id: "strings".to_string(),
            adapter: "binutils".to_string(),
            runtime: JobRuntime::Native,
            state: JobStatus::Queued,
            argv: vec!["strings".to_string(), "target.bin".to_string()],
            input_refs: vec![],
            exit_code: None,
            timeout_ms: 10000,
            timeout_triggered: false,
            started_at: None,
            completed_at: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_challenge_state_transitions() {
        let mut chal = dummy_challenge();
        assert_eq!(chal.status, ChallengeStatus::New);

        // New -> InProgress
        transition_challenge(&mut chal, ChallengeStatus::InProgress, None).unwrap();
        assert_eq!(chal.status, ChallengeStatus::InProgress);

        // InProgress -> Blocked requires reason
        let err = transition_challenge(&mut chal, ChallengeStatus::Blocked, None).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));

        // InProgress -> Blocked with reason
        transition_challenge(
            &mut chal,
            ChallengeStatus::Blocked,
            Some(BlockedReason("Needs remote VPN".into())),
        )
        .unwrap();
        assert_eq!(chal.status, ChallengeStatus::Blocked);
        assert_eq!(chal.blocked_reason.as_ref().unwrap().0, "Needs remote VPN");

        // Blocked -> InProgress clears reason
        transition_challenge(&mut chal, ChallengeStatus::InProgress, None).unwrap();
        assert_eq!(chal.status, ChallengeStatus::InProgress);
        assert!(chal.blocked_reason.is_none());

        // InProgress -> Solved
        transition_challenge(&mut chal, ChallengeStatus::Solved, None).unwrap();
        assert_eq!(chal.status, ChallengeStatus::Solved);

        // Invalid: Solved cannot go directly to Blocked
        let err = transition_challenge(
            &mut chal,
            ChallengeStatus::Blocked,
            Some(BlockedReason("Invalid".into())),
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::Conflict(_)));
    }

    #[test]
    fn test_job_state_transitions() {
        let mut job = dummy_job();
        assert_eq!(job.state, JobStatus::Queued);

        // Queued -> Preparing
        transition_job(&mut job, JobStatus::Preparing).unwrap();
        assert_eq!(job.state, JobStatus::Preparing);

        // Preparing -> Running
        transition_job(&mut job, JobStatus::Running).unwrap();
        assert_eq!(job.state, JobStatus::Running);
        assert!(job.started_at.is_some());

        // Running -> Succeeded
        transition_job(&mut job, JobStatus::Succeeded).unwrap();
        assert_eq!(job.state, JobStatus::Succeeded);
        assert!(job.completed_at.is_some());

        // Terminal state cannot transition to Running
        let err = transition_job(&mut job, JobStatus::Running).unwrap_err();
        assert!(matches!(err, DomainError::Conflict(_)));
    }

    #[test]
    fn test_job_timeout_flag() {
        let mut job = dummy_job();
        transition_job(&mut job, JobStatus::Preparing).unwrap();
        transition_job(&mut job, JobStatus::Running).unwrap();
        transition_job(&mut job, JobStatus::TimedOut).unwrap();
        assert_eq!(job.state, JobStatus::TimedOut);
        assert!(job.timeout_triggered);
    }
}
