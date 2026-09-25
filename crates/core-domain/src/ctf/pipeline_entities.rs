use super::entities::{ArtifactId, ChallengeId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type JobId = String;
pub type RecipeId = String;
pub type CandidateId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRuntime {
    Native,
    Wsl2,
    Container,
    Microvm,
}

impl Default for JobRuntime {
    fn default() -> Self {
        Self::Native
    }
}

impl std::fmt::Display for JobRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native => write!(f, "native"),
            Self::Wsl2 => write!(f, "wsl2"),
            Self::Container => write!(f, "container"),
            Self::Microvm => write!(f, "microvm"),
        }
    }
}

impl std::str::FromStr for JobRuntime {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "native" => Ok(Self::Native),
            "wsl2" => Ok(Self::Wsl2),
            "container" => Ok(Self::Container),
            "microvm" => Ok(Self::Microvm),
            _ => Err(format!("Unknown job runtime: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Preparing,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Interrupted,
}

impl Default for JobStatus {
    fn default() -> Self {
        Self::Queued
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Preparing => write!(f, "preparing"),
            Self::Running => write!(f, "running"),
            Self::Succeeded => write!(f, "succeeded"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::TimedOut => write!(f, "timed_out"),
            Self::Interrupted => write!(f, "interrupted"),
        }
    }
}

impl std::str::FromStr for JobStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "queued" => Ok(Self::Queued),
            "preparing" => Ok(Self::Preparing),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "timed_out" => Ok(Self::TimedOut),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(format!("Unknown job status: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_bytes: Option<u64>,
    pub max_cpu_percent: Option<u32>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    pub challenge_id: ChallengeId,
    pub tool_id: String,
    pub adapter: Option<String>,
    pub argv: Vec<String>,
    pub input_refs: Option<Vec<String>>,
    pub timeout_ms: Option<u64>,
    pub runtime: Option<JobRuntime>,
    pub limits: Option<ResourceLimits>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: JobId,
    pub challenge_id: ChallengeId,
    pub tool_id: String,
    pub adapter: String,
    pub runtime: JobRuntime,
    pub state: JobStatus,
    pub argv: Vec<String>,
    pub input_refs: Vec<String>,
    pub exit_code: Option<i32>,
    pub timeout_ms: u64,
    pub timeout_triggered: bool,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRuntimeState {
    pub id: JobId,
    pub challenge_id: ChallengeId,
    pub tool_id: String,
    pub status: JobStatus,
    pub exit_code: Option<i32>,
    pub elapsed_ms: u64,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OutputTail {
    pub head: String,
    pub tail: String,
    pub dropped_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformStep {
    pub id: String,
    pub challenge_id: ChallengeId,
    pub recipe_id: Option<RecipeId>,
    pub step_order: u32,
    pub operation: String,
    pub parameters_json: String,
    pub input_artifact_id: Option<ArtifactId>,
    pub output_artifact_id: Option<ArtifactId>,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipeOp {
    HexDecode,
    HexEncode,
    Base64Decode,
    Base64Encode,
    Xor { key: Vec<u8> },
    Rot13,
    ZlibDecompress,
    ZlibCompress,
    UrlDecode,
    UrlEncode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipePreview {
    pub input_sample: String,
    pub output_sample: String,
    pub input_len: usize,
    pub output_len: usize,
    pub detected_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeMeta {
    pub id: RecipeId,
    pub name: String,
    pub step_count: usize,
    pub ops_summary: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Candidate,
    Accepted,
    Rejected,
}

impl Default for VerificationStatus {
    fn default() -> Self {
        Self::Candidate
    }
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Candidate => write!(f, "candidate"),
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

impl std::str::FromStr for VerificationStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "candidate" => Ok(Self::Candidate),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            _ => Err(format!("Unknown verification status: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlagCandidate {
    pub id: CandidateId,
    pub challenge_id: ChallengeId,
    pub value: String,
    pub provenance_run_id: Option<JobId>,
    pub provenance_artifact_id: Option<ArtifactId>,
    pub provenance_step_id: Option<String>,
    pub pattern_match: Option<String>,
    pub verification_status: VerificationStatus,
    pub rejection_reason: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub submitted_to_platform: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Writeup {
    pub id: String,
    pub challenge_id: ChallengeId,
    pub markdown_content: String,
    pub exported_version: u32,
    pub summary: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub challenge_id: Option<ChallengeId>,
    pub key_name: String,
    pub masked_placeholder: String,
    pub ciphertext_ref: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
