use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type CompetitionId = String;
pub type ChallengeId = String;
pub type ArtifactId = String;
pub type Blake3Hash = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompetitionStatus {
    Draft,
    #[default]
    Active,
    Paused,
    Completed,
    Archived,
}

impl std::fmt::Display for CompetitionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Archived => write!(f, "archived"),
        }
    }
}

impl std::str::FromStr for CompetitionStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "draft" => Ok(Self::Draft),
            "active" => Ok(Self::Active),
            "paused" => Ok(Self::Paused),
            "completed" => Ok(Self::Completed),
            "archived" => Ok(Self::Archived),
            _ => Err(format!("Unknown competition status: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompetitionFormat {
    #[default]
    Jeopardy,
    AttackDefense,
    Mixed,
    AdHoc,
}

impl std::fmt::Display for CompetitionFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jeopardy => write!(f, "jeopardy"),
            Self::AttackDefense => write!(f, "attack_defense"),
            Self::Mixed => write!(f, "mixed"),
            Self::AdHoc => write!(f, "ad_hoc"),
        }
    }
}

impl std::str::FromStr for CompetitionFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "jeopardy" => Ok(Self::Jeopardy),
            "attack_defense" => Ok(Self::AttackDefense),
            "mixed" => Ok(Self::Mixed),
            "ad_hoc" => Ok(Self::AdHoc),
            _ => Err(format!("Unknown competition format: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Competition {
    pub id: CompetitionId,
    pub name: String,
    pub description: Option<String>,
    pub format: CompetitionFormat,
    pub flag_format_regex: Option<String>,
    pub start_at: Option<DateTime<Utc>>,
    pub end_at: Option<DateTime<Utc>>,
    pub status: CompetitionStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompetitionSummary {
    pub id: CompetitionId,
    pub name: String,
    pub format: CompetitionFormat,
    pub status: CompetitionStatus,
    pub challenge_count: usize,
    pub solved_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCompetitionCmd {
    pub name: String,
    pub description: Option<String>,
    pub format: Option<CompetitionFormat>,
    pub flag_format_regex: Option<String>,
    pub start_at: Option<DateTime<Utc>>,
    pub end_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeCategory {
    Web,
    Pwn,
    Reverse,
    Crypto,
    Forensics,
    Misc,
    Osint,
    Stego,
    Network,
}

impl std::fmt::Display for ChallengeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Web => write!(f, "web"),
            Self::Pwn => write!(f, "pwn"),
            Self::Reverse => write!(f, "reverse"),
            Self::Crypto => write!(f, "crypto"),
            Self::Forensics => write!(f, "forensics"),
            Self::Misc => write!(f, "misc"),
            Self::Osint => write!(f, "osint"),
            Self::Stego => write!(f, "stego"),
            Self::Network => write!(f, "network"),
        }
    }
}

impl std::str::FromStr for ChallengeCategory {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "web" => Ok(Self::Web),
            "pwn" => Ok(Self::Pwn),
            "reverse" | "rev" => Ok(Self::Reverse),
            "crypto" => Ok(Self::Crypto),
            "forensics" => Ok(Self::Forensics),
            "misc" => Ok(Self::Misc),
            "osint" => Ok(Self::Osint),
            "stego" => Ok(Self::Stego),
            "network" => Ok(Self::Network),
            _ => Err(format!("Unknown challenge category: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    #[default]
    New,
    InProgress,
    Blocked,
    Solved,
    Archived,
}

impl std::fmt::Display for ChallengeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Blocked => write!(f, "blocked"),
            Self::Solved => write!(f, "solved"),
            Self::Archived => write!(f, "archived"),
        }
    }
}

impl std::str::FromStr for ChallengeStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "new" => Ok(Self::New),
            "in_progress" => Ok(Self::InProgress),
            "blocked" => Ok(Self::Blocked),
            "solved" => Ok(Self::Solved),
            "archived" => Ok(Self::Archived),
            _ => Err(format!("Unknown challenge status: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedReason(pub String);

impl std::fmt::Display for BlockedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetScope {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: String,
}

impl Default for TargetScope {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: None,
            protocol: "tcp".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub id: ChallengeId,
    pub competition_id: CompetitionId,
    pub name: String,
    pub category: String,
    pub points: u32,
    pub status: ChallengeStatus,
    pub blocked_reason: Option<BlockedReason>,
    pub target_scope: Option<TargetScope>,
    pub case_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeSummary {
    pub id: ChallengeId,
    pub competition_id: CompetitionId,
    pub name: String,
    pub category: String,
    pub points: u32,
    pub status: ChallengeStatus,
    pub has_target: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeDetails {
    pub challenge: Challenge,
    pub artifacts: Vec<ChallengeArtifact>,
    pub active_jobs: usize,
    pub candidate_flags_count: usize,
    pub accepted_flag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateChallengeCmd {
    pub competition_id: CompetitionId,
    pub name: String,
    pub category: String,
    pub points: Option<u32>,
    pub target: Option<TargetScope>,
    pub expected_flag: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    #[default]
    Input,
    Extracted,
    Transformed,
    MemoryDump,
    Pcaps,
    Evidence,
    Scratch,
}

impl std::fmt::Display for ArtifactRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input => write!(f, "input"),
            Self::Extracted => write!(f, "extracted"),
            Self::Transformed => write!(f, "transformed"),
            Self::MemoryDump => write!(f, "memory_dump"),
            Self::Pcaps => write!(f, "pcaps"),
            Self::Evidence => write!(f, "evidence"),
            Self::Scratch => write!(f, "scratch"),
        }
    }
}

impl std::str::FromStr for ArtifactRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "input" => Ok(Self::Input),
            "extracted" => Ok(Self::Extracted),
            "transformed" => Ok(Self::Transformed),
            "memory_dump" => Ok(Self::MemoryDump),
            "pcaps" => Ok(Self::Pcaps),
            "evidence" => Ok(Self::Evidence),
            "scratch" => Ok(Self::Scratch),
            _ => Err(format!("Unknown artifact role: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeArtifact {
    pub id: String,
    pub challenge_id: ChallengeId,
    pub artifact_id: ArtifactId,
    pub role: ArtifactRole,
    pub alias: Option<String>,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestMetadata {
    pub original_name: String,
    pub mime_type: Option<String>,
    pub case_id: Option<String>,
    pub challenge_id: Option<ChallengeId>,
    pub role: Option<ArtifactRole>,
    pub alias: Option<String>,
}
