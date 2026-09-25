#![forbid(unsafe_code)]

use core_domain::ctf::*;
use core_domain::error::DomainError;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Competitions DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetitionCreateReq {
    pub name: String,
    pub description: Option<String>,
    pub flag_format: Option<String>,
    pub format: Option<String>,
}

impl CompetitionCreateReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        let trimmed = self.name.trim();
        if trimmed.is_empty() || trimmed.len() > 120 {
            return Err(DomainError::Validation(
                "Competition name must be between 1 and 120 characters".to_string(),
            ));
        }
        if let Some(ref pattern) = self.flag_format {
            Regex::new(pattern)
                .map_err(|e| DomainError::Validation(format!("Invalid flag format regex: {e}")))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetitionGetReq {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompetitionListReq {
    pub status: Option<String>,
}

// ---------------------------------------------------------------------------
// Challenges DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetScopeDto {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub in_scope: Option<bool>,
}

impl From<TargetScopeDto> for TargetScope {
    fn from(dto: TargetScopeDto) -> Self {
        Self {
            host: dto.host,
            port: dto.port,
            protocol: dto.protocol.unwrap_or_else(|| "tcp".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeCreateReq {
    pub competition_id: String,
    pub name: String,
    pub category: String,
    pub points: Option<u32>,
    pub target: Option<TargetScopeDto>,
}

impl ChallengeCreateReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.competition_id.trim().is_empty() {
            return Err(DomainError::Validation(
                "competition_id cannot be empty".to_string(),
            ));
        }
        let trimmed = self.name.trim();
        if trimmed.is_empty() || trimmed.len() > 120 {
            return Err(DomainError::Validation(
                "Challenge name must be between 1 and 120 characters".to_string(),
            ));
        }
        let cat = self.category.trim().to_lowercase();
        let valid_categories = [
            "crypto",
            "pwn",
            "web",
            "rev",
            "reverse",
            "forensics",
            "misc",
            "osint",
            "stego",
            "network",
        ];
        if !valid_categories.contains(&cat.as_str()) {
            return Err(DomainError::Validation(format!(
                "Invalid category '{cat}'. Valid categories: crypto, pwn, web, rev, reverse, forensics, misc, osint, stego, network"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeGetReq {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeListReq {
    pub competition_id: String,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeUpdateStatusReq {
    pub id: String,
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeUpdateTargetReq {
    pub id: String,
    pub target: TargetScopeDto,
}

// ---------------------------------------------------------------------------
// Artifacts DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSliceReq {
    pub artifact_id: String,
    pub offset: u64,
    pub length: usize,
}

impl ArtifactSliceReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.artifact_id.trim().is_empty() {
            return Err(DomainError::Validation(
                "artifact_id cannot be empty".to_string(),
            ));
        }
        if self.length == 0 || self.length > 65536 {
            return Err(DomainError::Validation(format!(
                "Slice length must be between 1 and 65536 bytes, got {}",
                self.length
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactVerifyReq {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactUnpackReq {
    pub artifact_id: String,
    pub target_dir: String,
}

impl ArtifactUnpackReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.artifact_id.trim().is_empty() {
            return Err(DomainError::Validation(
                "artifact_id cannot be empty".to_string(),
            ));
        }
        if self.target_dir.trim().is_empty() {
            return Err(DomainError::Validation(
                "target_dir cannot be empty".to_string(),
            ));
        }
        if self.target_dir.contains("..") {
            return Err(DomainError::SecurityViolation(
                "Path traversal (..) in target_dir is prohibited".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLinkChallengeReq {
    pub challenge_id: String,
    pub artifact_id: String,
    pub role: Option<String>,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactListForChallengeReq {
    pub challenge_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactIngestReq {
    pub data_base64: String,
    pub filename: Option<String>,
    pub challenge_id: Option<String>,
    pub role: Option<String>,
}

impl ArtifactIngestReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.data_base64.trim().is_empty() {
            return Err(DomainError::Validation(
                "data_base64 cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tools DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub supported_extensions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Jobs DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitsDto {
    pub max_memory_mb: Option<u64>,
    pub max_cpu_percent: Option<u32>,
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSubmitReq {
    pub challenge_id: String,
    pub tool_id: String,
    pub adapter: Option<String>,
    pub argv: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub limits: Option<ResourceLimitsDto>,
}

impl JobSubmitReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.challenge_id.trim().is_empty() {
            return Err(DomainError::Validation(
                "challenge_id cannot be empty".to_string(),
            ));
        }
        if self.tool_id.trim().is_empty() {
            return Err(DomainError::Validation(
                "tool_id cannot be empty".to_string(),
            ));
        }
        validate_zero_shell_argv(&self.argv)?;

        let disallowed_shells = [
            "sh",
            "bash",
            "zsh",
            "cmd",
            "cmd.exe",
            "powershell",
            "powershell.exe",
            "pwsh",
        ];
        if let Some(prog) = self.argv.first() {
            let p_lower = prog.to_lowercase();
            let base = std::path::Path::new(&p_lower)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&p_lower);
            if disallowed_shells.contains(&base) {
                return Err(DomainError::SecurityViolation(format!(
                    "Direct shell invocation prohibited by SEC-ARCH-01: {base}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCancelReq {
    pub id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStateReq {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobOutputReq {
    pub id: String,
    pub max_bytes: Option<usize>,
}

// ---------------------------------------------------------------------------
// Recipes DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipePreviewReq {
    pub input_data: Option<String>,
    pub input_base64: Option<String>,
    pub ops: Vec<RecipeOp>,
    pub flag_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeExecuteReq {
    pub artifact_id: String,
    pub ops: Vec<RecipeOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeSaveStepReq {
    pub challenge_id: String,
    pub recipe_id: Option<String>,
    pub step_order: u32,
    pub operation: String,
    pub parameters_json: Option<String>,
    pub input_artifact_id: Option<String>,
    pub output_artifact_id: Option<String>,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeListStepsReq {
    pub challenge_id: String,
    pub recipe_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Flags DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagRegisterReq {
    pub challenge_id: String,
    pub value: String,
    pub source_ref: String,
}

impl FlagRegisterReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.challenge_id.trim().is_empty() {
            return Err(DomainError::Validation(
                "challenge_id cannot be empty".to_string(),
            ));
        }
        if self.value.trim().is_empty() {
            return Err(DomainError::Validation(
                "Flag value cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagAcceptReq {
    pub candidate_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagRejectReq {
    pub candidate_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagListReq {
    pub challenge_id: String,
}

// ---------------------------------------------------------------------------
// Writeups DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteupGenerateReq {
    pub challenge_id: String,
    pub include_timeline: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteupExportReq {
    pub challenge_id: String,
    pub dest_path: String,
}

impl WriteupExportReq {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.challenge_id.trim().is_empty() {
            return Err(DomainError::Validation(
                "challenge_id cannot be empty".to_string(),
            ));
        }
        if self.dest_path.trim().is_empty() {
            return Err(DomainError::Validation(
                "dest_path cannot be empty".to_string(),
            ));
        }
        if self.dest_path.contains("..") {
            return Err(DomainError::SecurityViolation(
                "Path traversal in dest_path is prohibited".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteupUpdateSectionReq {
    pub challenge_id: String,
    pub section: String,
    pub content: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_competition_req_validation() {
        let valid = CompetitionCreateReq {
            name: "DefCamp 2026".to_string(),
            description: Some("CTF".to_string()),
            flag_format: Some(r"flag\{[a-z0-9]+\}".to_string()),
            format: None,
        };
        assert!(valid.validate().is_ok());

        let empty = CompetitionCreateReq {
            name: "".to_string(),
            description: None,
            flag_format: None,
            format: None,
        };
        assert!(empty.validate().is_err());

        let bad_regex = CompetitionCreateReq {
            name: "Valid".to_string(),
            description: None,
            flag_format: Some("[unclosed".to_string()),
            format: None,
        };
        assert!(bad_regex.validate().is_err());
    }

    #[test]
    fn test_challenge_req_validation() {
        let valid = ChallengeCreateReq {
            competition_id: "comp-1".to_string(),
            name: "Crypto 101".to_string(),
            category: "crypto".to_string(),
            points: Some(100),
            target: None,
        };
        assert!(valid.validate().is_ok());

        let bad_cat = ChallengeCreateReq {
            competition_id: "comp-1".to_string(),
            name: "Crypto 101".to_string(),
            category: "invalid_category".to_string(),
            points: Some(100),
            target: None,
        };
        assert!(bad_cat.validate().is_err());
    }

    #[test]
    fn test_artifact_slice_bounds() {
        let req = ArtifactSliceReq {
            artifact_id: "art-1".to_string(),
            offset: 0,
            length: 65536,
        };
        assert!(req.validate().is_ok());

        let req_too_big = ArtifactSliceReq {
            artifact_id: "art-1".to_string(),
            offset: 0,
            length: 65537,
        };
        assert!(req_too_big.validate().is_err());
    }

    #[test]
    fn test_job_submit_zero_shell_validation() {
        let shell_req = JobSubmitReq {
            challenge_id: "chal-1".to_string(),
            tool_id: "sh".to_string(),
            adapter: None,
            argv: vec!["sh".to_string(), "-c".to_string(), "whoami".to_string()],
            timeout_ms: None,
            limits: None,
        };
        assert!(matches!(
            shell_req.validate().unwrap_err(),
            DomainError::SecurityViolation(_)
        ));

        let valid_tool = JobSubmitReq {
            challenge_id: "chal-1".to_string(),
            tool_id: "strings".to_string(),
            adapter: None,
            argv: vec![
                "strings".to_string(),
                "-a".to_string(),
                "sample.bin".to_string(),
            ],
            timeout_ms: Some(5000),
            limits: None,
        };
        assert!(valid_tool.validate().is_ok());
    }
}
