use super::entities::*;
use super::pipeline_entities::*;
use crate::error::DomainError;
use async_trait::async_trait;
use std::path::Path;

#[async_trait]
pub trait WorkspaceService: Send + Sync {
    async fn create_competition(
        &self,
        cmd: CreateCompetitionCmd,
    ) -> Result<CompetitionId, DomainError>;
    async fn get_competition(&self, id: &CompetitionId) -> Result<Competition, DomainError>;
    async fn list_competitions(
        &self,
        filter: Option<CompetitionStatus>,
    ) -> Result<Vec<CompetitionSummary>, DomainError>;
    async fn create_challenge(&self, cmd: CreateChallengeCmd) -> Result<ChallengeId, DomainError>;
    async fn get_challenge(&self, id: &ChallengeId) -> Result<ChallengeDetails, DomainError>;
    async fn list_challenges(
        &self,
        comp_id: &CompetitionId,
        cat: Option<String>,
    ) -> Result<Vec<ChallengeSummary>, DomainError>;
    async fn update_challenge_status(
        &self,
        id: &ChallengeId,
        status: ChallengeStatus,
        reason: Option<BlockedReason>,
    ) -> Result<(), DomainError>;
    async fn update_challenge_target(
        &self,
        id: &ChallengeId,
        target: TargetScope,
    ) -> Result<(), DomainError>;
}

#[async_trait]
pub trait CasStorageService: Send + Sync {
    async fn store_stream<R: tokio::io::AsyncRead + Unpin + Send>(
        &self,
        reader: R,
        meta: IngestMetadata,
    ) -> Result<ArtifactId, DomainError>;
    async fn read_slice(
        &self,
        hash: &Blake3Hash,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, DomainError>;
    async fn verify_integrity(&self, hash: &Blake3Hash) -> Result<bool, DomainError>;
    async fn unpack_archive_safe(
        &self,
        artifact_id: &ArtifactId,
        target_dir: &Path,
    ) -> Result<Vec<ArtifactId>, DomainError>;
}

#[async_trait]
pub trait JobEngineService: Send + Sync {
    async fn submit_job(&self, spec: JobSpec) -> Result<JobId, DomainError>;
    async fn cancel_job(&self, id: &JobId, reason: Option<String>) -> Result<(), DomainError>;
    async fn get_job_state(&self, id: &JobId) -> Result<JobRuntimeState, DomainError>;
    async fn get_output_tail(
        &self,
        id: &JobId,
        max_bytes: usize,
    ) -> Result<OutputTail, DomainError>;
}

#[async_trait]
pub trait RecipeService: Send + Sync {
    fn preview(&self, input: &[u8], ops: &[RecipeOp]) -> Result<RecipePreview, DomainError>;
    async fn execute_pipeline(
        &self,
        artifact_id: &ArtifactId,
        ops: &[RecipeOp],
    ) -> Result<ArtifactId, DomainError>;
    async fn save_recipe(
        &self,
        chal_id: &ChallengeId,
        name: String,
        ops: Vec<RecipeOp>,
    ) -> Result<RecipeId, DomainError>;
    async fn list_recipes(&self, chal_id: &ChallengeId) -> Result<Vec<RecipeMeta>, DomainError>;
}

#[async_trait]
pub trait FlagService: Send + Sync {
    async fn register_candidate(
        &self,
        chal_id: &ChallengeId,
        value: String,
        source_ref: String,
    ) -> Result<CandidateId, DomainError>;
    async fn accept_flag(&self, candidate_id: &CandidateId) -> Result<bool, DomainError>;
    async fn reject_flag(
        &self,
        candidate_id: &CandidateId,
        reason: Option<String>,
    ) -> Result<(), DomainError>;
    async fn list_flags(&self, chal_id: &ChallengeId) -> Result<Vec<FlagCandidate>, DomainError>;
}

#[async_trait]
pub trait WriteupService: Send + Sync {
    async fn generate_draft(
        &self,
        chal_id: &ChallengeId,
        include_timeline: bool,
    ) -> Result<String, DomainError>;
    async fn export_markdown(
        &self,
        chal_id: &ChallengeId,
        dest_path: &Path,
    ) -> Result<u64, DomainError>;
    async fn update_section(
        &self,
        chal_id: &ChallengeId,
        section: String,
        content: String,
    ) -> Result<(), DomainError>;
}
