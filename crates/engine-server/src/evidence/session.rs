#![forbid(unsafe_code)]

use super::staging::StagingManager;
use super::token::{TokenManager, UploadTokenClaims};
use super::{process_committed_artifact, ArtifactProcessingResult, ParserStatus};
use chrono::Utc;
use core_domain::artifact::Artifact;
use core_domain::id::EntityId;
use ipc_protocol::ProblemDetails;
use serde::{Deserialize, Serialize};
use storage_cas::ContentAddressedStorage;
use storage_sqlite::evidence::{
    compute_custody_event_hash, ForensicCustodyEvent, IngestSessionRecord,
};
use storage_sqlite::SqliteStorage;
use tool_adapters::magic::detect_artifact_format;

const MAX_DECLARED_BYTES: u64 = 100 * 1024 * 1024 * 1024; // 100 GB
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginIngestResult {
    pub session_id: EntityId,
    pub upload_url: String,
    pub upload_token: String,
    pub chunk_size: usize,
    pub declared_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteIngestResult {
    pub session_id: EntityId,
    pub artifact_id: EntityId,
    pub status: String,
    pub format: String,
    pub sha256: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub parser_status: ParserStatus,
    pub observations_created: u64,
    pub facts_created: u64,
    pub diagnostics_created: u64,
    pub parser_name: Option<String>,
    pub parser_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatusResult {
    pub session_id: EntityId,
    pub case_id: EntityId,
    pub filename: String,
    pub declared_size_bytes: u64,
    pub bytes_received: u64,
    pub status: String,
    pub sha256: Option<String>,
    pub blake3: Option<String>,
    pub artifact_id: Option<EntityId>,
    pub error_message: Option<String>,
    pub custody_chain_valid: bool,
}

#[derive(Clone)]
pub struct IngestSessionManager {
    staging: StagingManager,
    token_mgr: TokenManager,
}

#[allow(clippy::too_many_arguments)]
fn append_custody_step(
    storage: &SqliteStorage,
    session: &IngestSessionRecord,
    artifact_id: Option<EntityId>,
    action: &str,
    sha256: &str,
    blake3: &str,
    details_hash: &str,
    details_json: serde_json::Value,
) {
    let existing = storage
        .list_custody_events_for_session(session.id)
        .unwrap_or_default();
    let next_seq = (existing.len() as u64) + 1;
    let prev_hash = existing
        .last()
        .map(|e| e.event_hash.clone())
        .unwrap_or_else(|| "GENESIS".to_string());
    let event_id = EntityId::new_v7();
    let ts = Utc::now();
    let art_str = artifact_id.map(|id| id.to_string());
    let hash = compute_custody_event_hash(
        &prev_hash,
        next_seq,
        &event_id.to_string(),
        &session.id.to_string(),
        art_str.as_deref(),
        &session.case_id.to_string(),
        action,
        &session.actor_id,
        &ts.to_rfc3339(),
        sha256,
        blake3,
        details_hash,
    );
    let event = ForensicCustodyEvent {
        event_id,
        session_id: session.id,
        artifact_id,
        case_id: session.case_id,
        sequence_no: next_seq,
        action: action.to_string(),
        actor_id: session.actor_id.clone(),
        timestamp_utc: ts,
        sha256: sha256.to_string(),
        blake3: blake3.to_string(),
        previous_event_hash: prev_hash,
        event_hash: hash,
        details_hash: details_hash.to_string(),
        details_json: details_json.to_string(),
    };
    let _ = storage.record_custody_event(&event);
}

impl IngestSessionManager {
    pub fn new(staging: StagingManager) -> Self {
        Self {
            staging,
            token_mgr: TokenManager::new(),
        }
    }

    pub fn staging(&self) -> &StagingManager {
        &self.staging
    }

    pub fn token_mgr(&self) -> &TokenManager {
        &self.token_mgr
    }

    pub async fn begin_ingest(
        &self,
        case_id: EntityId,
        filename: &str,
        declared_size_bytes: u64,
        actor_id: &str,
        storage: &SqliteStorage,
    ) -> Result<BeginIngestResult, ProblemDetails> {
        // Validate case exists
        storage
            .get_case(case_id)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?
            .ok_or_else(|| {
                ProblemDetails::bad_request("Case not found", vec!["case_id".to_string()])
            })?;

        if declared_size_bytes == 0 || declared_size_bytes > MAX_DECLARED_BYTES {
            return Err(ProblemDetails::bad_request(
                &format!("Declared size must be between 1 and {MAX_DECLARED_BYTES} bytes"),
                vec!["declared_size_bytes".to_string()],
            ));
        }

        // Sanitize filename against directory traversal
        let sanitized_name = std::path::Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artifact.bin")
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .collect::<String>();

        let session_id = EntityId::new_v7();
        let staging_path = self.staging.staging_path(session_id);

        let claims = UploadTokenClaims {
            session_id,
            case_id,
            actor_id: actor_id.to_string(),
            max_size_bytes: declared_size_bytes,
            expires_at_epoch: Utc::now().timestamp() + 86400, // 24 hours
        };

        let upload_token = self.token_mgr.generate_token(&claims);
        let token_hash = self.token_mgr.hash_token(&upload_token);

        let now = Utc::now();
        let record = IngestSessionRecord {
            id: session_id,
            case_id,
            filename: sanitized_name,
            declared_size_bytes,
            bytes_received: 0,
            staging_path: staging_path.display().to_string(),
            status: "CREATED".to_string(),
            sha256: None,
            blake3: None,
            artifact_id: None,
            actor_id: actor_id.to_string(),
            upload_token_hash: token_hash,
            error_message: None,
            created_at: now,
            updated_at: now,
        };
        storage
            .create_ingest_session(&record)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        Ok(BeginIngestResult {
            session_id,
            upload_url: format!("/ingest/{session_id}/chunk"),
            upload_token,
            chunk_size: DEFAULT_CHUNK_SIZE,
            declared_size_bytes,
        })
    }

    pub async fn write_chunk(
        &self,
        session_id: EntityId,
        token: &str,
        offset: u64,
        chunk_data: &[u8],
        storage: &SqliteStorage,
    ) -> Result<u64, ProblemDetails> {
        let claims = self
            .token_mgr
            .validate_token(token)
            .map_err(|e| ProblemDetails::unauthorized(&e))?;

        if claims.session_id != session_id {
            return Err(ProblemDetails::unauthorized("Token session mismatch"));
        }

        let mut session = storage
            .get_ingest_session(session_id)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?
            .ok_or_else(|| ProblemDetails::not_found("Ingest session not found"))?;

        if session.status != "CREATED" && session.status != "RECEIVING" {
            return Err(ProblemDetails::conflict(&format!(
                "Cannot write chunk: session is in status {}",
                session.status
            )));
        }

        // Record initial RECEIVED custody event on first chunk if status was CREATED
        if session.status == "CREATED" && offset == 0 {
            append_custody_step(
                storage,
                &session,
                None,
                "RECEIVED",
                "PENDING",
                "PENDING",
                "session_started",
                serde_json::json!({
                    "filename": session.filename,
                    "declared_size": session.declared_size_bytes,
                }),
            );
        }

        let new_len = self
            .staging
            .append_chunk(session_id, offset, session.declared_size_bytes, chunk_data)
            .await
            .map_err(|e| match e {
                super::staging::StagingError::OffsetMismatch { expected, actual } => {
                    ProblemDetails::conflict(&format!(
                        "Offset mismatch: expected {expected}, got {actual}"
                    ))
                }
                _ => ProblemDetails::bad_request(&e.to_string(), vec![]),
            })?;

        session.bytes_received = new_len;
        session.status = "RECEIVING".to_string();
        session.updated_at = Utc::now();

        storage
            .update_ingest_session(&session)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        Ok(new_len)
    }

    pub async fn complete_ingest(
        &self,
        session_id: EntityId,
        storage: &SqliteStorage,
        cas: &ContentAddressedStorage,
        correlator: &correlation_engine::DeterministicCorrelationEngine,
    ) -> Result<CompleteIngestResult, ProblemDetails> {
        let mut session = storage
            .get_ingest_session(session_id)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?
            .ok_or_else(|| ProblemDetails::not_found("Ingest session not found"))?;

        // Idempotent: if already committed, return existing artifact info
        if session.status == "COMMITTED" {
            if let Some(art) = session
                .artifact_id
                .and_then(|aid| storage.get_artifact(aid).ok().flatten())
            {
                let observations_created = storage
                    .list_observations_for_artifact(art.id)
                    .map(|values| values.len() as u64)
                    .unwrap_or(0);
                return Ok(CompleteIngestResult {
                    session_id,
                    artifact_id: art.id,
                    status: "COMMITTED".to_string(),
                    format: art.mime_type.clone(),
                    sha256: art.hash_sha256,
                    blake3: art.hash_blake3,
                    size_bytes: art.file_size,
                    parser_status: if observations_created > 0 {
                        ParserStatus::Succeeded
                    } else {
                        ParserStatus::NotApplicable
                    },
                    observations_created,
                    facts_created: 0,
                    diagnostics_created: 0,
                    parser_name: Some("PcapAdapter".to_string()),
                    parser_version: Some(tool_adapters::pcap::phase3::PARSER_VERSION.to_string()),
                });
            }
        }

        if session.status == "CANCELLED" || session.status == "FAILED" {
            return Err(ProblemDetails::conflict(&format!(
                "Session is in terminal state: {}",
                session.status
            )));
        }

        // Check declared size matches actual received bytes
        if session.bytes_received != session.declared_size_bytes {
            session.status = "FAILED".to_string();
            session.error_message = Some(format!(
                "Size mismatch: received {} bytes, declared {} bytes",
                session.bytes_received, session.declared_size_bytes
            ));
            let _ = storage.update_ingest_session(&session);
            return Err(ProblemDetails::bad_request(
                session.error_message.as_deref().unwrap_or("Size mismatch"),
                vec!["bytes_received".to_string()],
            ));
        }

        // Read magic bytes header for format detection
        let header = self
            .staging
            .read_header(session_id, 64)
            .await
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        let format = detect_artifact_format(&header);
        if !format.is_supported() {
            session.status = "QUARANTINED".to_string();
            session.error_message =
                Some("Malformed or unrecognized forensic artifact format".to_string());
            let _ = storage.update_ingest_session(&session);
            append_custody_step(
                storage,
                &session,
                None,
                "QUARANTINED",
                "NONE",
                "NONE",
                "magic_mismatch",
                serde_json::json!({ "error": "Unrecognized or malformed signature" }),
            );
            return Err(ProblemDetails::bad_request(
                "QUARANTINED: Unrecognized or malformed forensic artifact signature",
                vec!["magic_bytes".to_string()],
            ));
        }

        // Streaming dual hash calculation
        let (actual_len, sha256_hex, blake3_hex) =
            self.staging
                .scan_and_rehash(session_id)
                .await
                .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        append_custody_step(
            storage,
            &session,
            None,
            "HASHED",
            &sha256_hex,
            &blake3_hex,
            "stream_dual_hash",
            serde_json::json!({ "bytes_scanned": actual_len }),
        );
        append_custody_step(
            storage,
            &session,
            None,
            "VALIDATED",
            &sha256_hex,
            &blake3_hex,
            "signature_verified",
            serde_json::json!({ "format": format.mime_type() }),
        );

        // Atomic commit to CAS
        let staging_file = self.staging.staging_path(session_id);
        let stored_hashes = cas
            .commit_staging_file(&staging_file, &blake3_hex, &sha256_hex, actual_len)
            .await
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        // Create Artifact record in SQLite
        let artifact_id = EntityId::new_v7();
        let now = Utc::now();
        let artifact = Artifact {
            id: artifact_id,
            case_id: session.case_id,
            hash_blake3: stored_hashes.blake3.clone(),
            hash_sha256: stored_hashes.sha256.clone(),
            original_name: session.filename.clone(),
            file_size: stored_hashes.size_bytes,
            mime_type: format.mime_type().to_string(),
            acquisition_method: "StreamingUpload".to_string(),
            acquired_at: session.created_at,
            ingested_at: now,
        };

        storage
            .insert_artifact(&artifact)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        // Update IngestSession with artifact_id and COMMITTED status
        session.artifact_id = Some(artifact_id);
        session.status = "COMMITTED".to_string();
        session.sha256 = Some(stored_hashes.sha256.clone());
        session.blake3 = Some(stored_hashes.blake3.clone());
        session.updated_at = now;

        storage
            .update_ingest_session(&session)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        // Record COMMITTED_TO_CAS custody event
        append_custody_step(
            storage,
            &session,
            Some(artifact_id),
            "COMMITTED_TO_CAS",
            &stored_hashes.sha256,
            &stored_hashes.blake3,
            "cas_finalized",
            serde_json::json!({
                "format": format.default_extension(),
                "file_size": actual_len,
            }),
        );

        let processing = match process_committed_artifact(
            session.case_id,
            &artifact,
            &cas.get_path_for_blake3(&stored_hashes.blake3),
            storage,
            correlator,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => {
                tracing::error!(artifact_id = %artifact.id, error = ?error, "post-CAS artifact processing failed");
                ArtifactProcessingResult {
                    parser_status: ParserStatus::Failed,
                    observations_created: 0,
                    facts_created: 0,
                    diagnostics_created: 0,
                    parser_name: Some("PcapAdapter".to_string()),
                    parser_version: Some(tool_adapters::pcap::phase3::PARSER_VERSION.to_string()),
                }
            }
        };

        Ok(CompleteIngestResult {
            session_id,
            artifact_id,
            status: "COMMITTED".to_string(),
            format: format.default_extension().to_string(),
            sha256: stored_hashes.sha256,
            blake3: stored_hashes.blake3,
            size_bytes: stored_hashes.size_bytes,
            parser_status: processing.parser_status,
            observations_created: processing.observations_created,
            facts_created: processing.facts_created,
            diagnostics_created: processing.diagnostics_created,
            parser_name: processing.parser_name,
            parser_version: processing.parser_version,
        })
    }

    pub async fn cancel_ingest(
        &self,
        session_id: EntityId,
        storage: &SqliteStorage,
    ) -> Result<serde_json::Value, ProblemDetails> {
        let mut session = storage
            .get_ingest_session(session_id)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?
            .ok_or_else(|| ProblemDetails::not_found("Ingest session not found"))?;

        if session.status == "COMMITTED" {
            return Err(ProblemDetails::conflict(
                "Cannot cancel committed evidence artifact; forensic immutability invariant",
            ));
        }

        self.staging.delete_staging(session_id).await;
        session.status = "CANCELLED".to_string();
        session.updated_at = Utc::now();

        storage
            .update_ingest_session(&session)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?;

        Ok(serde_json::json!({
            "session_id": session_id,
            "status": "CANCELLED"
        }))
    }

    pub async fn get_status(
        &self,
        session_id: EntityId,
        storage: &SqliteStorage,
    ) -> Result<SessionStatusResult, ProblemDetails> {
        let session = storage
            .get_ingest_session(session_id)
            .map_err(|e| ProblemDetails::internal_error(&e.to_string()))?
            .ok_or_else(|| ProblemDetails::not_found("Ingest session not found"))?;

        let custody_valid = storage
            .verify_session_custody_chain(session_id)
            .unwrap_or(false);

        Ok(SessionStatusResult {
            session_id,
            case_id: session.case_id,
            filename: session.filename,
            declared_size_bytes: session.declared_size_bytes,
            bytes_received: session.bytes_received,
            status: session.status,
            sha256: session.sha256,
            blake3: session.blake3,
            artifact_id: session.artifact_id,
            error_message: session.error_message,
            custody_chain_valid: custody_valid,
        })
    }
}
