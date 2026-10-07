#![forbid(unsafe_code)]

use crate::EngineApp;
use core_domain::ctf::*;
use core_domain::error::DomainError;
use ipc_protocol::*;
use serde_json::json;
use std::path::Path;
use std::str::FromStr;

pub async fn handle_ctf_command(
    app: &EngineApp,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, DomainError> {
    match method {
        // Competitions
        "competitions.create" => {
            let req: CompetitionCreateReq = serde_json::from_value(params).map_err(|e| {
                DomainError::Validation(format!("Invalid CompetitionCreateReq: {e}"))
            })?;
            req.validate()?;
            let format = req
                .format
                .and_then(|f| CompetitionFormat::from_str(&f).ok())
                .unwrap_or(CompetitionFormat::Jeopardy);
            let cmd = CreateCompetitionCmd {
                name: req.name,
                description: req.description,
                format: Some(format),
                flag_format_regex: req.flag_format,
                start_at: None,
                end_at: None,
            };
            let comp_id = app.storage.create_competition(cmd).await?;
            Ok(json!({ "id": comp_id, "competition_id": comp_id }))
        }
        "competitions.get" => {
            let req: CompetitionGetReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid CompetitionGetReq: {e}")))?;
            if req.id.trim().is_empty() {
                return Err(DomainError::Validation("id cannot be empty".to_string()));
            }
            let comp = app.storage.get_competition(&req.id).await?;
            Ok(json!(comp))
        }
        "competitions.list" => {
            let req: CompetitionListReq = serde_json::from_value(params).unwrap_or_default();
            let filter = req
                .status
                .and_then(|s| CompetitionStatus::from_str(&s).ok());
            let list = app.storage.list_competitions(filter).await?;
            Ok(json!(list))
        }

        // Challenges
        "challenges.create" => {
            let req: ChallengeCreateReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid ChallengeCreateReq: {e}")))?;
            req.validate()?;
            let category =
                ChallengeCategory::from_str(&req.category).unwrap_or(ChallengeCategory::Misc);
            let cmd = CreateChallengeCmd {
                competition_id: req.competition_id,
                name: req.name,
                category: category.to_string(),
                points: req.points,
                target: req.target.map(TargetScope::from),
                expected_flag: req.expected_flag,
            };
            let chal_id = app.storage.create_challenge(cmd).await?;
            Ok(json!({ "id": chal_id, "challenge_id": chal_id }))
        }
        "challenges.get" => {
            let req: ChallengeGetReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid ChallengeGetReq: {e}")))?;
            if req.id.trim().is_empty() {
                return Err(DomainError::Validation("id cannot be empty".to_string()));
            }
            let details = app.storage.get_challenge(&req.id).await?;
            Ok(json!(details))
        }
        "challenges.list" => {
            let req: ChallengeListReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid ChallengeListReq: {e}")))?;
            let list = app
                .storage
                .list_challenges(&req.competition_id, req.category)
                .await?;
            Ok(json!(list))
        }
        "challenges.update_status" => {
            let req: ChallengeUpdateStatusReq = serde_json::from_value(params).map_err(|e| {
                DomainError::Validation(format!("Invalid ChallengeUpdateStatusReq: {e}"))
            })?;
            let status = ChallengeStatus::from_str(&req.status).map_err(DomainError::Validation)?;
            let reason = req.reason.map(BlockedReason);
            app.storage
                .update_challenge_status(&req.id, status, reason)
                .await?;
            Ok(json!({ "updated": true, "status": status.to_string() }))
        }
        "challenges.update_target" => {
            let req: ChallengeUpdateTargetReq = serde_json::from_value(params).map_err(|e| {
                DomainError::Validation(format!("Invalid ChallengeUpdateTargetReq: {e}"))
            })?;
            let target = TargetScope::from(req.target);
            app.storage.update_challenge_target(&req.id, target).await?;
            Ok(json!({ "updated": true }))
        }

        // Artifacts
        "artifacts.get_slice" => {
            let req: ArtifactSliceReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid ArtifactSliceReq: {e}")))?;
            req.validate()?;
            let bytes = app
                .cas
                .read_slice(&req.artifact_id, req.offset, req.length)
                .await?;
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
            Ok(json!({
                "artifact_id": req.artifact_id,
                "offset": req.offset,
                "length": bytes.len(),
                "bytes_base64": b64,
            }))
        }
        "artifacts.verify" => {
            let req: ArtifactVerifyReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid ArtifactVerifyReq: {e}")))?;
            let valid = app.cas.verify_integrity(&req.hash).await?;
            Ok(json!({ "hash": req.hash, "valid": valid }))
        }
        "artifacts.unpack_archive" => {
            let req: ArtifactUnpackReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid ArtifactUnpackReq: {e}")))?;
            req.validate()?;
            let ids = app
                .cas
                .unpack_archive_safe(&req.artifact_id, Path::new(&req.target_dir))
                .await?;
            Ok(json!({ "artifact_ids": ids }))
        }
        "artifacts.ingest" => {
            let req: ArtifactIngestReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid ArtifactIngestReq: {e}")))?;
            req.validate()?;
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &req.data_base64,
            )
            .map_err(|e| DomainError::Validation(format!("Invalid base64 payload: {e}")))?;
            let stored = app
                .cas
                .store_bytes(&bytes)
                .await
                .map_err(|e| DomainError::Storage(format!("CAS store error: {e}")))?;
            let fname = req.filename.as_deref().unwrap_or("artifact.bin");
            let _ = app.storage.register_artifact(
                &stored.blake3,
                fname,
                &stored.blake3,
                &stored.sha256,
                stored.size_bytes,
                None,
            );
            let mut link_id = None;
            if let Some(ref chal_id) = req.challenge_id {
                let role = req
                    .role
                    .as_deref()
                    .and_then(|r| ArtifactRole::from_str(r).ok())
                    .unwrap_or(ArtifactRole::Input);
                let ca = app.storage.add_challenge_artifact(
                    chal_id,
                    &stored.blake3,
                    role,
                    Some(fname),
                )?;
                link_id = Some(ca);
            }
            Ok(json!({
                "artifact_id": stored.blake3,
                "blake3": stored.blake3,
                "sha256": stored.sha256,
                "size_bytes": stored.size_bytes,
                "challenge_artifact_id": link_id,
            }))
        }
        "artifacts.link_challenge" => {
            let req: ArtifactLinkChallengeReq = serde_json::from_value(params).map_err(|e| {
                DomainError::Validation(format!("Invalid ArtifactLinkChallengeReq: {e}"))
            })?;
            let role = req
                .role
                .as_deref()
                .and_then(|r| ArtifactRole::from_str(r).ok())
                .unwrap_or(ArtifactRole::Input);
            let _ = app.storage.register_artifact(
                &req.artifact_id,
                req.alias.as_deref().unwrap_or("artifact.bin"),
                &req.artifact_id,
                "",
                0,
                None,
            );
            let id = app.storage.add_challenge_artifact(
                &req.challenge_id,
                &req.artifact_id,
                role,
                req.alias.as_deref(),
            )?;
            Ok(json!({ "id": id }))
        }
        "artifacts.list_for_challenge" => {
            let req: ArtifactListForChallengeReq = serde_json::from_value(params).map_err(|e| {
                DomainError::Validation(format!("Invalid ArtifactListForChallengeReq: {e}"))
            })?;
            let list = app.storage.list_challenge_artifacts(&req.challenge_id)?;
            Ok(json!(list))
        }

        // Tools
        "tools.list" => {
            let tools = vec![
                ToolInfo {
                    id: "evtx_parser".to_string(),
                    name: "Windows EVTX Log Parser".to_string(),
                    version: "1.0.0".to_string(),
                    description: Some("Forensic parser for Windows XML Event Logs".to_string()),
                    supported_extensions: vec!["evtx".to_string()],
                },
                ToolInfo {
                    id: "pcap_parser".to_string(),
                    name: "Packet Capture Analyzer".to_string(),
                    version: "1.0.0".to_string(),
                    description: Some(
                        "Deep network packet inspector and flow reassembler".to_string(),
                    ),
                    supported_extensions: vec![
                        "pcap".to_string(),
                        "pcapng".to_string(),
                        "cap".to_string(),
                    ],
                },
                ToolInfo {
                    id: "host_discovery".to_string(),
                    name: "Host & Asset Discovery".to_string(),
                    version: "1.0.0".to_string(),
                    description: Some("Host and service discovery scanner".to_string()),
                    supported_extensions: vec!["json".to_string(), "xml".to_string()],
                },
                ToolInfo {
                    id: "strings".to_string(),
                    name: "Binary Strings Extractor".to_string(),
                    version: "2.40".to_string(),
                    description: Some("Extract printable strings from binary payloads".to_string()),
                    supported_extensions: vec!["*".to_string()],
                },
            ];
            Ok(json!(tools))
        }

        // Jobs
        "jobs.submit" => {
            let req: JobSubmitReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid JobSubmitReq: {e}")))?;
            req.validate()?;
            let limits = req.limits.map(|l| ResourceLimits {
                max_memory_bytes: l.max_memory_mb.map(|mb| mb * 1024 * 1024),
                max_cpu_percent: l.max_cpu_percent,
                timeout_ms: req.timeout_ms,
            });
            let spec = JobSpec {
                challenge_id: req.challenge_id.clone(),
                tool_id: req.tool_id.clone(),
                adapter: req.adapter.clone(),
                argv: req.argv.clone(),
                input_refs: None,
                timeout_ms: req.timeout_ms,
                runtime: Some(JobRuntime::Native),
                limits,
            };
            let job_id = app.job_engine.submit_job(spec).await?;
            let job = Job {
                id: job_id.clone(),
                challenge_id: req.challenge_id,
                tool_id: req.tool_id,
                adapter: req.adapter.unwrap_or_else(|| "native".to_string()),
                runtime: JobRuntime::Native,
                state: JobStatus::Running,
                argv: req.argv,
                input_refs: vec![],
                exit_code: None,
                timeout_ms: req.timeout_ms.unwrap_or(60_000),
                timeout_triggered: false,
                started_at: Some(chrono::Utc::now()),
                completed_at: None,
                created_at: chrono::Utc::now(),
            };
            let _ = app.storage.insert_job(&job);
            Ok(json!({ "id": job_id, "job_id": job_id, "status": "running" }))
        }
        "jobs.cancel" => {
            let req: JobCancelReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid JobCancelReq: {e}")))?;
            app.job_engine
                .cancel_job(&req.id, req.reason.clone())
                .await?;
            let _ = app
                .storage
                .update_job_state(&req.id, JobStatus::Cancelled, None);
            Ok(json!({ "cancelled": true }))
        }
        "jobs.get_state" => {
            let req: JobStateReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid JobStateReq: {e}")))?;
            let state = app.job_engine.get_job_state(&req.id).await?;
            if state.status.is_terminal() {
                let _ = app
                    .storage
                    .update_job_state(&req.id, state.status, state.exit_code);
            }
            Ok(json!(state))
        }
        "jobs.get_output" => {
            let req: JobOutputReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid JobOutputReq: {e}")))?;
            let max_bytes = req.max_bytes.unwrap_or(8192);
            let tail = app.job_engine.get_output_tail(&req.id, max_bytes).await?;
            Ok(json!(tail))
        }

        // Recipes
        "recipes.preview" => {
            let req: RecipePreviewReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid RecipePreviewReq: {e}")))?;
            let raw_bytes = if let Some(ref b64) = req.input_base64 {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                    .map_err(|e| DomainError::Validation(format!("Invalid base64 in input: {e}")))?
            } else if let Some(ref text) = req.input_data {
                text.as_bytes().to_vec()
            } else {
                return Err(DomainError::Validation(
                    "Either input_data or input_base64 must be provided".to_string(),
                ));
            };
            let preview = preview_pipeline(&raw_bytes, &req.ops, req.flag_pattern.as_deref())?;
            Ok(json!(preview))
        }
        "recipes.execute" => {
            let req: RecipeExecuteReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid RecipeExecuteReq: {e}")))?;
            let path = app.cas.get_path_for_blake3(&req.artifact_id);
            if !path.exists() {
                return Err(DomainError::not_found("Artifact", &req.artifact_id));
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|e| DomainError::Storage(format!("Failed to read artifact: {e}")))?;
            let transformed = apply_pipeline(&bytes, &req.ops)?;
            let stored = app.cas.store_bytes(&transformed).await.map_err(|e| {
                DomainError::Storage(format!("Failed to store transformed artifact: {e}"))
            })?;
            let _ = app.storage.register_artifact(
                &stored.blake3,
                "transformed.bin",
                &stored.blake3,
                &stored.sha256,
                stored.size_bytes,
                None,
            );
            Ok(json!({
                "output_artifact_id": stored.blake3,
                "hash_blake3": stored.blake3,
                "hash_sha256": stored.sha256,
                "size_bytes": stored.size_bytes,
            }))
        }
        "recipes.save_step" => {
            let req: RecipeSaveStepReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid RecipeSaveStepReq: {e}")))?;
            if let Some(ref in_id) = req.input_artifact_id {
                let _ = app
                    .storage
                    .register_artifact(in_id, "input.bin", in_id, "", 0, None);
            }
            if let Some(ref out_id) = req.output_artifact_id {
                let _ = app
                    .storage
                    .register_artifact(out_id, "output.bin", out_id, "", 0, None);
            }
            let op_norm = match req.operation.to_lowercase().as_str() {
                "hexencode" | "hex_encode" => "hex_encode".to_string(),
                "hexdecode" | "hex_decode" => "hex_decode".to_string(),
                "base64encode" | "base64_encode" => "base64_encode".to_string(),
                "base64decode" | "base64_decode" => "base64_decode".to_string(),
                "rot13" => "rot13".to_string(),
                "xor" => "xor".to_string(),
                "zlibdecompress" | "zlib_decompress" => "zlib_decompress".to_string(),
                "gzipdecompress" | "gzip_decompress" => "gzip_decompress".to_string(),
                "urldecode" | "url_decode" => "url_decode".to_string(),
                other => other.to_string(),
            };
            let step = TransformStep {
                id: format!("step-{}", uuid::Uuid::now_v7()),
                challenge_id: req.challenge_id,
                recipe_id: req.recipe_id,
                step_order: req.step_order,
                operation: op_norm,
                parameters_json: req.parameters_json.unwrap_or_else(|| "{}".to_string()),
                input_artifact_id: req.input_artifact_id,
                output_artifact_id: req.output_artifact_id,
                input_hash: req.input_hash,
                output_hash: req.output_hash,
                created_at: chrono::Utc::now(),
            };
            app.storage.insert_transform_step(&step)?;
            Ok(json!({ "id": step.id }))
        }
        "recipes.list_steps" => {
            let req: RecipeListStepsReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid RecipeListStepsReq: {e}")))?;
            let steps = app
                .storage
                .list_transform_steps(&req.challenge_id, req.recipe_id.as_deref())?;
            Ok(json!(steps))
        }

        // Flags
        "flags.register" => {
            let req: FlagRegisterReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid FlagRegisterReq: {e}")))?;
            req.validate()?;
            let candidate_id = app
                .storage
                .register_candidate(&req.challenge_id, req.value, req.source_ref)
                .await?;
            Ok(json!({ "id": candidate_id, "candidate_id": candidate_id }))
        }
        "flags.accept" => {
            let req: FlagAcceptReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid FlagAcceptReq: {e}")))?;
            let accepted = app.storage.accept_flag(&req.candidate_id).await?;
            Ok(json!({ "accepted": accepted }))
        }
        "flags.reject" => {
            let req: FlagRejectReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid FlagRejectReq: {e}")))?;
            app.storage
                .reject_flag(&req.candidate_id, req.reason)
                .await?;
            Ok(json!({ "rejected": true }))
        }
        "flags.list" => {
            let req: FlagListReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid FlagListReq: {e}")))?;
            let flags = app.storage.list_flags(&req.challenge_id).await?;
            Ok(json!(flags))
        }

        // Writeups
        "writeups.generate_draft" => {
            let req: WriteupGenerateReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid WriteupGenerateReq: {e}")))?;
            let draft = app
                .storage
                .generate_draft(&req.challenge_id, req.include_timeline.unwrap_or(true))
                .await?;
            Ok(json!({ "markdown": draft }))
        }
        "writeups.export" => {
            let req: WriteupExportReq = serde_json::from_value(params)
                .map_err(|e| DomainError::Validation(format!("Invalid WriteupExportReq: {e}")))?;
            req.validate()?;
            let bytes = app
                .storage
                .export_markdown(&req.challenge_id, Path::new(&req.dest_path))
                .await?;
            Ok(json!({ "bytes_written": bytes }))
        }
        "writeups.update_section" => {
            let req: WriteupUpdateSectionReq = serde_json::from_value(params).map_err(|e| {
                DomainError::Validation(format!("Invalid WriteupUpdateSectionReq: {e}"))
            })?;
            app.storage
                .update_section(&req.challenge_id, req.section, req.content)
                .await?;
            Ok(json!({ "updated": true }))
        }

        _ => Err(DomainError::not_found("Method", method)),
    }
}

pub async fn try_dispatch_jsonrpc(app: &EngineApp, req_json: &str) -> Option<String> {
    let parsed: Result<JsonRpcRequest<serde_json::Value>, _> = serde_json::from_str(req_json);
    let req = match parsed {
        Ok(r) => r,
        Err(e) => {
            if req_json.contains("\"jsonrpc\"") {
                let err = JsonRpcError::parse_error(e.to_string());
                let resp = JsonRpcResponse::<()>::err(serde_json::Value::Null, err);
                return Some(serde_json::to_string(&resp).unwrap());
            }
            return None;
        }
    };

    if req.jsonrpc != "2.0" {
        let err = JsonRpcError::invalid_request("Field 'jsonrpc' must be '2.0'");
        let resp = JsonRpcResponse::<()>::err(req.id, err);
        return Some(serde_json::to_string(&resp).unwrap());
    }

    let method = req.method.as_str();
    let res = if method == "health" {
        Ok(serde_json::to_value(ApiDispatcher::handle_health()).unwrap())
    } else {
        handle_ctf_command(app, method, req.params).await
    };

    let resp = match res {
        Ok(val) => JsonRpcResponse::ok(req.id, val),
        Err(err) => JsonRpcResponse::err(req.id, err.into()),
    };
    Some(serde_json::to_string(&resp).unwrap())
}
