use super::entities::*;
use super::pipeline_entities::*;
use crate::error::DomainError;
use std::path::Path;

pub struct WriteupDraftContext {
    pub challenge: Challenge,
    pub accepted_flags: Vec<FlagCandidate>,
    pub transform_steps: Vec<TransformStep>,
    pub jobs: Vec<Job>,
    pub artifacts: Vec<ChallengeArtifact>,
}

pub fn generate_markdown_writeup(ctx: &WriteupDraftContext, include_timeline: bool) -> String {
    let mut md = String::new();

    // 1. Header
    md.push_str(&format!(
        "# Write-up: {} ({} - {} pts)\n\n",
        ctx.challenge.name,
        ctx.challenge.category.to_uppercase(),
        ctx.challenge.points
    ));

    // 2. Metadata table
    md.push_str("## 1. Challenge Overview\n\n");
    md.push_str("| Property | Value |\n|---|---|\n");
    md.push_str(&format!(
        "| **Category** | `{}` |\n",
        ctx.challenge.category
    ));
    md.push_str(&format!("| **Points** | {} |\n", ctx.challenge.points));
    md.push_str(&format!("| **Status** | `{}` |\n", ctx.challenge.status));
    if let Some(ref target) = ctx.challenge.target_scope {
        let port_str = target
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "N/A".into());
        md.push_str(&format!(
            "| **Target** | `{}:{} ({})` |\n",
            target.host, port_str, target.protocol
        ));
    }
    md.push_str(&format!(
        "| **Created** | `{}` |\n\n",
        ctx.challenge.created_at
    ));

    // 3. Flags Section
    md.push_str("## 2. Captured Flag(s)\n\n");
    if ctx.accepted_flags.is_empty() {
        md.push_str("> *No flags officially accepted yet.*\n\n");
    } else {
        for flag in &ctx.accepted_flags {
            md.push_str(&format!("> [!IMPORTANT]\n> **Flag**: `{}`\n\n", flag.value));
            if let Some(ref pattern) = flag.pattern_match {
                md.push_str(&format!("*Pattern match*: `{}`  \n", pattern));
            }
            if let Some(ref run_id) = flag.provenance_run_id {
                md.push_str(&format!("*Provenance Job*: `{}`  \n", run_id));
            }
            md.push('\n');
        }
    }

    // 4. Lineage DAG & Transform Steps
    md.push_str("## 3. Analysis Lineage DAG & Recipe Transformations\n\n");
    if ctx.transform_steps.is_empty() {
        md.push_str("*No recipe transform steps recorded.*\n\n");
    } else {
        md.push_str(
            "| Step | Operation | Parameters | Input Hash | Output Hash |\n|---|---|---|---|---|\n",
        );
        for step in &ctx.transform_steps {
            let in_h = step.input_hash.as_deref().unwrap_or("-");
            let out_h = step.output_hash.as_deref().unwrap_or("-");
            md.push_str(&format!(
                "| {} | `{}` | `{}` | `{}` | `{}` |\n",
                step.step_order, step.operation, step.parameters_json, in_h, out_h
            ));
        }
        md.push('\n');
    }

    // 5. Tool Runs Executed
    md.push_str("## 4. Key Tool Runs\n\n");
    if ctx.jobs.is_empty() {
        md.push_str("*No background tool executions recorded.*\n\n");
    } else {
        md.push_str("| Job ID | Tool | State | Exit Code | Runtime | Command |\n|---|---|---|---|---|---|\n");
        for job in &ctx.jobs {
            let cmd_str = job.argv.join(" ");
            let exit_str = job
                .exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into());
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
                job.id, job.tool_id, job.state, exit_str, job.runtime, cmd_str
            ));
        }
        md.push('\n');
    }

    // 6. Walkthrough Narrative
    md.push_str("## 5. Detailed Walkthrough & Solution\n\n");
    md.push_str("### Step 1: Initial Triage and Reconnaissance\n");
    md.push_str(
        "Artifacts provided were ingested into CAS storage and evaluated for basic properties.\n\n",
    );
    md.push_str("### Step 2: Vulnerability Analysis & Exploitation / Deobfuscation\n");
    md.push_str("Automated tools and transformation pipelines were executed to unpack the target payload.\n\n");
    md.push_str("### Step 3: Flag Recovery\n");
    md.push_str(
        "The flag was captured and successfully verified against competition requirements.\n\n",
    );

    // 7. Timeline (Optional)
    if include_timeline {
        md.push_str("## 6. Investigation Timeline\n\n");
        md.push_str("| Timestamp (UTC) | Event Type | Description |\n|---|---|---|\n");
        md.push_str(&format!(
            "| `{}` | Challenge Created | Challenge initialized in workspace |\n",
            ctx.challenge.created_at
        ));
        for job in &ctx.jobs {
            if let Some(st) = job.started_at {
                md.push_str(&format!(
                    "| `{}` | Tool Run Started | Executed `{}` |\n",
                    st, job.tool_id
                ));
            }
        }
        for flag in &ctx.accepted_flags {
            if let Some(vt) = flag.verified_at {
                md.push_str(&format!(
                    "| `{}` | Flag Accepted | Flag `{}` captured |\n",
                    vt, flag.value
                ));
            }
        }
        md.push('\n');
    }

    md
}

pub fn update_markdown_section(markdown: &str, section_title: &str, new_content: &str) -> String {
    let header_prefix = format!("## {}", section_title);
    let lines = markdown.lines().collect::<Vec<_>>();
    let mut start_idx = None;
    let mut end_idx = None;

    for (i, line) in lines.iter().enumerate() {
        if line.trim().starts_with(&header_prefix)
            || line.trim().contains(section_title) && line.starts_with('#')
        {
            start_idx = Some(i);
            continue;
        }
        if start_idx.is_some() && line.starts_with("## ") {
            end_idx = Some(i);
            break;
        }
    }

    if let Some(start) = start_idx {
        let end = end_idx.unwrap_or(lines.len());
        let mut result = Vec::new();
        for &line in &lines[..=start] {
            result.push(line.to_string());
        }
        result.push(String::new());
        result.push(new_content.to_string());
        result.push(String::new());
        for &line in &lines[end..] {
            result.push(line.to_string());
        }
        result.join("\n")
    } else {
        // Append section if not found
        format!(
            "{}\n\n## {}\n\n{}\n",
            markdown.trim(),
            section_title,
            new_content
        )
    }
}

pub async fn export_markdown_file(markdown: &str, dest_path: &Path) -> Result<u64, DomainError> {
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            DomainError::storage(format!("Failed to create export parent directory: {}", e))
        })?;
    }
    tokio::fs::write(dest_path, markdown).await.map_err(|e| {
        DomainError::storage(format!("Failed to write export markdown file: {}", e))
    })?;

    let meta = tokio::fs::metadata(dest_path).await.map_err(|e| {
        DomainError::storage(format!("Failed to read metadata of exported file: {}", e))
    })?;

    Ok(meta.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ctx() -> WriteupDraftContext {
        let chal = Challenge {
            id: "chal-writeup".to_string(),
            competition_id: "comp-1".to_string(),
            name: "Secret Gate".to_string(),
            category: "reverse".to_string(),
            points: 250,
            status: ChallengeStatus::Solved,
            blocked_reason: None,
            target_scope: Some(TargetScope {
                host: "ctf.target.local".into(),
                port: Some(1337),
                protocol: "tcp".into(),
            }),
            case_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let flag = FlagCandidate {
            id: "flag-1".to_string(),
            challenge_id: "chal-writeup".to_string(),
            value: "flag{r3v_m4st3r_2026}".to_string(),
            provenance_run_id: Some("job-1".to_string()),
            provenance_artifact_id: None,
            provenance_step_id: None,
            pattern_match: Some(r"flag\{.*\}".to_string()),
            verification_status: VerificationStatus::Accepted,
            rejection_reason: None,
            verified_at: Some(chrono::Utc::now()),
            submitted_to_platform: false,
            created_at: chrono::Utc::now(),
        };

        let step = TransformStep {
            id: "step-1".to_string(),
            challenge_id: "chal-writeup".to_string(),
            recipe_id: None,
            step_order: 1,
            operation: "base64_decode".to_string(),
            parameters_json: "{}".to_string(),
            input_artifact_id: None,
            output_artifact_id: None,
            input_hash: Some("abc".to_string()),
            output_hash: Some("def".to_string()),
            created_at: chrono::Utc::now(),
        };

        let job = Job {
            id: "job-1".to_string(),
            challenge_id: "chal-writeup".to_string(),
            tool_id: "ghidra".to_string(),
            adapter: "decompiler".to_string(),
            runtime: JobRuntime::Native,
            state: JobStatus::Succeeded,
            argv: vec!["analyzeHeadless".into(), "chal.bin".into()],
            input_refs: vec![],
            exit_code: Some(0),
            timeout_ms: 60000,
            timeout_triggered: false,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
        };

        WriteupDraftContext {
            challenge: chal,
            accepted_flags: vec![flag],
            transform_steps: vec![step],
            jobs: vec![job],
            artifacts: vec![],
        }
    }

    #[test]
    fn test_markdown_draft_generation() {
        let ctx = dummy_ctx();
        let md = generate_markdown_writeup(&ctx, true);

        assert!(md.contains("# Write-up: Secret Gate (REVERSE - 250 pts)"));
        assert!(md.contains("flag{r3v_m4st3r_2026}"));
        assert!(md.contains("base64_decode"));
        assert!(md.contains("ghidra"));
        assert!(md.contains("Investigation Timeline"));
    }

    #[test]
    fn test_markdown_section_update() {
        let ctx = dummy_ctx();
        let md = generate_markdown_writeup(&ctx, false);

        let updated = update_markdown_section(
            &md,
            "Detailed Walkthrough & Solution",
            "Custom injected solution notes: bypassed check by patching byte at offset 0x40.",
        );

        assert!(updated.contains("Custom injected solution notes"));
    }

    #[tokio::test]
    async fn test_markdown_export() {
        let ctx = dummy_ctx();
        let md = generate_markdown_writeup(&ctx, true);
        let temp_file =
            std::env::temp_dir().join(format!("writeup_test_{}.md", uuid::Uuid::now_v7()));

        let bytes = export_markdown_file(&md, &temp_file).await.unwrap();
        assert!(bytes > 0);
        assert!(temp_file.exists());

        let _ = tokio::fs::remove_file(temp_file).await;
    }
}
