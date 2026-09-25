use core_domain::ctf::traits::{FlagService, WorkspaceService, WriteupService};
use core_domain::ctf::*;
use storage_sqlite::SqliteStorage;

#[tokio::test]
async fn test_ctf_workspace_lifecycle_and_crud() {
    let storage = SqliteStorage::open_in_memory().expect("Failed to open in-memory db");

    // 1. Create Competition
    let comp_cmd = CreateCompetitionCmd {
        name: "CyberSecurity Open 2026".to_string(),
        description: Some("Flagship National CTF Championship".to_string()),
        format: Some(CompetitionFormat::Jeopardy),
        flag_format_regex: Some(r"flag\{[a-zA-Z0-9_]+\}".to_string()),
        start_at: None,
        end_at: None,
    };
    let comp_id = storage.create_competition(comp_cmd).await.unwrap();
    assert!(comp_id.starts_with("comp-"));

    // 2. Get & List Competitions
    let comp = storage.get_competition(&comp_id).await.unwrap();
    assert_eq!(comp.name, "CyberSecurity Open 2026");
    assert_eq!(comp.format, CompetitionFormat::Jeopardy);
    assert_eq!(comp.status, CompetitionStatus::Active);

    let comp_list = storage.list_competitions(None).await.unwrap();
    assert_eq!(comp_list.len(), 1);
    assert_eq!(comp_list[0].id, comp_id);

    // 3. Create Challenges
    let chal_cmd = CreateChallengeCmd {
        competition_id: comp_id.clone(),
        name: "Buffer Overflow 101".to_string(),
        category: "pwn".to_string(),
        points: Some(150),
        target: Some(TargetScope {
            host: "pwn.ctf.local".into(),
            port: Some(31337),
            protocol: "tcp".into(),
        }),
        expected_flag: None,
    };
    let chal_id = storage.create_challenge(chal_cmd).await.unwrap();
    assert!(chal_id.starts_with("chal-"));

    // 4. Get Challenge Details
    let details = storage.get_challenge(&chal_id).await.unwrap();
    assert_eq!(details.challenge.name, "Buffer Overflow 101");
    assert_eq!(details.challenge.category, "pwn");
    assert_eq!(details.challenge.points, 150);
    assert_eq!(details.challenge.status, ChallengeStatus::New);
    assert!(details.challenge.target_scope.is_some());

    // 5. Update Status & Target
    storage
        .update_challenge_status(&chal_id, ChallengeStatus::InProgress, None)
        .await
        .unwrap();

    let updated_details = storage.get_challenge(&chal_id).await.unwrap();
    assert_eq!(
        updated_details.challenge.status,
        ChallengeStatus::InProgress
    );

    storage
        .update_challenge_target(
            &chal_id,
            TargetScope {
                host: "pwn2.ctf.local".into(),
                port: Some(31338),
                protocol: "nc".into(),
            },
        )
        .await
        .unwrap();

    let target_updated = storage.get_challenge(&chal_id).await.unwrap();
    assert_eq!(
        target_updated.challenge.target_scope.as_ref().unwrap().host,
        "pwn2.ctf.local"
    );
    assert_eq!(
        target_updated.challenge.target_scope.as_ref().unwrap().port,
        Some(31338)
    );
}

#[tokio::test]
async fn test_ctf_artifacts_and_lineage_pipeline() {
    let storage = SqliteStorage::open_in_memory().expect("Failed to open in-memory db");

    let comp_id = storage
        .create_competition(CreateCompetitionCmd {
            name: "Forensics Challenge".into(),
            description: None,
            format: None,
            flag_format_regex: None,
            start_at: None,
            end_at: None,
        })
        .await
        .unwrap();

    let chal_id = storage
        .create_challenge(CreateChallengeCmd {
            competition_id: comp_id,
            name: "Memory Forensic Triage".into(),
            category: "forensics".into(),
            points: Some(300),
            target: None,
            expected_flag: None,
        })
        .await
        .unwrap();

    // Insert dummy artifact into artifacts table
    let art_id = "art-blake3-123456";
    {
        let conn_arc = storage.conn();
        let conn = conn_arc.lock().unwrap();
        conn.execute(
            r#"INSERT INTO artifacts (id, original_name, blake3, sha256, size, detected_type, storage_state, created_at)
               VALUES (?1, 'memdump.raw', 'b3hash1', 'sha256hash1', 1048576, 'application/octet-stream', 'stored', datetime('now'))"#,
            rusqlite::params![art_id],
        ).unwrap();
    }

    // Add to challenge
    let ca_id = storage
        .add_challenge_artifact(&chal_id, art_id, ArtifactRole::MemoryDump, Some("dump.raw"))
        .unwrap();
    assert!(ca_id.starts_with("ca-"));

    let artifacts = storage.list_challenge_artifacts(&chal_id).unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].artifact_id, art_id);
    assert_eq!(artifacts[0].role, ArtifactRole::MemoryDump);

    // Record Transform Step
    let step = TransformStep {
        id: "step-100".into(),
        challenge_id: chal_id.clone(),
        recipe_id: Some("recipe-xor".into()),
        step_order: 1,
        operation: "xor".into(),
        parameters_json: r#"{"key":"42"}"#.into(),
        input_artifact_id: Some(art_id.into()),
        output_artifact_id: None,
        input_hash: Some("b3hash1".into()),
        output_hash: Some("b3hash2".into()),
        created_at: chrono::Utc::now(),
    };
    storage.insert_transform_step(&step).unwrap();

    let steps = storage.list_transform_steps(&chal_id, None).unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].operation, "xor");
}

#[tokio::test]
async fn test_ctf_flag_verification_and_writeup_service() {
    let storage = SqliteStorage::open_in_memory().expect("Failed to open in-memory db");

    let comp_id = storage
        .create_competition(CreateCompetitionCmd {
            name: "Reverse Track".into(),
            description: None,
            format: None,
            flag_format_regex: None,
            start_at: None,
            end_at: None,
        })
        .await
        .unwrap();

    let chal_id = storage
        .create_challenge(CreateChallengeCmd {
            competition_id: comp_id,
            name: "Crackme Level 1".into(),
            category: "reverse".into(),
            points: Some(200),
            target: None,
            expected_flag: Some("flag{cr4ckm3_succ3ss_2026}".into()),
        })
        .await
        .unwrap();

    // 1. Register candidate flag
    let cand_id = storage
        .register_candidate(
            &chal_id,
            "flag{cr4ckm3_succ3ss_2026}".into(),
            "strings_search".into(),
        )
        .await
        .unwrap();
    assert!(cand_id.starts_with("flag-"));

    let flags = storage.list_flags(&chal_id).await.unwrap();
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].verification_status, VerificationStatus::Candidate);

    let wrong_id = storage
        .register_candidate(&chal_id, "flag{wrong}".into(), "manual".into())
        .await
        .unwrap();
    assert!(!storage.accept_flag(&wrong_id).await.unwrap());
    assert_eq!(
        storage
            .get_challenge(&chal_id)
            .await
            .unwrap()
            .challenge
            .status,
        ChallengeStatus::New
    );

    // 2. Accept matching flag -> marks challenge solved
    let accepted = storage.accept_flag(&cand_id).await.unwrap();
    assert!(accepted);

    let details = storage.get_challenge(&chal_id).await.unwrap();
    assert_eq!(details.challenge.status, ChallengeStatus::Solved);
    assert_eq!(
        details.accepted_flag.as_deref(),
        Some("flag{cr4ckm3_succ3ss_2026}")
    );

    // 3. Generate Draft Writeup
    let draft_md = storage.generate_draft(&chal_id, true).await.unwrap();
    assert!(draft_md.contains("# Write-up: Crackme Level 1 (REVERSE - 200 pts)"));
    assert!(draft_md.contains("flag{cr4ckm3_succ3ss_2026}"));
    assert!(draft_md.contains("Investigation Timeline"));

    // 4. Update section in writeup
    storage
        .update_section(
            &chal_id,
            "Detailed Walkthrough & Solution".into(),
            "Decompiled main() in Ghidra and inverted the XOR cipher key.".into(),
        )
        .await
        .unwrap();

    let temp_dest =
        std::env::temp_dir().join(format!("ctf_writeup_export_{}.md", uuid::Uuid::now_v7()));
    let bytes_exported = storage.export_markdown(&chal_id, &temp_dest).await.unwrap();
    assert!(bytes_exported > 0);
    assert!(temp_dest.exists());

    let exported_text = tokio::fs::read_to_string(&temp_dest).await.unwrap();
    assert!(exported_text.contains("Decompiled main() in Ghidra"));

    let _ = tokio::fs::remove_file(temp_dest).await;
}
