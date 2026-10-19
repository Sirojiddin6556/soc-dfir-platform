use engine_server::EngineApp;
use std::sync::Arc;

#[tokio::test]
async fn test_engine_app_composition_and_dispatch() {
    let temp_dir = std::env::temp_dir().join(format!("engine_test_{}", uuid::Uuid::now_v7()));
    let app = Arc::new(EngineApp::new_in_memory(temp_dir.clone()));

    // 1. Test Health Probe
    let health_req =
        r#"{"api_version": 1, "request_id": "req-1", "method": "health", "params": {}}"#;
    let health_resp = app.dispatch_request(health_req).await;
    assert!(health_resp.contains("\"live\":true"));

    // 2. Test Case Creation
    let case_req = r#"{"api_version": 1, "request_id": "req-2", "method": "cases.create", "params": {"title": "Incident Beta", "description": "Automated test"}}"#;
    let case_resp = app.dispatch_request(case_req).await;
    assert!(case_resp.contains("\"case_id\""));
    assert!(case_resp.contains("\"status\":\"Active\""));

    // 3. Test Cases List
    let list_req =
        r#"{"api_version": 1, "request_id": "req-3", "method": "cases.list", "params": {}}"#;
    let list_resp = app.dispatch_request(list_req).await;
    assert!(list_resp.contains("Incident Beta"));

    // 4. Test Unknown Method -> RFC 7807 404
    let unknown_req =
        r#"{"api_version": 1, "request_id": "req-6", "method": "non_existent", "params": {}}"#;
    let unknown_resp = app.dispatch_request(unknown_req).await;
    assert!(unknown_resp.contains("\"status\":404"));
    assert!(unknown_resp.contains("Not Found"));

    let _ = tokio::fs::remove_dir_all(temp_dir).await;
}

/// A real, harmless process (a copy of `sleep` / `PING.EXE`) running from a
/// world-writable directory: precisely the on-host condition CORR-LIN-001b
/// (Linux) and CORR-WIN-001f (Windows) detect. Live correlation of a clean
/// machine legitimately produces no facts, so a test that needs facts must
/// create a genuine finding on the host rather than rely on whatever happens
/// to be running. Killed and removed on drop.
struct SuspiciousProcess {
    child: std::process::Child,
    dir: std::path::PathBuf,
}

impl SuspiciousProcess {
    fn spawn() -> Self {
        #[cfg(target_os = "windows")]
        let (bases, sources, file, args): (&[&str], &[&str], &str, &[&str]) = (
            &["C:\\Users\\Public"],
            &["C:\\Windows\\System32\\PING.EXE"],
            "ping.exe",
            &["-n", "120", "127.0.0.1"],
        );
        #[cfg(not(target_os = "windows"))]
        let (bases, sources, file, args): (&[&str], &[&str], &str, &[&str]) = (
            &["/tmp", "/var/tmp", "/dev/shm"],
            &["/bin/sleep", "/usr/bin/sleep"],
            "sleep",
            &["120"],
        );
        let source = sources
            .iter()
            .find(|s| std::path::Path::new(s).exists())
            .expect("a harmless system binary to copy");
        for base in bases {
            let dir =
                std::path::Path::new(base).join(format!("soc-dfir-it-{}", uuid::Uuid::now_v7()));
            if std::fs::create_dir_all(&dir).is_err() {
                continue;
            }
            let exe = dir.join(file);
            if std::fs::copy(source, &exe).is_ok() {
                // A noexec mount makes spawn fail; try the next directory.
                if let Ok(child) = spawn_retrying_busy(
                    std::process::Command::new(&exe)
                        .args(args)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null()),
                ) {
                    return Self { child, dir };
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
        panic!(
            "could not execute a binary from any world-writable directory {:?}",
            bases
        );
    }
}

/// Executing a file right after copying it can fail with ETXTBSY when
/// another test thread forks while the copy's write handle is still open;
/// the forked child drops it on exec, so retry briefly.
fn spawn_retrying_busy(cmd: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    let mut attempts = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

impl Drop for SuspiciousProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn test_case_id_required_and_data_survives_restart() {
    let suspicious = SuspiciousProcess::spawn();
    let suspicious_pid = suspicious.child.id();

    let scratch =
        std::env::temp_dir().join(format!("engine_persist_test_{}", uuid::Uuid::now_v7()));
    let cas_dir = scratch.join("cas");
    let db_path = scratch.join("case.db");

    let (case_id, finding_id) = {
        let app = EngineApp::new(cas_dir.clone(), db_path.clone()).expect("open persistent db");

        // Collection must be rejected without a real case_id, not silently
        // fabricate a random one.
        let missing_case_req =
            r#"{"api_version": 1, "request_id": "r1", "method": "host.correlate", "params": {}}"#;
        let missing_case_resp = app.dispatch_request(missing_case_req).await;
        assert!(missing_case_resp.contains("\"status\":400"));

        // Create a real case and use its id end to end.
        let case_req = r#"{"api_version": 1, "request_id": "r2", "method": "cases.create", "params": {"title": "Incident Persist"}}"#;
        let case_resp = app.dispatch_request(case_req).await;
        let case_val: serde_json::Value = serde_json::from_str(&case_resp).unwrap();
        let case_id = case_val["result"]["case_id"].as_str().unwrap().to_string();

        let correlate_req = format!(
            r#"{{"api_version": 1, "request_id": "r3", "method": "host.correlate", "params": {{"case_id": "{}", "refresh": true}}}}"#,
            case_id
        );
        let correlate_resp = app.dispatch_request(&correlate_req).await;
        assert!(correlate_resp.contains("\"error\":null"));

        // Facts from correlation must be stored under the real case id, and
        // must include the finding for the process this test started.
        let cid = core_domain::id::EntityId::parse(&case_id).unwrap();
        let facts = app.storage.get_facts_for_case(cid).unwrap();
        let finding = facts
            .iter()
            .find(|f| f.data["pid"] == suspicious_pid)
            .unwrap_or_else(|| {
                panic!(
                    "live correlation must flag pid {} running from a world-writable dir; facts: {:?}",
                    suspicious_pid,
                    facts.iter().map(|f| &f.data["rule_id"]).collect::<Vec<_>>()
                )
            });
        #[cfg(target_os = "linux")]
        assert_eq!(finding.data["rule_id"], "CORR-LIN-001b");
        #[cfg(target_os = "windows")]
        assert_eq!(finding.data["rule_id"], "CORR-WIN-001f");

        // Re-running collection (the workspace does it on every load) must
        // not store the same finding again.
        let finding_count = |facts: &[core_domain::fact::Fact]| {
            facts
                .iter()
                .filter(|f| f.data["pid"] == suspicious_pid)
                .count()
        };
        assert_eq!(finding_count(&facts), 1);
        for _ in 0..2 {
            app.dispatch_request(&correlate_req).await;
        }
        let facts_again = app.storage.get_facts_for_case(cid).unwrap();
        assert_eq!(finding_count(&facts_again), 1, "no duplicate findings");

        (case_id, finding.id)
    }; // app dropped here, simulating the application closing
    drop(suspicious);

    // Reopen against the same db file, as a fresh process would.
    let reopened = EngineApp::new(cas_dir, db_path.clone()).expect("reopen persistent db");
    let list_resp = reopened
        .dispatch_request(
            r#"{"api_version": 1, "request_id": "r4", "method": "cases.list", "params": {}}"#,
        )
        .await;
    assert!(list_resp.contains("Incident Persist"));

    let cid = core_domain::id::EntityId::parse(&case_id).unwrap();
    let facts_after_restart = reopened.storage.get_facts_for_case(cid).unwrap();
    assert!(
        facts_after_restart.iter().any(|f| f.id == finding_id),
        "the finding must still be there after reopening the database"
    );

    let _ = tokio::fs::remove_dir_all(scratch).await;
}

/// `code.scan` passes its options through: a C tool that runs its argument
/// is reported only when command-line input counts as an attacker's.
#[tokio::test]
async fn code_scan_reports_findings_with_the_requested_sources() {
    let temp_dir = std::env::temp_dir().join(format!("engine_code_{}", uuid::Uuid::now_v7()));
    let project = temp_dir.join("tool");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("tool.c"),
        "#include <stdlib.h>\nint main(int argc, char **argv) {\n    system(argv[1]);\n    return 0;\n}\n",
    )
    .unwrap();
    let app = Arc::new(EngineApp::new_in_memory(temp_dir.join("data")));

    let scan = |external: bool| {
        let params = serde_json::json!({ "path": project, "external_sources": external });
        format!(
            r#"{{"api_version": 1, "request_id": "code", "method": "code.scan", "params": {params}}}"#
        )
    };
    let finished = || async {
        for _ in 0..600 {
            let resp = app
                .dispatch_request(
                    r#"{"api_version": 1, "request_id": "s", "method": "code.status", "params": {}}"#,
                )
                .await;
            let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
            if v["result"]["running"] == false {
                return v["result"].clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("code analysis did not finish");
    };

    let started: serde_json::Value =
        serde_json::from_str(&app.dispatch_request(&scan(false)).await).unwrap();
    assert_eq!(started["result"]["running"], true, "{started}");
    let status = finished().await;
    assert_eq!(status["external_sources"], false);
    assert_eq!(
        status["report"]["findings"].as_array().unwrap().len(),
        0,
        "{status}"
    );

    app.dispatch_request(&scan(true)).await;
    let status = finished().await;
    let findings = status["report"]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{status}");
    assert_eq!(findings[0]["rule"], "command-injection");
    assert_eq!(findings[0]["file"], "tool.c");
    assert_eq!(findings[0]["line"], 3);

    let missing =
        r#"{"api_version": 1, "request_id": "m", "method": "code.scan", "params": {"path": ""}}"#;
    let resp = app.dispatch_request(missing).await;
    assert!(resp.contains("\"status\":400"), "{resp}");

    std::fs::remove_dir_all(temp_dir).ok();
}
