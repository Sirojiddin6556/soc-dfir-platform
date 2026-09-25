pub const MIGRATION_001_SQL: &str = r#"
-- Core Relational Schema (Data Contract v2 & Appendix A)
PRAGMA foreign_keys = ON;

-- 1. Cases Table
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 2. Artifacts Table
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    hash_blake3 TEXT NOT NULL,
    hash_sha256 TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    acquisition_method TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_blake3 ON artifacts(case_id, hash_blake3);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_sha256 ON artifacts(case_id, hash_sha256);

-- 3. Tool Runs Table
CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    output_hash TEXT NOT NULL,
    exit_status INTEGER NOT NULL,
    timeout_triggered INTEGER NOT NULL DEFAULT 0,
    workflow_task_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_runs_case ON tool_runs(case_id, adapter_name);

-- 4. Observations Table
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    tool_run_id TEXT REFERENCES tool_runs(id) ON DELETE SET NULL,
    source_tool TEXT NOT NULL,
    raw_event_type TEXT NOT NULL,
    source_timestamp TEXT,
    ingest_timestamp TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_artifact ON observations(artifact_id, source_timestamp);

-- 5. Facts Table
CREATE TABLE IF NOT EXISTS facts (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    assertion_type TEXT NOT NULL,
    verification_state TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    fact_type TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    severity TEXT NOT NULL DEFAULT 'Info',
    risk_score REAL NOT NULL DEFAULT 0.0,
    evidence_strength REAL NOT NULL DEFAULT 1.0,
    pain_level TEXT,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_facts_entity ON facts(case_id, entity_type, entity_key);
CREATE INDEX IF NOT EXISTS idx_facts_assertion ON facts(case_id, assertion_type, verification_state);

-- 6. Evidence Aggregates
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    confidence REAL NOT NULL DEFAULT 1.0,
    evidence_strength REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_members (
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    fact_id TEXT NOT NULL REFERENCES facts(id) ON DELETE CASCADE,
    relevance_score REAL NOT NULL DEFAULT 1.0,
    PRIMARY KEY (evidence_id, fact_id)
);

-- 7. Attack Graph Nodes
CREATE TABLE IF NOT EXISTS attack_nodes (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_case ON attack_nodes(case_id, node_type);

-- 8. Attack Graph Edges
CREATE TABLE IF NOT EXISTS attack_edges (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    supported_by_json TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edges_case ON attack_edges(case_id, source_node_id, target_node_id);

-- 9. Versioned Taxonomies
CREATE TABLE IF NOT EXISTS taxonomy_versions (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    version TEXT NOT NULL,
    release_date TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    imported_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS taxonomy_mappings (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    taxonomy_version_id TEXT NOT NULL REFERENCES taxonomy_versions(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,
    tactic TEXT,
    verification_state TEXT NOT NULL DEFAULT 'Candidate',
    confidence REAL NOT NULL DEFAULT 1.0,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
    mapping_rule_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tax_mapping ON taxonomy_mappings(node_id, taxonomy_version_id);

-- 10. Diagram Snapshots
CREATE TABLE IF NOT EXISTS diagram_snapshots (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    diagram_type TEXT NOT NULL,
    layout_data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 11. Chain of Custody
CREATE TABLE IF NOT EXISTS custody_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    artifact_hash TEXT,
    details_json TEXT NOT NULL,
    previous_state_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custody_case_ts ON custody_events(case_id, timestamp);

-- 12. Workflow Tasks
CREATE TABLE IF NOT EXISTS workflow_tasks (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    task_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_cpu INTEGER NOT NULL DEFAULT 1,
    resource_io INTEGER NOT NULL DEFAULT 1,
    resource_net INTEGER NOT NULL DEFAULT 0,
    resource_mem_mb INTEGER NOT NULL DEFAULT 512,
    resource_forensic INTEGER NOT NULL DEFAULT 0,
    resource_target_load INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    condition_dsl TEXT,
    dependencies_json TEXT NOT NULL DEFAULT '[]',
    error_message TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_wf_status ON workflow_tasks(case_id, status);

-- 13. Findings Table
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'Open',
    mitre_technique TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id, severity);

-- 14. Hypotheses Table
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    statement TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Proposed',
    confidence REAL NOT NULL DEFAULT 0.5,
    created_at TEXT NOT NULL,
    evaluated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_case ON hypotheses(case_id, status);

-- 15. Entities Table
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    properties_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entities_case_key ON entities(case_id, entity_type, entity_key);

-- 16. Software Table
CREATE TABLE IF NOT EXISTS software (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    vendor TEXT,
    version TEXT,
    architecture TEXT,
    install_path TEXT,
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_software_case ON software(case_id, name);

-- 17. Vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    cvss_score REAL NOT NULL DEFAULT 0.0,
    severity TEXT NOT NULL DEFAULT 'Medium',
    affected_software TEXT,
    remediation TEXT,
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulns_case_cve ON vulnerabilities(case_id, cve_id);

-- 18. Software Vulnerability Link Table
CREATE TABLE IF NOT EXISTS software_vulnerabilities (
    software_id TEXT NOT NULL REFERENCES software(id) ON DELETE CASCADE,
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    PRIMARY KEY (software_id, vulnerability_id)
);

-- 19. Audit Events Table
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    outcome TEXT NOT NULL DEFAULT 'Success',
    details_json TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_case_ts ON audit_events(case_id, timestamp);
"#;

pub const MIGRATION_002_SQL: &str = r#"
-- 20. Users Table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Analyst',
    department TEXT NOT NULL DEFAULT 'SOC',
    timezone TEXT NOT NULL DEFAULT 'Asia/Tashkent',
    language TEXT NOT NULL DEFAULT 'ru',
    avatar_url TEXT,
    created_at TEXT NOT NULL
);

-- 21. User Sessions Table
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token);

-- 22. Workspaces Table
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    organization_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 23. Teams Table
CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
);

-- 24. Team Members Table
CREATE TABLE IF NOT EXISTS team_members (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'Analyst',
    joined_at TEXT NOT NULL,
    PRIMARY KEY (team_id, user_id)
);

-- 25. Channels Table
CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    channel_type TEXT NOT NULL DEFAULT 'General',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_channels_case ON channels(case_id);

-- 26. Messages Table
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    author_name TEXT NOT NULL,
    author_role TEXT NOT NULL,
    body TEXT NOT NULL,
    reply_to_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
    references_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_channel_created ON messages(channel_id, created_at);

-- 27. User Presence Table
CREATE TABLE IF NOT EXISTS user_presence (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    is_online INTEGER NOT NULL DEFAULT 0,
    active_case_id TEXT,
    status_text TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL
);

-- 28. Notifications Table
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'General',
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at);
"#;

pub const MIGRATION_003_SQL: &str = r#"
-- 29. Workspace Members Table
CREATE TABLE IF NOT EXISTS workspace_members (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'Analyst',
    status TEXT NOT NULL DEFAULT 'Active',
    joined_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members(user_id);

-- 30. Invitations Table
CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    code TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'Analyst',
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Pending',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invitations_code ON invitations(code);
CREATE INDEX IF NOT EXISTS idx_invitations_status ON invitations(status);

-- 31. Case Members Table
CREATE TABLE IF NOT EXISTS case_members (
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'Analyst',
    assigned_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at TEXT NOT NULL,
    PRIMARY KEY (case_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_case_members_user ON case_members(user_id);

-- 32. Join Requests Table
CREATE TABLE IF NOT EXISTS join_requests (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'Analyst',
    status TEXT NOT NULL DEFAULT 'Pending',
    reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    reviewed_at TEXT
);

-- 33. Membership Audit Table
CREATE TABLE IF NOT EXISTS membership_audit (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_membership_audit_ws ON membership_audit(workspace_id, created_at);
"#;

pub const MIGRATION_004_SQL: &str = r#"
-- 34. Scan Scope Allowlist
CREATE TABLE IF NOT EXISTS scope_allowlist (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,           -- CIDR, single IP, or hostname
    pattern_type TEXT NOT NULL DEFAULT 'ip',  -- 'ip', 'cidr', 'hostname'
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scope_case ON scope_allowlist(case_id);
"#;

pub const MIGRATION_005_SQL: &str = r#"
-- 35. Local CVE Knowledge Base (VULN2-002)
-- Indexed local store for NVD/OSV/KEV/EPSS records.
-- Populated by the offline bundle importer (VULN2-003).
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id         TEXT PRIMARY KEY,
    cpe_vendor     TEXT NOT NULL DEFAULT '',
    cpe_product    TEXT NOT NULL DEFAULT '',
    cvss_v3        REAL NOT NULL DEFAULT 0.0,
    epss_score     REAL NOT NULL DEFAULT 0.0,
    cisa_kev       INTEGER NOT NULL DEFAULT 0,  -- boolean
    severity       TEXT NOT NULL DEFAULT 'Unknown',
    cwe_ids        TEXT NOT NULL DEFAULT '[]',  -- JSON array
    description    TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT '',    -- 'nvd' | 'osv' | 'kev' | 'epss'
    published_at   TEXT,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cve_vendor_product ON cve_entries(cpe_vendor, cpe_product);
CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve_entries(cisa_kev) WHERE cisa_kev = 1;
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity);

-- 36. CVE Bundle Import Log
CREATE TABLE IF NOT EXISTS cve_import_log (
    id          TEXT PRIMARY KEY,
    source      TEXT NOT NULL,   -- 'nvd' | 'osv' | 'kev' | 'epss'
    bundle_path TEXT NOT NULL,
    records_imported INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL
);
"#;

pub const MIGRATION_007_SQL: &str = r#"
-- 39. Canonical forensic timeline and deterministic correlations (Phase 4)
CREATE TABLE IF NOT EXISTS timeline_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_timestamp TEXT,
    ingest_timestamp TEXT NOT NULL,
    normalized_timestamp TEXT,
    source_kind TEXT NOT NULL,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    observation_id TEXT NOT NULL,
    quality TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timeline_case_time
    ON timeline_events(case_id, normalized_timestamp, event_id);

CREATE TABLE IF NOT EXISTS correlations (
    correlation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    supporting_observations_json TEXT NOT NULL,
    assertion_type TEXT NOT NULL,
    verification_state TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    provenance_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_correlations_case_rule
    ON correlations(case_id, rule_id, rule_version, correlation_id);
"#;

pub const MIGRATION_V002_CTF_CORE_SQL: &str =
    include_str!("../migrations/V002_ctf_core_schema.sql");
