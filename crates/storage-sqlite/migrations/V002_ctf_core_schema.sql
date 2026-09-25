-- ============================================================================
-- Migration: V002_ctf_core_schema.sql (UP)
-- Description: Production CTF Core Schema for SQLite (WAL Mode + Dual-Tier Storage)
-- Compatibility: Strictly additive & compatible with SOC-DFIR MIGRATION_001_SQL
-- ============================================================================

PRAGMA foreign_keys = OFF;

-- ----------------------------------------------------------------------------
-- 1. Competitions Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS competitions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    format TEXT NOT NULL DEFAULT 'jeopardy' CHECK (format IN ('jeopardy', 'attack_defense', 'mixed', 'ad_hoc')),
    flag_format_regex TEXT,
    start_at TEXT,
    end_at TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'paused', 'completed', 'archived')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_competitions_status ON competitions(status);

-- ----------------------------------------------------------------------------
-- 2. Challenges Table (With DFIR Case Bridge)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    competition_id TEXT NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('web', 'pwn', 'reverse', 'crypto', 'forensics', 'misc', 'osint', 'stego', 'network')),
    points INTEGER DEFAULT 0 CHECK (points >= 0),
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'in_progress', 'blocked', 'solved', 'archived')),
    blocked_reason TEXT CHECK (status != 'blocked' OR blocked_reason IS NOT NULL),
    target_host TEXT,
    target_port INTEGER CHECK (target_port IS NULL OR (target_port >= 1 AND target_port <= 65535)),
    target_proto TEXT DEFAULT 'tcp' CHECK (target_proto IN ('tcp', 'udp', 'http', 'https', 'nc')),
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_comp_cat_status ON challenges(competition_id, category, status);
CREATE INDEX IF NOT EXISTS idx_challenges_status ON challenges(status);
CREATE INDEX IF NOT EXISTS idx_challenges_case ON challenges(case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_challenges_active ON challenges(competition_id, status) WHERE status IN ('new', 'in_progress', 'blocked');

-- ----------------------------------------------------------------------------
-- 3. Artifacts Table Evolution (CAS Metadata + Legacy Compatibility)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS artifacts_v2 (
    id TEXT PRIMARY KEY,
    blake3 TEXT,
    sha256 TEXT,
    size INTEGER CHECK (size IS NULL OR size >= 0),
    detected_type TEXT DEFAULT 'application/octet-stream',
    storage_state TEXT NOT NULL DEFAULT 'stored' CHECK (storage_state IN ('stored', 'quarantined', 'evicted', 'missing')),
    original_name TEXT NOT NULL,
    entropy REAL CHECK (entropy IS NULL OR (entropy >= 0.0 AND entropy <= 8.0)),
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    hash_blake3 TEXT,
    hash_sha256 TEXT,
    file_size INTEGER,
    mime_type TEXT,
    acquisition_method TEXT DEFAULT 'cas_ingest',
    acquired_at TEXT,
    ingested_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO artifacts_v2 (
    id, blake3, sha256, size, detected_type, storage_state, original_name, entropy, case_id,
    hash_blake3, hash_sha256, file_size, mime_type, acquisition_method, acquired_at, ingested_at, created_at
)
SELECT
    id, hash_blake3, hash_sha256, file_size, mime_type, 'stored', original_name, NULL, case_id,
    hash_blake3, hash_sha256, file_size, mime_type, acquisition_method, acquired_at, ingested_at, ingested_at
FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_v2 RENAME TO artifacts;

CREATE INDEX IF NOT EXISTS idx_artifacts_blake3 ON artifacts(blake3);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_artifacts_storage ON artifacts(storage_state);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_blake3 ON artifacts(case_id, hash_blake3) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_artifacts_case_sha256 ON artifacts(case_id, hash_sha256) WHERE case_id IS NOT NULL;

-- Backward compatibility trigger for legacy code inserting via hash_blake3
CREATE TRIGGER IF NOT EXISTS trg_artifacts_legacy_sync
AFTER INSERT ON artifacts
FOR EACH ROW
WHEN NEW.blake3 IS NULL AND NEW.hash_blake3 IS NOT NULL
BEGIN
    UPDATE artifacts SET
        blake3 = NEW.hash_blake3,
        sha256 = NEW.hash_sha256,
        size = NEW.file_size,
        detected_type = COALESCE(NEW.mime_type, 'application/octet-stream'),
        created_at = COALESCE(NEW.ingested_at, datetime('now'))
    WHERE id = NEW.id;
END;

-- ----------------------------------------------------------------------------
-- 4. Challenge Artifacts Junction (M:N)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS challenge_artifacts (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    role TEXT NOT NULL DEFAULT 'input' CHECK (role IN ('input', 'extracted', 'transformed', 'memory_dump', 'pcaps', 'evidence', 'scratch')),
    alias TEXT,
    added_at TEXT NOT NULL,
    UNIQUE(challenge_id, artifact_id, role)
);
CREATE INDEX IF NOT EXISTS idx_chal_art_lookup ON challenge_artifacts(challenge_id, role, artifact_id, alias);
CREATE INDEX IF NOT EXISTS idx_chal_art_rev ON challenge_artifacts(artifact_id, challenge_id);

-- ----------------------------------------------------------------------------
-- 5. Jobs Table (CLI Runner Subsystem)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    tool_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    runtime TEXT NOT NULL DEFAULT 'native' CHECK (runtime IN ('native', 'wsl2', 'container', 'microvm')),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'preparing', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out', 'interrupted')),
    argv_json TEXT NOT NULL,
    input_refs_json TEXT NOT NULL DEFAULT '[]',
    exit_code INTEGER,
    timeout_ms INTEGER NOT NULL DEFAULT 60000 CHECK (timeout_ms > 0),
    timeout_triggered INTEGER NOT NULL DEFAULT 0 CHECK (timeout_triggered IN (0, 1)),
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_chal_state_created ON jobs(challenge_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_running_watchdog ON jobs(state, timeout_ms, started_at) WHERE state = 'running';
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);

-- ----------------------------------------------------------------------------
-- 6. Run Outputs Table (Spillover & Stream Heads/Tails)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS run_outputs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    stream_type TEXT NOT NULL CHECK (stream_type IN ('stdout', 'stderr', 'file', 'diagnostics')),
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    head_text TEXT,
    tail_text TEXT,
    dropped_bytes INTEGER NOT NULL DEFAULT 0 CHECK (dropped_bytes >= 0),
    diagnostics_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_run_outputs_job_stream ON run_outputs(job_id, stream_type);

-- ----------------------------------------------------------------------------
-- 7. Transform Steps Table (Recipe Lineage DAG)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transform_steps (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    recipe_id TEXT,
    step_order INTEGER NOT NULL CHECK (step_order >= 0),
    operation TEXT NOT NULL CHECK (operation IN ('hex_decode', 'hex_encode', 'base64_decode', 'base64_encode', 'xor', 'rot13', 'zlib_decompress', 'gzip_decompress', 'url_decode', 'custom_script')),
    parameters_json TEXT NOT NULL DEFAULT '{}',
    input_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    output_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    input_hash TEXT,
    output_hash TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_chal_recipe_order ON transform_steps(challenge_id, recipe_id, step_order);
CREATE INDEX IF NOT EXISTS idx_steps_in_art ON transform_steps(input_artifact_id);
CREATE INDEX IF NOT EXISTS idx_steps_out_art ON transform_steps(output_artifact_id);
CREATE INDEX IF NOT EXISTS idx_steps_lineage ON transform_steps(input_hash, output_hash);

-- ----------------------------------------------------------------------------
-- 8. Findings Table Evolution (CTF & DFIR Dual-Support)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings_v2 (
    id TEXT PRIMARY KEY,
    challenge_id TEXT REFERENCES challenges(id) ON DELETE CASCADE,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    observation TEXT,
    interpretation TEXT,
    description TEXT,
    byte_start INTEGER CHECK (byte_start IS NULL OR byte_start >= 0),
    byte_end INTEGER CHECK (byte_end IS NULL OR (byte_start IS NOT NULL AND byte_end >= byte_start)),
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('draft', 'confirmed', 'refuted', 'investigating', 'Open', 'Closed', 'Resolved')),
    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical', 'Info', 'Low', 'Medium', 'High', 'Critical')),
    mitre_technique TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO findings_v2 (
    id, challenge_id, case_id, title, observation, interpretation, description,
    byte_start, byte_end, evidence_refs, status, severity, mitre_technique, created_at, updated_at
)
SELECT
    id, NULL, case_id, title, description, NULL, description,
    NULL, NULL, '[]', status, severity, mitre_technique, created_at, updated_at
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_v2 RENAME TO findings;

CREATE INDEX IF NOT EXISTS idx_findings_chal_status ON findings(challenge_id, status) WHERE challenge_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_case_severity ON findings(case_id, severity) WHERE case_id IS NOT NULL;

-- ----------------------------------------------------------------------------
-- 9. Hypotheses Table Evolution (CTF & DFIR Dual-Support)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hypotheses_v2 (
    id TEXT PRIMARY KEY,
    challenge_id TEXT REFERENCES challenges(id) ON DELETE CASCADE,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    question TEXT,
    statement TEXT,
    planned_check TEXT,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'in_progress', 'confirmed', 'rejected', 'abandoned', 'Proposed', 'InProgress', 'Confirmed', 'Refuted')),
    conclusion TEXT,
    confidence REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at TEXT NOT NULL,
    evaluated_at TEXT
);

INSERT INTO hypotheses_v2 (
    id, challenge_id, case_id, title, question, statement, planned_check, evidence_refs, status, conclusion, confidence, created_at, evaluated_at
)
SELECT
    id, NULL, case_id, title, statement, statement, 'Verification inspection', '[]', status, NULL, confidence, created_at, evaluated_at
FROM hypotheses;

DROP TABLE hypotheses;
ALTER TABLE hypotheses_v2 RENAME TO hypotheses;

CREATE INDEX IF NOT EXISTS idx_hypotheses_chal_status ON hypotheses(challenge_id, status) WHERE challenge_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hypotheses_case_status ON hypotheses(case_id, status) WHERE case_id IS NOT NULL;

-- ----------------------------------------------------------------------------
-- 10. Flag Candidates Table (Verification Pipeline)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flag_candidates (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    provenance_run_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    provenance_artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    provenance_step_id TEXT REFERENCES transform_steps(id) ON DELETE SET NULL,
    pattern_match TEXT,
    verification_status TEXT NOT NULL DEFAULT 'candidate' CHECK (verification_status IN ('candidate', 'accepted', 'rejected')),
    rejection_reason TEXT,
    verified_at TEXT,
    submitted_to_platform INTEGER NOT NULL DEFAULT 0 CHECK (submitted_to_platform IN (0, 1)),
    created_at TEXT NOT NULL,
    UNIQUE(challenge_id, value)
);
CREATE INDEX IF NOT EXISTS idx_flags_chal_verif_value ON flag_candidates(challenge_id, verification_status, value);
CREATE INDEX IF NOT EXISTS idx_flags_unsubmitted ON flag_candidates(challenge_id, verification_status) WHERE verification_status = 'accepted' AND submitted_to_platform = 0;

-- ----------------------------------------------------------------------------
-- 11. Writeups Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS writeups (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL UNIQUE REFERENCES challenges(id) ON DELETE CASCADE,
    markdown_content TEXT NOT NULL DEFAULT '',
    exported_version INTEGER NOT NULL DEFAULT 1 CHECK (exported_version >= 1),
    summary TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ----------------------------------------------------------------------------
-- 12. Secrets Registry Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    challenge_id TEXT REFERENCES challenges(id) ON DELETE CASCADE,
    key_name TEXT NOT NULL,
    masked_placeholder TEXT NOT NULL UNIQUE,
    ciphertext_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(challenge_id, key_name)
);
CREATE INDEX IF NOT EXISTS idx_secrets_mask ON secrets(masked_placeholder);

-- ----------------------------------------------------------------------------
-- 13. Audit Events Table Evolution & Append-Only Triggers
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events_v2 (
    id TEXT PRIMARY KEY,
    challenge_id TEXT REFERENCES challenges(id) ON DELETE SET NULL,
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL DEFAULT 'system',
    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warn', 'error', 'critical', 'Info', 'Warn', 'Error', 'Critical')),
    actor_id TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    process_argv TEXT,
    outcome TEXT NOT NULL DEFAULT 'Success',
    details_json TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
);

INSERT INTO audit_events_v2 (
    id, challenge_id, case_id, event_type, severity, actor_id, action, resource_type, resource_id, process_argv, outcome, details_json, timestamp
)
SELECT
    id, NULL, case_id, 'audit', 'info', actor_id, action, resource_type, resource_id, NULL, outcome, details_json, timestamp
FROM audit_events;

DROP TABLE audit_events;
ALTER TABLE audit_events_v2 RENAME TO audit_events;

CREATE INDEX IF NOT EXISTS idx_audit_chal_ts ON audit_events(challenge_id, timestamp) WHERE challenge_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_case_ts ON audit_events(case_id, timestamp) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type);

CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'SecurityViolation: audit_events log is strictly append-only (UPDATE rejected)');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'SecurityViolation: audit_events log is strictly append-only (DELETE rejected)');
END;

-- ----------------------------------------------------------------------------
-- 14. Compatibility Views: Bridging CTF and DFIR Models
-- ----------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS v_legacy_cases AS
SELECT
    c.id AS case_id, c.title, c.description, c.status AS case_status,
    ch.id AS challenge_id, ch.competition_id, ch.category AS challenge_category,
    ch.points AS challenge_points, ch.status AS challenge_status, c.created_at, c.updated_at
FROM cases c LEFT JOIN challenges ch ON ch.case_id = c.id;

CREATE VIEW IF NOT EXISTS v_unified_artifacts AS
SELECT
    a.id AS artifact_id, COALESCE(a.blake3, a.hash_blake3) AS blake3, COALESCE(a.sha256, a.hash_sha256) AS sha256,
    a.original_name, COALESCE(a.size, a.file_size) AS size, COALESCE(a.detected_type, a.mime_type) AS detected_type,
    a.storage_state, ca.challenge_id, ca.role AS challenge_role, ca.alias AS challenge_alias,
    a.case_id, a.created_at
FROM artifacts a LEFT JOIN challenge_artifacts ca ON ca.artifact_id = a.id;

CREATE VIEW IF NOT EXISTS v_tool_runs_legacy AS
SELECT
    j.id AS run_id, j.challenge_id, ch.case_id, j.adapter AS adapter_name, j.runtime,
    j.state, j.argv_json, j.exit_code AS exit_status, j.timeout_triggered, j.started_at, j.completed_at
FROM jobs j LEFT JOIN challenges ch ON ch.id = j.challenge_id;

PRAGMA foreign_keys = ON;
