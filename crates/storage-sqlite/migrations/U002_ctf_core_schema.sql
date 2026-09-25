-- ============================================================================
-- Migration: U002_ctf_core_schema.sql (DOWN / Rollback)
-- Description: Reverts CTF Core Schema to SOC-DFIR MIGRATION_001_SQL Baseline
-- Compatibility: Restores exact original 21 baseline tables and schemas
-- ============================================================================

PRAGMA foreign_keys = OFF;

-- ----------------------------------------------------------------------------
-- 1. Drop Compatibility Views
-- ----------------------------------------------------------------------------
DROP VIEW IF EXISTS v_tool_runs_legacy;
DROP VIEW IF EXISTS v_unified_artifacts;
DROP VIEW IF EXISTS v_legacy_cases;

-- ----------------------------------------------------------------------------
-- 2. Drop Triggers
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_audit_no_update;
DROP TRIGGER IF EXISTS trg_audit_no_delete;
DROP TRIGGER IF EXISTS trg_artifacts_legacy_sync;

-- ----------------------------------------------------------------------------
-- 3. Revert audit_events to V001 Baseline
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events_v1 (
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

INSERT INTO audit_events_v1 (
    id, case_id, actor_id, action, resource_type, resource_id, outcome, details_json, timestamp
)
SELECT
    id, case_id, actor_id, action, resource_type, resource_id, outcome, details_json, timestamp
FROM audit_events;

DROP TABLE audit_events;
ALTER TABLE audit_events_v1 RENAME TO audit_events;
CREATE INDEX IF NOT EXISTS idx_audit_events_case_ts ON audit_events(case_id, timestamp);

-- ----------------------------------------------------------------------------
-- 4. Drop CTF Specific Standalone Tables
-- ----------------------------------------------------------------------------
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS writeups;
DROP TABLE IF EXISTS flag_candidates;

-- ----------------------------------------------------------------------------
-- 5. Revert hypotheses to V001 Baseline
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hypotheses_v1 (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    statement TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Proposed',
    confidence REAL NOT NULL DEFAULT 0.5,
    created_at TEXT NOT NULL,
    evaluated_at TEXT
);

INSERT INTO hypotheses_v1 (
    id, case_id, title, statement, status, confidence, created_at, evaluated_at
)
SELECT
    id, COALESCE(case_id, '00000000-0000-0000-0000-000000000000'), title,
    COALESCE(statement, question, title), status, confidence, created_at, evaluated_at
FROM hypotheses
WHERE case_id IS NOT NULL;

DROP TABLE hypotheses;
ALTER TABLE hypotheses_v1 RENAME TO hypotheses;
CREATE INDEX IF NOT EXISTS idx_hypotheses_case ON hypotheses(case_id, status);

-- ----------------------------------------------------------------------------
-- 6. Revert findings to V001 Baseline
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings_v1 (
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

INSERT INTO findings_v1 (
    id, case_id, title, description, severity, status, mitre_technique, created_at, updated_at
)
SELECT
    id, COALESCE(case_id, '00000000-0000-0000-0000-000000000000'), title,
    COALESCE(description, observation), severity, status, mitre_technique, created_at, updated_at
FROM findings
WHERE case_id IS NOT NULL;

DROP TABLE findings;
ALTER TABLE findings_v1 RENAME TO findings;
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id, severity);

-- ----------------------------------------------------------------------------
-- 7. Drop Lineage and Execution Tables
-- ----------------------------------------------------------------------------
DROP TABLE IF EXISTS transform_steps;
DROP TABLE IF EXISTS run_outputs;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS challenge_artifacts;

-- ----------------------------------------------------------------------------
-- 8. Revert artifacts to V001 Baseline
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS artifacts_v1 (
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

INSERT INTO artifacts_v1 (
    id, case_id, hash_blake3, hash_sha256, original_name, file_size, mime_type, acquisition_method, acquired_at, ingested_at
)
SELECT
    id, case_id, COALESCE(hash_blake3, blake3), COALESCE(hash_sha256, sha256), original_name,
    COALESCE(file_size, size, 0), COALESCE(mime_type, detected_type, 'application/octet-stream'),
    COALESCE(acquisition_method, 'cas_ingest'), COALESCE(acquired_at, created_at), COALESCE(ingested_at, created_at)
FROM artifacts
WHERE case_id IS NOT NULL;

DROP TABLE artifacts;
ALTER TABLE artifacts_v1 RENAME TO artifacts;
CREATE INDEX IF NOT EXISTS idx_artifacts_case_blake3 ON artifacts(case_id, hash_blake3);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_sha256 ON artifacts(case_id, hash_sha256);

-- ----------------------------------------------------------------------------
-- 9. Drop Challenges and Competitions
-- ----------------------------------------------------------------------------
DROP TABLE IF EXISTS challenges;
DROP TABLE IF EXISTS competitions;

PRAGMA foreign_keys = ON;
