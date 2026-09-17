# 08. Database Engineering (DDL & Migrations): Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-08-DBENG`  
**Status**: `FROZEN (Approved at Human Gate 2 on 2026-09-17)`  
**Baseline**: Human Gate 2 Architecture & Contract Gate

---

## 1. Migration 001: Initial Core Schema (Data Contract v2)

```sql
-- Migration: 001_initial_schema.sql
PRAGMA foreign_keys = ON;

-- 1. Cases Table
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY, -- UUIDv7
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'Active', -- 'Active', 'Archived', 'Exported'
    created_at TEXT NOT NULL,              -- UTC ISO-8601
    updated_at TEXT NOT NULL               -- UTC ISO-8601
);

-- 2. Artifacts Table (Dual-Hash CAS & Forensic Registration)
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    hash_blake3 TEXT NOT NULL, -- Internal CAS locator
    hash_sha256 TEXT NOT NULL, -- External / IOC standard hash
    original_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    acquisition_method TEXT NOT NULL,
    acquired_at TEXT NOT NULL, -- UTC ISO-8601
    ingested_at TEXT NOT NULL  -- UTC ISO-8601
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_blake3 ON artifacts(case_id, hash_blake3);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_sha256 ON artifacts(case_id, hash_sha256);

-- 3. Tool Runs (Forensic Provenance & Execution Tracking)
CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY, -- UUIDv7
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

-- 4. Observations Table (Raw Normalized Events from Tool Runs)
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    tool_run_id TEXT REFERENCES tool_runs(id) ON DELETE SET NULL,
    source_tool TEXT NOT NULL,
    raw_event_type TEXT NOT NULL,
    source_timestamp TEXT NOT NULL, -- UTC
    ingest_timestamp TEXT NOT NULL, -- UTC
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_artifact ON observations(artifact_id, source_timestamp);

-- 5. Facts Table (Multi-Dimensional Epistemic Assertions)
CREATE TABLE IF NOT EXISTS facts (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    observation_id TEXT REFERENCES observations(id) ON DELETE SET NULL,
    assertion_type TEXT NOT NULL,    -- 'Fact', 'Inference', 'Hypothesis'
    verification_state TEXT NOT NULL,-- 'Candidate', 'Corroborated', 'Confirmed', 'Disproved'
    entity_type TEXT NOT NULL,       -- 'Process', 'Host', 'Socket', 'Identity', 'File'
    entity_key TEXT NOT NULL,        -- Canonical deduplicated key
    fact_type TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,      -- 0.0 .. 1.0
    severity TEXT NOT NULL DEFAULT 'Info',     -- 'Info', 'Low', 'Medium', 'High', 'Critical'
    risk_score REAL NOT NULL DEFAULT 0.0,      -- 0.0 .. 100.0
    evidence_strength REAL NOT NULL DEFAULT 1.0,-- 0.0 .. 1.0
    pain_level TEXT,                           -- 'Hash', 'IP', 'Domain', 'NetworkArtifact', 'HostArtifact', 'Tool', 'TTP'
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_facts_entity ON facts(case_id, entity_type, entity_key);
CREATE INDEX IF NOT EXISTS idx_facts_assertion ON facts(case_id, assertion_type, verification_state);

-- 6. Evidence Aggregates
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY, -- UUIDv7
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

-- 7. Attack Graph Nodes (Event-Derived)
CREATE TABLE IF NOT EXISTS attack_nodes (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    node_type TEXT NOT NULL, -- 'Host', 'Process', 'Socket', 'Identity', 'Artifact', 'Tactic'
    label TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_case ON attack_nodes(case_id, node_type);

-- 8. Attack Graph Edges with Provenance
CREATE TABLE IF NOT EXISTS attack_edges (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    supported_by_json TEXT NOT NULL DEFAULT '[]', -- Array of Fact UUIDs
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edges_case ON attack_edges(case_id, source_node_id, target_node_id);

-- 9. Versioned Taxonomies
CREATE TABLE IF NOT EXISTS taxonomy_versions (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,      -- 'MITRE_ATTACK', 'KILL_CHAIN', 'PYRAMID_OF_PAIN'
    version TEXT NOT NULL,        -- 'v14.1', 'v1.0'
    release_date TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    imported_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS taxonomy_mappings (
    id TEXT PRIMARY KEY, -- UUIDv7
    node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    taxonomy_version_id TEXT NOT NULL REFERENCES taxonomy_versions(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,
    tactic TEXT,
    verification_state TEXT NOT NULL DEFAULT 'Candidate', -- 'Candidate', 'Corroborated', 'Confirmed'
    confidence REAL NOT NULL DEFAULT 1.0,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
    mapping_rule_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tax_mapping ON taxonomy_mappings(node_id, taxonomy_version_id);

-- 10. Diagram Snapshots
CREATE TABLE IF NOT EXISTS diagram_snapshots (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    diagram_type TEXT NOT NULL, -- 'AttackGraph', 'Timeline', 'Infrastructure', 'MitreMatrix'
    layout_data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 11. Append-Only Chain of Custody (Audit Trail)
CREATE TABLE IF NOT EXISTS custody_events (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL, -- 'ArtifactAcquired', 'ArtifactStored', 'ArtifactHashed', 'ArtifactParsed', 'ArtifactAccessed', 'ArtifactExported'
    artifact_hash TEXT,
    details_json TEXT NOT NULL,
    previous_state_hash TEXT NOT NULL, -- Cryptographic Merkle chain link
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custody_case_ts ON custody_events(case_id, timestamp);

-- 12. Workflow Tasks (Standardized 10-State Machine with 6 Resource Classes)
CREATE TABLE IF NOT EXISTS workflow_tasks (
    id TEXT PRIMARY KEY, -- UUIDv7
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    task_name TEXT NOT NULL,
    status TEXT NOT NULL, -- 'PENDING', 'READY', 'QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'BLOCKED', 'SKIPPED'
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
```
