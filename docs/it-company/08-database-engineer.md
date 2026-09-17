# 08. Database Engineering (DDL & Migrations): Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-08-DBENG`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/07-database-architect.md`

---

## 1. Migration 001: Initial Schema (Data Contract v1)

```sql
-- Migration: 001_initial_schema.sql

PRAGMA foreign_keys = ON;

-- 1. Cases Table
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'Active', -- 'Active', 'Archived', 'Exported'
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 2. Artifacts Table (CAS Metadata)
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    hash_blake3 TEXT NOT NULL,
    hash_sha256 TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_hash ON artifacts(case_id, hash_blake3);

-- 3. Observations Table (Raw Parser Output)
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    source_tool TEXT NOT NULL,
    raw_event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_artifact_ts ON observations(artifact_id, timestamp);

-- 4. Facts Table (Extracted Security Facts)
CREATE TABLE IF NOT EXISTS facts (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    observation_id TEXT REFERENCES observations(id) ON DELETE SET NULL,
    entity_type TEXT NOT NULL, -- 'Process', 'Host', 'Socket', 'Identity', 'File'
    entity_key TEXT NOT NULL,  -- Canonical identifier (e.g. host:proc_guid, ip:port)
    fact_type TEXT NOT NULL,   -- 'SpawnedProcess', 'NetworkConnection', 'FileCreated'
    confidence REAL NOT NULL DEFAULT 1.0,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_facts_case_entity ON facts(case_id, entity_type, entity_key);
CREATE INDEX IF NOT EXISTS idx_facts_case_type ON facts(case_id, fact_type);

-- 5. Attack Graph Nodes
CREATE TABLE IF NOT EXISTS attack_nodes (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    node_type TEXT NOT NULL, -- 'Host', 'Process', 'NetworkSocket', 'Identity', 'Artifact', 'Tactic'
    label TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_case_type ON attack_nodes(case_id, node_type);

-- 6. Attack Graph Edges
CREATE TABLE IF NOT EXISTS attack_edges (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL, -- 'SPAWNED', 'CONNECTED_TO', 'WROTE_FILE', 'AUTHENTICATED_AS'
    confidence REAL NOT NULL DEFAULT 1.0,
    supporting_fact_id TEXT REFERENCES facts(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edges_case_src_tgt ON attack_edges(case_id, source_node_id, target_node_id);

-- 7. Multi-Taxonomy Mappings
CREATE TABLE IF NOT EXISTS taxonomy_mappings (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    framework TEXT NOT NULL,     -- 'MITRE_ATTACK', 'KILL_CHAIN', 'PYRAMID_OF_PAIN'
    technique_id TEXT NOT NULL,  -- e.g. 'T1059.001', 'Execution', 'NetworkArtifact'
    tactic TEXT,
    confidence REAL NOT NULL DEFAULT 1.0
);
CREATE INDEX IF NOT EXISTS idx_taxonomy_node_framework ON taxonomy_mappings(node_id, framework);

-- 8. Audit Log (Chain of Custody)
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_case_ts ON audit_log(case_id, timestamp);

-- 9. Workflow Tasks
CREATE TABLE IF NOT EXISTS workflow_tasks (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    task_type TEXT NOT NULL,
    status TEXT NOT NULL, -- 'CREATED', 'READY', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'
    resource_class TEXT NOT NULL, -- 'CPU', 'IO', 'NETWORK', 'FORENSIC'
    priority INTEGER NOT NULL DEFAULT 0,
    dependencies_json TEXT NOT NULL DEFAULT '[]',
    error_message TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_case_status ON workflow_tasks(case_id, status);
```
