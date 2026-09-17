# 07. Database Architecture: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-07-DBARCH`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/04-solution-architect.md` & `docs/it-company/06-system-analyst.md`

---

## 1. Storage Strategy: SQLite WAL + Content-Addressed Storage (CAS)

The system leverages a hybrid storage model:
- **SQLite (WAL mode)**: Structured relational metadata, cases, facts, graph topology, and audit trails with immediate consistency and ACID safety.
- **CAS (Local File Repository)**: Append-only, content-addressed storage for heavy immutable binaries (PCAP files, disk images, EVTX dumps) addressed by `cas/<hash[0..2]>/<hash[2..4]>/<hash>`.

---

## 2. Entity-Relationship (ER) Diagram

```mermaid
erDiagram
    CASES ||--o{ ARTIFACTS : contains
    CASES ||--o{ AUDIT_LOG : tracks
    CASES ||--o{ TASKS : schedules
    ARTIFACTS ||--o{ OBSERVATIONS : yields
    OBSERVATIONS ||--o{ FACTS : supports
    FACTS ||--o{ ATTACK_NODES : correlates_to
    ATTACK_NODES ||--o{ ATTACK_EDGES : source_node
    ATTACK_NODES ||--o{ ATTACK_EDGES : target_node
    ATTACK_NODES ||--o{ TAXONOMY_MAPPINGS : projects_to

    CASES {
        TEXT id PK
        TEXT title
        TEXT status
        TEXT created_at
        TEXT updated_at
    }
    ARTIFACTS {
        TEXT id PK
        TEXT case_id FK
        TEXT hash_blake3
        TEXT hash_sha256
        TEXT original_name
        INTEGER file_size
        TEXT mime_type
        TEXT ingested_at
    }
    OBSERVATIONS {
        TEXT id PK
        TEXT artifact_id FK
        TEXT source_tool
        TEXT raw_event_type
        TEXT timestamp
        TEXT data_json
    }
    FACTS {
        TEXT id PK
        TEXT case_id FK
        TEXT observation_id FK
        TEXT entity_type
        TEXT entity_key
        TEXT fact_type
        REAL confidence
        TEXT data_json
        TEXT created_at
    }
    ATTACK_NODES {
        TEXT id PK
        TEXT case_id FK
        TEXT node_type
        TEXT label
        TEXT properties_json
        TEXT first_seen
        TEXT last_seen
    }
    ATTACK_EDGES {
        TEXT id PK
        TEXT case_id FK
        TEXT source_node_id FK
        TEXT target_node_id FK
        TEXT relation_type
        REAL confidence
        TEXT supporting_fact_id FK
    }
    TAXONOMY_MAPPINGS {
        TEXT id PK
        TEXT node_id FK
        TEXT framework
        TEXT technique_id
        TEXT tactic
        TEXT confidence
    }
```

---

## 3. Performance & Indexing Strategy
- `PRAGMA journal_mode = WAL;` — High concurrency, parallel readers while writer commits.
- `PRAGMA synchronous = NORMAL;` — Durability with high throughput for bulk event ingestion.
- `PRAGMA foreign_keys = ON;` — Referential integrity.
- **Covering Indexes**:
  - `idx_artifacts_case_hash` on `artifacts(case_id, hash_blake3)`
  - `idx_observations_artifact` on `observations(artifact_id, timestamp)`
  - `idx_facts_case_entity` on `facts(case_id, entity_type, entity_key)`
  - `idx_edges_source_target` on `attack_edges(case_id, source_node_id, target_node_id)`
  - `idx_taxonomy_node` on `taxonomy_mappings(node_id, framework)`
