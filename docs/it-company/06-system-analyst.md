# 06. System Analysis Document: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-06-SYSAN`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/04-solution-architect.md` & `docs/it-company/02-business-analyst.md`

---

## 1. End-to-End Ingestion & Investigation Sequence

```mermaid
sequenceDiagram
    actor Analyst as SOC / DFIR Analyst
    participant UI as Desktop Cockpit
    participant Engine as Engine Core Daemon
    participant CAS as CAS Storage
    participant DB as SQLite WAL DB
    participant Sched as DAG Scheduler
    participant Parser as Tool Adapter (EVTX/PCAP)
    participant Graph as Graph Engine

    Analyst->>UI: Import Evidence (file: memory.raw / security.evtx)
    UI->>Engine: IngestArtifact(case_id, file_path)
    Engine->>CAS: Compute BLAKE3 & Store in CAS
    CAS-->>Engine: ArtifactHash & Metadata
    Engine->>DB: INSERT into artifacts & audit_log
    Engine->>Sched: SpawnTask(Task::ParseArtifact(hash))
    Sched->>Parser: Execute Parser (streaming)
    Parser->>DB: INSERT Observations & Extracted Facts
    DB-->>Sched: Ingestion Complete
    Sched->>Graph: Trigger Graph Construction(case_id)
    Graph->>DB: Read Facts & Match Graph Rules
    Graph->>DB: INSERT/UPDATE attack_nodes & attack_edges
    Graph->>Engine: Notify GraphUpdated(case_id)
    Engine->>UI: Push Event(GraphChanged)
    UI->>Analyst: Render Updated Attack Graph & Timeline
```

---

## 2. Task Execution State Machine

```mermaid
stateDiagram-v2
    [*] --> CREATED: User / Workflow schedules task
    CREATED --> PLANNED: Dependencies analyzed
    PLANNED --> WAITING_DEPENDENCIES: Blocked on prerequisite task
    WAITING_DEPENDENCIES --> READY: All input dependencies VERIFIED
    PLANNED --> READY: No dependencies
    READY --> RUNNING: Resource semaphore acquired (CPU/IO/NET)
    RUNNING --> RUNNING: Progress emitted (stream)
    RUNNING --> CANCELLED: Cooperative cancellation token fired
    RUNNING --> TIMEOUT: Task budget exceeded
    RUNNING --> FAILED: Parser / tool error (malformed data)
    RUNNING --> COMPLETED: Success, facts written to DB
    COMPLETED --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
    TIMEOUT --> [*]
```

---

## 3. Fact & Evidence Confidence State Machine

```mermaid
stateDiagram-v2
    [*] --> RAW_OBSERVATION: Parsed from binary log/pcap
    RAW_OBSERVATION --> UNVERIFIED_FACT: Extracted by deterministic heuristic
    UNVERIFIED_FACT --> CORROBORATED_FACT: Cross-verified with 2nd source (confidence >= 0.8)
    UNVERIFIED_FACT --> REFUTED: Contradictory evidence discovered
    CORROBORATED_FACT --> ATTACK_NODE: Mapped to entity in Attack Graph
    ATTACK_NODE --> TAXONOMY_PROJECTION: Mapped to MITRE ATT&CK Technique
    TAXONOMY_PROJECTION --> [*]
```
