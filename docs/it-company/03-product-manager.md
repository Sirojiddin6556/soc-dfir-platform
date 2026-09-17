# 03. Product Manager: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-03-PRODUCT`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/01-product-discovery-manager.md` & `docs/it-company/02-business-analyst.md`

---

## 1. Epics & Feature Breakdown

### Epic 1: Forensic Storage & Case Workspace (P0 - MVP)
- **Feature 1.1**: SQLite Case Engine with WAL mode, schema migrations, and metadata tracking (`REQ-CASE-01`).
- **Feature 1.2**: Content-Addressed Storage (CAS) with BLAKE3/SHA-256 deduplication and immutability (`REQ-CASE-02`).
- **Feature 1.3**: Cryptographic Chain of Custody logging and audit trails.

### Epic 2: Deterministic Ingestion & Fact Pipeline (P0 - MVP)
- **Feature 2.1**: Extensible `ToolAdapter` interface for raw log parsers (EVTX, PCAP, Sysmon, Auditd) (`REQ-DATA-01`).
- **Feature 2.2**: 4-Tier Data Model: Observation → Fact → Inference → Hypothesis (`REQ-DATA-01`).
- **Feature 2.3**: Correlation Rules Engine with confidence scoring $\in [0.0, 1.0]$.

### Epic 3: Deterministic Attack Graph & Taxonomy Mappings (P0 - MVP)
- **Feature 3.1**: Attack Graph construction (Entities: Host, Process, NetworkSocket, User, File; Edges: Spawned, Connected, Wrote, Authenticated) (`REQ-GRAPH-01`).
- **Feature 3.2**: Multi-Taxonomy Projection Engine: MITRE ATT&CK Matrix, Cyber Kill Chain, Pyramid of Pain (`REQ-MAP-01`).

### Epic 4: Workflow DAG & Resilient Scheduling (P0 - MVP)
- **Feature 4.1**: Directed Acyclic Graph (DAG) task engine with cooperative cancellation and time budgets (`REQ-WORK-01`).
- **Feature 4.2**: Resource-class semaphores (`CPU`, `IO`, `NETWORK`, `FORENSIC`) preventing system lockups.

### Epic 5: Privileged Broker & Security Architecture (P0 - MVP)
- **Feature 5.1**: Unprivileged Desktop Shell with secure local IPC (named pipes / UNIX domain sockets) (`REQ-SEC-01`).
- **Feature 5.2**: Local Broker daemon enforcing strict argument allowlists and isolated process spawning.

### Epic 6: Interactive Desktop UI & Investigation Cockpit (P1 - MVP+)
- **Feature 6.1**: Multi-host timeline visualizer with lanes, zoom, and time-range filtering (`REQ-VIZ-01`).
- **Feature 6.2**: Graph viewer with accessible shapes/badges and MITRE matrix view.
- **Feature 6.3**: Evidence inspector and report exporter (JSON, STIX 2.1).

---

## 2. Definition of Done (DoD)
1. **Code Quality**: Code formatted according to standard conventions (e.g. `cargo fmt` & `cargo clippy`), zero compiler warnings.
2. **Deterministic Behavior**: Identical raw inputs produce bit-for-bit or entity-for-entity identical `Fact` and `AttackGraph` outputs.
3. **Traceability**: Every generated Fact, Inference, and Graph Edge references its origin `Observation` or rule ID.
4. **Security Check**: Privileged operations execute strictly through the Broker; UI runs with standard user privileges.
5. **Testing**: 100% of P0 Acceptance Criteria verified with automated unit and integration tests; zero memory leaks.

---

## 3. Sprint Roadmap (MVP Execution)
- **Sprint 1 (Core Engine & Storage)**:
  - Rust workspace setup, SQLite storage layer, CAS file repository, and `Observation`/`Fact` schemas.
- **Sprint 2 (Workflow DAG & Graph Engine)**:
  - DAG scheduler with resource budgets, parsers execution, entity deduplication, and Attack Graph builder.
- **Sprint 3 (Taxonomy Mappings & Broker IPC)**:
  - MITRE ATT&CK / Kill Chain projections, IPC protocol, and Local Privilege Broker.
- **Sprint 4 (Desktop UI & End-to-End Integration)**:
  - Investigation Cockpit, timeline & graph visualization, automated CTF verification test harness.
