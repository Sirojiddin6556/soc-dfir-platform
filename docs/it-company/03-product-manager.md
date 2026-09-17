# 03. Product Manager: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-03-PRODUCT`  
**Status**: `APPROVED / SCOPE FROZEN`  
**Baseline**: Human Gate 1 Scope Freeze

---

## 1. Product Epics Breakdown (P0 Scope)

### Epic 1: Domain, Forensic Storage & Case Workspace (P0)
- **Feature 1.1**: SQLite WAL storage layer with foreign keys and migrations (`REQ-DATA-01`).
- **Feature 1.2**: Content-Addressed Storage (CAS) on BLAKE3 (internal address) + SHA-256 (forensic hash).
- **Feature 1.3**: Cryptographic, append-only Chain of Custody tracking with Merkle-linked `previous_state_hash`.

### Epic 2: Automated Infrastructure & Host Discovery (P0)
- **Feature 2.1**: Network & Asset Discovery (active hosts, IP, interfaces, routing tables, open ports) (`REQ-DISC-01`).
- **Feature 2.2**: Deep Host Inspection (processes, services, cron/systemd, Scheduled Tasks, autoruns, sockets) (`REQ-HOST-01`).

### Epic 3: Software Discovery, SBOM & Vulnerability Pipeline (P0)
- **Feature 3.1**: Software inventory extraction and SBOM synthesis (CPE/PURL standard) (`REQ-VULN-01`).
- **Feature 3.2**: Multi-source vulnerability enrichment (CVE, CVSS, EPSS, CISA KEV) with Linux backport false-positive suppression.

### Epic 4: Ingestion, Normalization & Correlation Engine (P0)
- **Feature 4.1**: Modular `ToolAdapter` interface producing pure `RawToolResult`.
- **Feature 4.2**: `NormalizerEngine` transforming raw results into standardized `Observation[]`.
- **Feature 4.3**: `CorrelationEngine` synthesizing `Observation[]` into typed `Fact[]` (`Fact`, `Inference`, `Hypothesis`) with multi-dimensional confidence.
- **Feature 4.4**: `EvidenceEngine` aggregating supporting facts into verifiable `Evidence` units.

### Epic 5: Deterministic Attack Graph, Timeline & Taxonomy Projections (P0)
- **Feature 5.1**: Event-derived `AttackGraph` with `supported_by` fact provenance on all edges (`REQ-GRAPH-01`).
- **Feature 5.2**: Multi-host horizontal chronological timeline with lanes and filtering.
- **Feature 5.3**: Versioned taxonomy projection (MITRE ATT&CK Enterprise, Cyber Kill Chain, Pyramid of Pain) emitting `TaxonomyCandidate[]` (`REQ-TAX-01`).

### Epic 6: Workflow Automation DAG & Resource Budgets (P0)
- **Feature 6.1**: Conditional DAG execution with restricted expression DSL (`REQ-AUTO-01`).
- **Feature 6.2**: Standardized profiles (`Quick → Standard → Deep`) with auto-escalation upon anomaly detection.
- **Feature 6.3**: 6 resource semaphores (`CPU`, `IO`, `NET`, `MEMORY`, `FORENSIC`, `TARGET_LOAD`).

### Epic 7: Privilege Broker & Security Boundaries (P0)
- **Feature 7.1**: Unprivileged Desktop UI communicating via local IPC (`REQ-SEC-01`).
- **Feature 7.2**: Hardened Broker validating caller capabilities and executing strictly typed `PrivilegedOperation` without shell execution.

### Epic 8: Visual Intelligence & Desktop Cockpit (P0/P1)
- **Feature 8.1**: 3-pane desktop workspace (Sidebar, Canvas, Inspector) (`REQ-VIZ-01`).
- **Feature 8.2**: Geometry-based visual encoding (circle, hexagon, diamond, square, octagon) conforming to NFR-UX-002.
- **Feature 8.3**: Interactive views: Infrastructure Map, Attack Graph, Timeline, ATT&CK Matrix.

### Epic 9: Scenario Engine, Isolated Ground Truth & Scoring (P0)
- **Feature 9.1**: Cryptographically signed scenario bundles (`REQ-SCEN-01`).
- **Feature 9.2**: Sealed Ground Truth inaccessible to player queries or SQLite database.
- **Feature 9.3**: Multi-dimensional explainable scoring across 10 investigation criteria.

---

## 2. Realigned Sprint Roadmap

```
Sprint 1: Domain / Storage / CAS / SQLite WAL
   │
   ▼
Sprint 2: Workflow DAG / Automation / Resource Limiter
   │
   ▼
Sprint 3: Discovery / Normalization / Ingestion Adapters
   │
   ▼
Sprint 4: Evidence / Correlation / Graph Engine / Timeline
   │
   ▼
Sprint 5: Versioned Taxonomy / Diagram Engine / Desktop UI
   │
   ▼
Sprint 6: Scenario Engine / Isolated Ground Truth Verifier / Scoring Engine
```
