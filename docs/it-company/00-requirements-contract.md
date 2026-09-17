# 00. REQUIREMENTS CONTRACT: Blue Team Cyber Range & SOC/DFIR Platform

**Status**: `VERIFIED (Approved at Human Gate 1 on 2026-09-17)`  
**Baseline Date**: 2026-09-17  
**Traceability Baseline**: `D:\BlueTeam_CyberRange_TZ_v1.0.docx` (ТЗ v1.0) & `docs/it-company/01..03`

---

## 1. Problem Statement
Security Operations Center (SOC) and Digital Forensics / Incident Response (DFIR) teams face high operational friction when analyzing disparate forensic artifacts (EVTX, PCAP, memory dumps, file systems). Existing enterprise SIEMs are complex and cloud-heavy, while emerging autonomous AI tools suffer from hallucination and lack evidentiary integrity. Analysts require an offline-first, high-performance, deterministic desktop platform that converts raw data into verified attack graphs mapped to industry standards (MITRE ATT&CK, Kill Chain, Pyramid of Pain).

---

## 2. Business & Technical Goals
1. **Evidence Integrity**: Guarantee strict chain-of-custody and immutable storage (CAS) with cryptographic hashing.
2. **Deterministic Investigation**: 100% reproducible analysis without non-deterministic AI agent loops.
3. **High Performance & Safety**: Sub-second query response over millions of events; memory-safe implementation in Rust.
4. **Cross-Platform & Isolated Security**: Run unprivileged UI on Windows, Linux, and macOS with a hardened local privilege broker for elevated forensics operations.

---

## 3. Actors & Personas
- **SOC Analyst**: Rapid triage, fact exploration, correlation inspection.
- **DFIR Lead**: Deep forensic investigation, timeline analysis, raw artifact examination.
- **Cyber Range Instructor**: Scenario creation, answer/flag evaluation against deterministic facts.
- **System Admin**: Workspace and broker configuration, data export.

---

## 4. Use Cases
- **UC-01**: Ingest raw artifacts (EVTX, PCAP) into Case Workspace with automatic BLAKE3/SHA-256 CAS hashing.
- **UC-02**: Execute multi-stage parsers to extract `Observation` and synthesize `Fact` objects.
- **UC-03**: Automatically build and traverse the `Attack Graph` with explainable entity linkages.
- **UC-04**: Project attack paths synchronously into MITRE ATT&CK, Cyber Kill Chain, and Pyramid of Pain.
- **UC-05**: Run privileged probes (raw socket, ETW) safely via the local Broker over secure IPC.

---

## 5. Functional Requirements (FR Traceability)
- **`REQ-CASE-01` (FR-CASE-001)**: Isolated Case Storage with SQLite WAL and ACID compliance.
- **`REQ-CASE-02` (FR-CASE-002)**: Content-Addressed Storage (CAS) for immutable forensic artifacts.
- **`REQ-DATA-01` (FR-DATA-001)**: 4-Tier Data Pipeline: `Observation` → `Fact` → `Inference` → `Hypothesis`.
- **`REQ-GRAPH-01` (FR-GRAPH-001)**: Deterministic Attack Graph Engine with typed nodes and directional edges.
- **`REQ-MAP-01` (FR-MAP-001)**: Synchronous projection onto MITRE ATT&CK, Cyber Kill Chain, and Pyramid of Pain.
- **`REQ-WORK-01` (FR-WORK-001)**: Workflow DAG engine with resource semaphores (`CPU`, `IO`, `NETWORK`, `FORENSIC`) and cooperative cancellation.
- **`REQ-SEC-01` (FR-SEC-001)**: Privilege separation: Unprivileged UI + Local Privilege Broker with command allowlist.

---

## 6. Non-Functional Requirements (NFR)
- **NFR-PERF-001**: Ingestion throughput $\ge 50{,}000$ events/sec for EVTX/PCAP; query response $<100$ ms for $10^6$ facts.
- **NFR-SEC-001**: Least privilege enforcement; no arbitrary shell command execution; all arguments sanitized against strict regex.
- **NFR-REL-001**: Zero data corruption on abrupt application shutdown via SQLite WAL and CAS atomic writes.
- **NFR-UX-001**: Accessible visualization (WCAG / NFR-UX-002: graph states and statuses distinguishable by shape/text, not color alone).

---

## 7. Conditional Roles Decision Matrix
- **Roles 13–15 (ML/CV Block)**: `SKIPPED` (Explicit requirement: deterministic heuristics only, no LLM planners).
- **Role 20a (Data Visualization)**: `REQUIRED` (Complex attack graphs, timelines, MITRE matrices).
- **Role 26a (Accessibility Auditor)**: `REQUIRED` (Enforcing shape/text distinction in charts and graphs).
- **Role 31 (SRE)**: `SKIPPED` (Local workstation / lab deployment; no 24/7 cloud service SLA in MVP).

---

## 8. Out of Scope (Explicit)
- Non-deterministic probabilistic LLM agents or autonomous action loops.
- Cloud-only synchronization or compulsory external telemetry.
- Direct root/admin execution of the desktop UI.
