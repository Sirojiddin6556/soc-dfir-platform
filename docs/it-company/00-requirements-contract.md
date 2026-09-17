# 00. REQUIREMENTS CONTRACT: Blue Team Cyber Range & SOC/DFIR Platform

**Status**: `APPROVED / SCOPE FROZEN (Authoritative Requirements Baseline)`  
**Baseline Date**: 2026-09-17  
**Gate Resolution**: HUMAN GATE 1 — APPROVED. Product vision, MVP scope, functional/non-functional requirements, user roles, automation principles, platform boundaries and explicit out-of-scope items are accepted as the authoritative requirements baseline for Stage 2 architecture.

---

## 1. Product Vision
**SOC-DFIR Platform** — локальная deterministic desktop Blue Team-платформа, которая автоматически исследует неизвестную инфраструктуру, собирает и нормализует security evidence, определяет assets/software/vulnerabilities, строит доказуемый Attack Graph и Timeline, сопоставляет поведение противника с MITRE ATT&CK, Cyber Kill Chain и Pyramid of Pain и позволяет проводить воспроизводимые SOC/DFIR/Threat Hunting/CTF-расследования со скрытым Ground Truth и объяснимым scoring.

---

## 2. Invariants & Scope Baseline (P0 Scope)
1. **Deterministic Architecture**: Zero autonomous probabilistic LLM agent loops. Every fact, relationship, and taxonomy mapping is derived from deterministic rules and verifiable telemetry.
2. **Infrastructure & Asset Discovery**: Automated network scanning, port enumeration, host discovery, process inspection, autorun extraction, and scheduled tasks baseline.
3. **Software, SBOM & Vulnerability Pipeline**: Asset $\rightarrow$ Software $\rightarrow$ CPE/PURL $\rightarrow$ SBOM $\rightarrow$ CVE/CVSS/EPSS/KEV with Linux backport false-positive suppression.
4. **Multi-Stage Workflow Automation**: Conditional DAG engine with profiles (`Quick → Standard → Deep`) and 6 resource budgets (`CPU`, `IO`, `NET`, `MEMORY`, `FORENSIC`, `TARGET_LOAD`).
5. **Epistemic Data Pipeline**:
   - `Artifact` $\rightarrow$ `Observation` $\rightarrow$ `Fact` $\rightarrow$ `Evidence / EvidenceSet` $\rightarrow$ `Correlation` $\rightarrow$ `Attack Graph` $\rightarrow$ `Finding`.
   - `AssertionType`: `Fact`, `Inference`, `Hypothesis`.
   - `VerificationState`: `Candidate`, `Corroborated`, `Confirmed`, `Disproved`.
6. **Privilege Boundary**: Unprivileged UI; hardened Broker executing strictly typed `PrivilegedOperation` items with capability checks. Shell execution (`no sh -c`) and arbitrary argv from UI are prohibited.
7. **Visual Intelligence**: Interactive projections (Infrastructure, Attack Graph, Timeline, ATT&CK Matrix) with geometry-based shape encoding (NFR-UX-002) and fact drill-down.
8. **Scenario Verification & Scoring**: Sealed, isolated Ground Truth; multidimensional explainable scoring instead of flag-centric CTF.
9. **Platform Tiers**: Windows (Tier 1), Linux (Tier 1), macOS (Future / Tier 2).

---

## 3. Measurable NFR Targets
- **NFR-PERF-001**: Ingestion throughput $\ge 50{,}000$ events/sec on quad-core x86_64 NVMe.
- **NFR-PERF-002**: Query latency $<100$ ms (p95) for $10^6$ indexed facts in SQLite WAL.
- **NFR-DET-001**: Canonical deterministic equivalence under identical `dataset_version + engine_version + rules_version + taxonomy_version`.
