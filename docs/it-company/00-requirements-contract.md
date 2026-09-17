# 00. REQUIREMENTS CONTRACT: Blue Team Cyber Range & SOC/DFIR Platform

**Status**: `FROZEN (Approved at Human Gate 2 on 2026-09-17)`  
**Baseline Date**: 2026-09-17  
**Traceability Baseline**: `D:\BlueTeam_CyberRange_TZ_v1.0.docx` (ТЗ v1.0) & Human Gate 2 Directives

---

## 1. Problem Statement & System Invariants
Security Operations Center (SOC) and Digital Forensics / Incident Response (DFIR) teams require an offline-first, high-performance, deterministic desktop platform that transforms raw forensic artifacts into verified, explainable attack graphs mapped to industry taxonomies.

### Frozen Invariants:
1. **Zero Autonomous AI / LLM Loops**: All deductions are derived via deterministic parsers, heuristics, and graph correlation rules.
2. **Strict Privilege Separation**: UI runs completely unprivileged; no command execution or raw `argv[]` passing from UI. Broker executes only typed `PrivilegedOperation` items with checked capabilities.
3. **Shell Prohibition**: Execution of `sh -c`, `cmd.exe /c`, `powershell -Command`, or arbitrary binaries is strictly prohibited.
4. **Epistemic Separation**: Strict distinction between `AssertionType` (Fact, Inference, Hypothesis) and `VerificationState` (Candidate, Corroborated, Confirmed, Disproved).
5. **Multi-Dimensional Confidence**: `confidence`, `severity`, `risk_score`, `evidence_strength`, and IOC `pain_level` are evaluated as separate dimensions.
6. **Dual-Hash CAS**: BLAKE3 internal locator + SHA-256 standard external/forensic identification.
7. **Append-Only Custody**: Chain of custody events are append-only with Merkle back-links (`previous_state_hash`); no `audit.delete`.
8. **Ground Truth Isolation**: Scenario ground truth is sealed and restricted to `scenario-verifier`.

---

## 2. Core Functional Pipeline Contract

```
Artifact -> Observation -> Fact -> Evidence/EvidenceSet -> Finding/Attack Node -> Taxonomy Mapping
```

- **`ToolAdapter`**: Emits strictly `RawToolResult`.
- **`NormalizerEngine`**: Converts `RawToolResult` into `Observation[]`.
- **`CorrelationEngine`**: Synthesizes `Observation[]` into `Fact[]`.
- **`EvidenceEngine`**: Groups `Fact[]` into `Evidence` aggregates.
- **`GraphEngine`**: Builds event-derived `AttackGraph` with `supported_by` fact provenance on all edges.
- **`TaxonomyProjector`**: Projects `TaxonomyCandidate[]` against versioned taxonomy matrices.
- **`ScenarioVerifier` & `ScoringEngine`**: Multi-dimensional verification against ground truth (assets, facts, evidence, relationships, timeline, taxonomy, containment).

---

## 3. Scale & Platform Targets
- **Scale Capacity**: 100,000+ graph nodes, 1,000,000+ edges/events, 1,000,000+ timeline rows via LOD, clustering, and virtualization.
- **Platforms**: Windows (Tier 1), Linux (Tier 1), macOS (Tier 2 / future).
- **Tooling & Safety**: `#![forbid(unsafe_code)]` default across crates; safe wrappers in platform crates.
