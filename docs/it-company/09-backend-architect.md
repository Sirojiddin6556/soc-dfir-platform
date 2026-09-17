# 09. Backend Architecture & IPC Contract: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-09-BEARCH`  
**Status**: `FROZEN (Approved at Human Gate 2 on 2026-09-17)`  
**Baseline**: Human Gate 2 Architecture & Contract Gate

---

## 1. Domain Separation of Responsibilities

```mermaid
flowchart LR
    TA[ToolAdapter] -->|RawToolResult| NORM[NormalizerEngine]
    NORM -->|Observation[]| CORR[CorrelationEngine]
    CORR -->|Fact[]| EVID[EvidenceEngine]
    CORR & EVID -->|Facts + Evidence| GRAPH[GraphEngine]
    GRAPH -->|AttackGraph| TAX[TaxonomyProjector]
    TAX -->|TaxonomyCandidate[]| VERIF[ScenarioVerifier]
    VERIF -->|VerificationReport| SCORE[ScoringEngine]
```

### Critical Architectural Constraints:
- `ToolAdapter` produces strictly `RawToolResult`. It is prohibited from generating `Fact` or `AttackNode` entities.
- `NormalizerEngine` turns `RawToolResult` into standard `Observation[]`.
- `CorrelationEngine` derives `Fact[]` (with `AssertionType` and `VerificationState`).
- `GraphEngine` builds derived, explainable graph topologies with explicit `supported_by: [fact_id]` references.

---

## 2. Core Rust Traits & Interfaces

```rust
// crates/core-domain/src/traits.rs
use async_trait::async_trait;
use crate::models::*;

#[async_trait]
pub trait ToolAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn supported_inputs(&self) -> &'static [&'static str];
    async fn execute(&self, input: &ToolInput) -> Result<RawToolResult, ToolError>;
}

pub trait Normalizer: Send + Sync {
    fn tool_name(&self) -> &'static str;
    fn normalize(&self, raw: &RawToolResult) -> Result<Vec<Observation>, NormalizationError>;
}

#[async_trait]
pub trait CorrelationEngine: Send + Sync {
    async fn correlate(
        &self,
        case_id: &str,
        observations: &[Observation],
    ) -> Result<Vec<Fact>, CorrelationError>;
}

#[async_trait]
pub trait GraphEngine: Send + Sync {
    async fn build_graph(
        &self,
        case_id: &str,
        facts: &[Fact],
    ) -> Result<AttackGraph, GraphError>;

    async fn get_graph_delta(
        &self,
        case_id: &str,
        since_cursor: Option<&str>,
    ) -> Result<GraphDelta, GraphError>;
}

#[async_trait]
pub trait TaxonomyProjector: Send + Sync {
    async fn project_candidates(
        &self,
        case_id: &str,
        facts: &[Fact],
        evidence: &[Evidence],
        taxonomy: &TaxonomyVersion,
    ) -> Result<Vec<TaxonomyCandidate>, TaxonomyError>;
}

#[async_trait]
pub trait ScenarioVerifier: Send + Sync {
    async fn evaluate_investigation(
        &self,
        scenario_id: &str,
        player_case_id: &str,
    ) -> Result<VerificationReport, VerifierError>;
}
```

---

## 3. Versioned Local IPC API (JSON-RPC 2.0 & Streaming)

Every RPC call carries:
- `api_version: 1`
- `request_id: String` (UUIDv7)
- `case_id: Option<String>`

### Commands & Queries:
- `case.create(title, description)`
- `case.open(case_id)`
- `workflow.start(case_id, profile: "quick"|"standard"|"deep")`
- `workflow.cancel(task_id)`
- `graph.query(case_id, lod_level, bbox, cursor)` $\rightarrow$ `PaginatedNodes`
- `evidence.get(case_id, evidence_id)`
- `diagram.generate(case_id, diagram_type)`
- `scenario.verify(scenario_id, case_id)` $\rightarrow$ `ScoreBreakdown`

### Event Streams with Backpressure:
- `graph.subscribe_delta(case_id)` $\rightarrow$ Emits `GraphDelta` (added/updated nodes/edges in batches of $\le 500$, rate-limited).
- `workflow.subscribe_events(case_id)` $\rightarrow$ Emits task transitions (`READY`, `RUNNING`, `SUCCEEDED`, etc.).
