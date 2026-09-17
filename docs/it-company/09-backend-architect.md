# 09. Backend Architecture & IPC Contract: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-09-BEARCH`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/04-solution-architect.md` & `docs/it-company/08-database-engineer.md`

---

## 1. Core Rust Traits & Domain Contracts

```rust
// crates/core-domain/src/traits.rs

use async_trait::async_trait;
use crate::models::*;

#[async_trait]
pub trait ToolAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn supported_mimes(&self) -> &'static [&'static str];
    async fn parse(
        &self,
        artifact_path: &std::path::Path,
        context: &ParseContext,
    ) -> Result<Vec<Observation>, ToolError>;
}

#[async_trait]
pub trait GraphEngine: Send + Sync {
    async fn update_from_facts(
        &self,
        case_id: &str,
        facts: &[Fact],
    ) -> Result<GraphUpdateResult, GraphError>;
    
    async fn get_attack_graph(
        &self,
        case_id: &str,
        filter: GraphFilter,
    ) -> Result<AttackGraph, GraphError>;
}

#[async_trait]
pub trait TaxonomyProjector: Send + Sync {
    async fn project_graph(
        &self,
        graph: &AttackGraph,
    ) -> Result<TaxonomyProjections, TaxonomyError>;
}

#[async_trait]
pub trait WorkflowEngine: Send + Sync {
    async fn submit_task(&self, task: WorkflowTask) -> Result<TaskId, WorkflowError>;
    async fn cancel_task(&self, task_id: &str) -> Result<(), WorkflowError>;
    async fn get_task_status(&self, task_id: &str) -> Result<TaskStatus, WorkflowError>;
}
```

---

## 2. Local IPC Protocol (JSON-RPC / MessagePack over Pipe)

### Message Format
```json
{
  "jsonrpc": "2.0",
  "id": "req-101",
  "method": "cases.ingest_artifact",
  "params": {
    "case_id": "case-991",
    "file_path": "C:\\Forensics\\incident.evtx",
    "parser_hint": "evtx"
  }
}
```

### IPC API Methods Specification
1. `cases.create(title, description)` $\rightarrow$ `Case`
2. `cases.list()` $\rightarrow$ `Vec<CaseSummary>`
3. `cases.ingest_artifact(case_id, file_path)` $\rightarrow$ `ArtifactRecord`
4. `workflow.get_tasks(case_id)` $\rightarrow$ `Vec<WorkflowTask>`
5. `workflow.cancel_task(task_id)` $\rightarrow$ `bool`
6. `graph.get_attack_graph(case_id, filters)` $\rightarrow$ `AttackGraph`
7. `graph.get_projections(case_id)` $\rightarrow$ `TaxonomyProjections` (MITRE ATT&CK Matrix, Kill Chain, Pyramid of Pain)
8. `broker.execute_probe(probe_id, sanitized_args)` $\rightarrow$ `Stream<ProbeEvent>`
