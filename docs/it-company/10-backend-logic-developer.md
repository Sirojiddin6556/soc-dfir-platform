# 10. Backend Business Logic Implementation Report

**Profile ID**: `PRF-10-BELOGIC`  
**Status**: `VERIFIED`  
**Crates Delivered**:
- `core-domain` (EntityId, Epistemic, Dual-Hash, Fact, Evidence, Graph, Taxonomy, Workflow, Broker)
- `storage-cas` (Content-Addressed Storage on BLAKE3 + SHA-256)
- `storage-sqlite` (SQLite WAL repository: cases, artifacts, observations, facts, custody)
- `workflow-dag` (10-state machine, 6 resource semaphores, DAG dependency scheduler)
- `normalization-engine` (Generic, EVTX Security, Sysmon normalizers)
- `correlation-engine` (Credential dump, Scheduled Tasks, Reconnaissance, Obfuscation heuristics)
- `evidence-engine` (Multi-fact evidence aggregation and confidence weighting)
- `tool-adapters` (EVTX, PCAP, Host discovery adapters emitting pure RawToolResult)
- `privilege-broker` (Capability verification and typed PrivilegedOperation validation)
- `graph-engine` (Deterministic Attack Graph construction with explainable `supported_by` fact links)
- `timeline-engine` (Chronological multi-host event timeline)
- `taxonomy-projection` (Versioned ATT&CK technique candidates)
- `scenario-verifier` (Sealed Ground Truth evaluator)
- `scoring-engine` (Explainable scoring summary)
- `diagram-engine` (NFR-UX-002 shape encoding)
- `report-engine` (Incident findings & containment actions)

---

## 1. Summary of Implementation

1. **Epistemic Segregation**:
   - `AssertionType` (`Fact`, `Inference`, `Hypothesis`) and `VerificationState` (`Candidate`, `Corroborated`, `Confirmed`, `Disproved`) are strictly separated into different enum types.
   - Multi-dimensional scoring parameters (`confidence`, `severity`, `risk_score`, `evidence_strength`, `pain_level`) are calculated per fact.

2. **Zero Unvalidated Execution Boundary**:
   - `ToolAdapter` creates strictly `RawToolResult`. It cannot directly instantiate `Fact` or `AttackNode` entities.
   - `PrivilegeBroker` rejects any raw string or arbitrary executable arguments. Only predefined `PrivilegedOperation` items with checked `BrokerCapability` can run.

3. **Storage & Chain of Custody**:
   - `ContentAddressedStorage` automatically calculates `BLAKE3` (internal path indexing `cas/ab/cd/...`) and `SHA-256` (external forensic standard).
   - `SqliteStorage` enforces WAL mode, foreign keys, and atomic case/artifact/fact transactions.
   - `CustodyEvent` records append-only Merkle-chained history (`previous_state_hash`).

4. **Workflow DAG Automation**:
   - Implemented dependency graph resolution in `WorkflowScheduler`: tasks remain `Pending` until all prerequisites are `Succeeded`.
   - Priority queue ensures highest-priority investigations execute first under resource limits.

---

## 2. Unit & Integration Test Evidence

- `core-domain`:
  - `test_entity_id_ordering_v7` (PASS)
  - `test_epistemic_invariants` (PASS)
  - `test_end_to_end_golden_dataset_pipeline` (PASS)
- `storage-cas`:
  - `test_cas_dual_hash_storage` (PASS)
- `storage-sqlite`:
  - `test_sqlite_full_crud_and_query` (PASS)
- `correlation-engine`:
  - `test_credential_dumping_correlation` (PASS)
- `normalization-engine`:
  - `test_evtx_normalizer_event_id_mapping` (PASS)
- `privilege-broker`:
  - `test_broker_capability_enforcement` (PASS)
  - `test_broker_parameter_validation` (PASS)
- `tool-adapters`:
  - `test_pcap_adapter_file_parsing` (PASS)
- `workflow-dag`:
  - `test_workflow_dag_dependency_resolution` (PASS)

**Total Test Suite Result**: 12 passed, 0 failed.
