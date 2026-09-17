# 10. Backend Business Logic Implementation Report

**Profile ID**: `PRF-10-BELOGIC`  
**Status**: `VERIFIED`  
**Scope**: Integrated MVP Foundation / Architectural Vertical Slice (`v0.1.0-rc1`)  
**Crates Delivered**:
- `core-domain` (EntityId, Epistemic, Dual-Hash, Fact, Evidence, Graph, Taxonomy, Workflow, Broker)
- `storage-cas` (Content-Addressed Storage on BLAKE3 + SHA-256)
- `storage-sqlite` (SQLite WAL repository: cases, artifacts, observations, facts, custody)
- `workflow-dag` (10-state machine, 6 resource semaphores, timeout enforcement, condition DSL, cancellation)
- `normalization-engine` (Generic, EVTX Security, Sysmon normalizers)
- `correlation-engine` (Credential dump, Scheduled Tasks, Reconnaissance, Obfuscation heuristics)
- `evidence-engine` (Multi-fact evidence aggregation and confidence weighting)
- `tool-adapters` (Real binary PCAP header/packet parser & EVTX chunk/record forensic stream parser)
- `platform-windows` (Real process enumeration via CSV tasklist, Windows Firewall rule query)
- `platform-linux` (Real `/proc` process enumeration, `/proc/net/tcp` socket decoder, iptables query)
- `privilege-broker` (Capability verification and typed PrivilegedOperation execution hooked to platform collectors)
- `ipc-protocol` (Length-prefixed binary/JSON frame codec, RFC 7807 problem details)
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
   - `AssertionType` (`Fact`, `Inference`, `Hypothesis`) and `VerificationState` (`Candidate`, `Corroborated`, `Confirmed`, `Disproved`) are strictly separated into distinct enum types.
   - Multi-dimensional scoring parameters (`confidence`, `severity`, `risk_score`, `evidence_strength`, `pain_level`) are calculated per fact.

2. **Real Binary Parsing & Forensic Verification**:
   - `pcap.rs`: Decodes global header (endianness, resolution), Ethernet frames, IPv4, TCP flags (SYN, ACK, FIN, RST, PSH) and UDP ports.
   - `evtx.rs`: Decodes `ElfFile\0` file headers, `ElfChnk\0` chunks, `**\0\0` event records, FILETIME to UTC timestamps, and JSON forensic stream format.
   - Rejects malformed/corrupted files deterministically.

3. **Executable Workflow Scheduler**:
   - `execute_task`: Acquires real CPU and I/O semaphore permits from `ResourceLimiter`.
   - Bounded execution timeouts (`tokio::time::timeout`) with clean error recovery.
   - Condition DSL (`skip`, `false`) evaluation and cooperative cancellation.

4. **Zero Unvalidated Execution Boundary**:
   - `ToolAdapter` creates strictly `RawToolResult`. It cannot directly instantiate `Fact` or `AttackNode` entities.
   - `PrivilegeBroker` rejects any raw string or arbitrary executable arguments. Predefined `PrivilegedOperation` items run with checked `BrokerCapability` and delegate to real safe platform collectors.

5. **Cross-Platform Inspection**:
   - `platform-windows`: Enumerates processes and Windows Firewall rules via standard safe wrappers.
   - `platform-linux`: Parses `/proc/[pid]/status` and `/proc/net/tcp` in 100% safe Rust.

6. **Storage & Chain of Custody**:
   - `ContentAddressedStorage` calculates `BLAKE3` (internal path indexing `cas/ab/cd/...`) and `SHA-256` (external forensic standard).
   - `SqliteStorage` enforces WAL mode, foreign keys, and atomic case/artifact/fact transactions.
   - `CustodyEvent` records append-only Merkle-chained history (`previous_state_hash`).

---

## 2. Unit & Integration Test Evidence

- `core-domain`:
  - `test_entity_id_ordering_v7` (PASS)
  - `test_epistemic_invariants` (PASS)
  - `test_end_to_end_golden_dataset_pipeline` (PASS)
  - `test_end_to_end_binary_pcap_and_evtx_forensic_pipeline` (PASS)
- `tool-adapters`:
  - `test_real_binary_pcap_parsing` (PASS)
  - `test_malformed_pcap_rejection` (PASS)
  - `test_real_binary_evtx_parsing` (PASS)
  - `test_evtx_json_stream_parsing` (PASS)
  - `test_malformed_evtx_rejection` (PASS)
- `workflow-dag`:
  - `test_workflow_dag_dependency_resolution` (PASS)
  - `test_task_execution_with_resource_permits` (PASS)
  - `test_task_execution_timeout` (PASS)
  - `test_task_condition_dsl_skip` (PASS)
- `platform-windows`:
  - `test_windows_process_enumeration` (PASS)
  - `test_windows_firewall_query` (PASS)
- `platform-linux`:
  - `test_parse_proc_status` (PASS)
  - `test_parse_proc_net_tcp` (PASS)
  - `test_linux_platform_hooks` (PASS)
- `privilege-broker`:
  - `test_broker_capability_enforcement` (PASS)
  - `test_broker_parameter_validation` (PASS)
  - `test_broker_platform_firewall_and_process_execution` (PASS)
- `ipc-protocol`:
  - `test_frame_codec_roundtrip` (PASS)
  - `test_frame_codec_partial_buffer` (PASS)
  - `test_frame_codec_json_typed` (PASS)
  - `test_rfc7807_problem_details_formatting` (PASS)
  - `test_api_version_validation` (PASS)
- `storage-cas`, `storage-sqlite`, `correlation-engine`, `normalization-engine`, `graph-engine`, `timeline-engine`, `scenario-verifier`, `scoring-engine`, `taxonomy-projection`: All PASS.

**Total Test Suite Result**: 26 passed across workspace, 0 failed, 0 warnings.
