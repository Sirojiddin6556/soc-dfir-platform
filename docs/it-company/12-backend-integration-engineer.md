# Role 12: Backend Integration Engineer — Specification & Validation Report

## 1. Executive Summary & Ownership
- **Role**: PRF-12-BEINT (Backend Integration Engineer)
- **Artifact ID**: ART-12-BEINT
- **Revision**: r2
- **Status**: VERIFIED
- **Scope**: Integrated MVP Foundation / Architectural Vertical Slice (`v0.1.0-rc1`)
- **Requires**: ART-10-BELOGIC (r2), ART-11-BEAPI (r1), ART-09-BEARCH (r2)
- **Produces**: Integrated Composition Root (`crates/engine-server`), end-to-end binary forensic test verification suite (`golden_dataset_test`), IPC dispatch pipelines with length-prefixed frame codecs.

---

## 2. Composition Root Architecture (`crates/engine-server`)

The Composition Root assembles isolated domain components into an integrated desktop-first backend system:
```text
                  +-----------------------------------+
                  |         IPC API Layer             |
                  |     (JSON-RPC 2.0 / RFC 7807)     |
                  +-----------------+-----------------+
                                    |
                  +-----------------v-----------------+
                  |            EngineApp              |
                  |        (Composition Root)         |
                  +---+--------+--------+---------+---+
                      |        |        |         |
     +----------------v-+    +-v------+ |       +-v------------------+
     |   SqliteStorage  |    | CAS    | |       |  PrivilegeBroker   |
     | (WAL, Relational)|    | Dual-H | |       |  (Win/Linux Hooks) |
     +------------------+    +--------+ |       +--------------------+
                                        |
     +----------------------------------v----------------------------+
     | Correlation, Graph, Timeline, Scenario & Scoring Engines      |
     +---------------------------------------------------------------+
```

### Integrated Subsystems:
1. **Relational Storage (`storage-sqlite`)**: SQLite in WAL mode with normal sync, zero data corruption on abnormal exit.
2. **Content-Addressed Storage (`storage-cas`)**: BLAKE3 storage path keys + SHA-256 forensic provenance hashes.
3. **Privilege Broker (`privilege-broker`)**: Capability-restricted execution dispatching into safe platform-specific collectors (`platform-windows` and `platform-linux`).
4. **Workflow Scheduler (`workflow-dag`)**: Concurrency-bounded DAG execution with semaphore resource limiting, timeout bounds, and cancellation.
5. **Real Binary Parsing (`tool-adapters`)**: Decodes true binary PCAP headers/frames and EVTX binary chunk structures.
6. **Correlation & Analytics Engines**: Deterministic correlation, graph generation, timeline synthesis, and ground truth scenario verification.

---

## 3. Inter-Crate Integration Tests

### 3.1 Binary End-to-End Pipeline Validation (`golden_dataset_test`)
- Ingested real binary PCAP (global header, packet headers, Ethernet/IPv4/TCP frames) and EVTX chunks (`ElfFile\0`, `ElfChnk\0`, `**\0\0`) into dual-hash CAS.
- Extracted and normalized Sysmon Event ID 1 (`powershell.exe`) and Event ID 10 (`lsass.exe` access).
- Triggered credential dumping correlation rule.
- Produced high-severity `Fact` with confidence score 0.95 and `PainLevel::Tools`.
- Executed `ScenarioVerifier` against `GroundTruth` and produced 100/100 composite score.

### 3.2 IPC Dispatch & Framing Integration
- Validated length-prefixed binary frame codec roundtrips and partial buffer buffering.
- Validated `health` query with live version check.
- Validated `cases.create` and `cases.list` transactional persistence.
- Validated `broker.execute` with capability verification (authorized `CollectProcessMetadata` vs. forbidden `AcquireMemorySample`).
- Validated strict RFC 7807 Problem Details error generation for malformed input and unhandled methods.

---

## 4. Invariant Compliance Matrix

| Requirement | Description | Integrated Verification | Status |
|:---|:---|:---|:---|
| **NFR-SEC-001** | Global `#![forbid(unsafe_code)]` | Enforced across all 20 crates | Verified |
| **NFR-SEC-002** | Typed Privilege Broker | Capability check in `broker.execute` & safe platform hooks | Verified |
| **NFR-PERF-001** | CAS Dual Hashing | BLAKE3 (path) + SHA-256 (forensic) in CAS | Verified |
| **NFR-PERF-002** | Zero Compiler Warnings | Clean compilation across workspace (`-D warnings`) | Verified |
| **REQ-CORR-01** | Deterministic Correlation | TTP mapping with epistemic scoring | Verified |
| **REQ-SCEN-01** | Isolated Ground Truth Verifier | Ground truth verification without leakage | Verified |
| **REQ-ING-02**  | Binary Ingestion | Real PCAP & EVTX binary parsers with error validation | Verified |

---

## 5. Verification Command & Output
```bash
cargo test --workspace
```
Result: All 26 tests passed, 0 failures, 0 warnings.
