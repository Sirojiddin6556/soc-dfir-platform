# 05. Security Architecture Document: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-05-SECARC`  
**Status**: `FROZEN (Approved at Human Gate 2 on 2026-09-17)`  
**Baseline**: Human Gate 2 Architecture & Contract Gate

---

## 1. Privilege Boundaries & Capability Model

### Architectural Invariants:
1. **UI cannot execute commands.**
2. **Core cannot execute privileged commands directly.**
3. **Only Broker executes predefined `PrivilegedOperation` items.**
4. **Zero execution of shell evaluators** (`sh -c`, `cmd.exe /c`, `powershell -Command <arbitrary>`). UI never passes raw `argv[]`.

### Broker Capability Hierarchy:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrokerCapability {
    ReadProcesses,
    ReadFirewall,
    CapturePcap,
    AcquireMemory,
    ReadRegistry,
    NetworkScan,
}
```

### Typed Privileged Operations:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedOperation {
    CapturePcap {
        interface_id: String,
        duration_secs: u32,
        max_bytes: u64,
        bpf_filter: Option<String>,
    },
    ReadFirewallRules {
        direction: Option<RuleDirection>,
    },
    CollectProcessMetadata {
        pid: u32,
    },
    AcquireMemorySample {
        target: MemoryTarget,
        chunk_size_mb: u32,
    },
    CollectRegistryKeys {
        hive: RegistryHive,
        subpath: String,
    },
    RunTargetedScan {
        target_ip: String,
        ports: Vec<u16>,
        rate_limit: u32,
    },
}
```
The Broker validates the requesting client's identity (OS SID/UID), checks task `required_capabilities`, sanitizes parameters against strict type definitions, and executes the predefined internal binary using fixed parameter templates (no dynamic shell).

---

## 2. Ground Truth Isolation & Anti-Cheating Boundary

In CTF / Cyber Range mode, player collusion or inspection of local state must be prevented:
- **Sealed Ground Truth**: Scenario packages are distributed with an asymmetric cryptographic signature and an encrypted Ground Truth envelope.
- **Access Isolation**: The `scenario-verifier` operates within an isolated boundary; Ground Truth facts, attack trees, and expected findings are NEVER written to the player's accessible SQLite database or exposed over client IPC queries.
- **Integrity Verification**: Corrupted or modified scenario bundles fail HMAC/signature checks and are rejected prior to mounting.

---

## 3. Append-Only Chain of Custody & Audit Log

The audit trail is cryptographically chained and strictly append-only. The API explicitly omits any `audit.delete` or `audit.update` operations.

### Custody Events:
- `ArtifactAcquired`
- `ArtifactStored`
- `ArtifactHashed`
- `ArtifactParsed`
- `ArtifactAccessed`
- `ArtifactExported`

Each event records:
- `timestamp`: UTC (ISO-8601 monotonic)
- `actor`: User or system service ID
- `operation`: Exact typed action
- `artifact_hash`: BLAKE3 and SHA-256
- `previous_state_hash`: Cryptographic back-link to the prior audit block (Merkle chain).

---

## 4. Unsafe Code Isolation Policy
- `#![forbid(unsafe_code)]` is strictly set in crate roots for: `core-domain`, `storage-cas`, `storage-sqlite`, `workflow-dag`, `normalization-engine`, `correlation-engine`, `evidence-engine`, `graph-engine`, `taxonomy-projection`, `scenario-engine`, `scenario-verifier`, and `scoring-engine`.
- Unsafe blocks are permitted solely in `platform-windows` and `platform-linux` under the following conditions:
  1. Isolated in dedicated low-level submodules.
  2. Wrapped in zero-cost safe Rust abstractions.
  3. Every block accompanied by an explicit `// SAFETY:` rationale.
  4. Covered by integration tests and fuzzers.
