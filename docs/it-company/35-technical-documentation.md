# Role 35: Technical Documentation Specialist — System Manual & Architecture Reference

## 1. Executive Summary & Ownership
- **Role**: PRF-35-TECHDOC (Technical Documentation Specialist)
- **Artifact ID**: ART-35-TECHDOC
- **Revision**: r1
- **Status**: VERIFIED
- **Scope**: Release Candidate `v0.1.0-rc1` / `v0.1.0-mvp`
- **Requires**: ART-04-SOLARCH (r2), ART-12-BEINT (r2), ART-30-RELINT (r1)
- **Produces**: Technical Reference Manual, Architecture Overview, Quick Start Guide, and API Specification.

---

## 2. Platform Architecture Overview

The Blue Team Cyber Range & SOC/DFIR Platform is built as a desktop-first, local-first forensic and incident response system designed with high epistemic rigor and mathematical verification.

### Core Guarantees:
- **Local Sovereignty**: All telemetry, artifacts, and forensic databases reside locally on the investigator's workstation.
- **Pure Safe Rust**: Every domain and platform crate enforces `#![forbid(unsafe_code)]`.
- **Dual-Hash Integrity**: Raw artifacts are stored in a Content-Addressed Storage (CAS) indexed by BLAKE3 hashes with SHA-256 cryptographic provenance headers.
- **Epistemic Segregation**: Every statement is classified into `Fact`, `Inference`, or `Hypothesis`, with explicit `VerificationState` (`Candidate`, `Corroborated`, `Confirmed`, `Disproved`).
- **Sealed Ground Truth**: Educational cyber range scenarios evaluate investigator hypotheses against hidden scenario baselines using mathematical distance and explainable scoring without leaking solutions.

---

## 3. Quick Start & Execution

### 3.1 Prerequisites
- Rust 1.85+ (stable toolchain)
- Node.js 20+ (for desktop UI packaging, optional for engine-server)

### 3.2 Running the Desktop Cockpit Engine
```bash
# Run tests across all workspace crates
cargo test --workspace

# Launch the local Engine Server and auto-open the Desktop Cockpit
cargo run -p engine-server -- --port 8080
```
When launched, `engine-server` initializes the SQLite WAL database, mounts the CAS store, binds the IPC JSON-RPC dispatcher at `http://127.0.0.1:8080/rpc`, and opens the Desktop UI window.

---

## 4. IPC Wire Protocol Specification

The platform communicates between the UI shell and the background engine via JSON-RPC 2.0 requests over HTTP/WebSocket or length-prefixed binary frames:

### Length-Prefixed Frame Structure:
- `Bytes 0..4`: 32-bit unsigned integer (big-endian) representing payload length in bytes.
- `Bytes 4..N`: Payload byte sequence (JSON or binary stream). Maximum frame limit: 16 MB.

### Standard Request Envelope:
```json
{
  "api_version": 1,
  "request_id": "req-0191f630-3c22-7d22-9011-8729583bc123",
  "case_id": "0191f630-3c22-7d22-9011-8729583bc124",
  "method": "case.create",
  "params": {
    "title": "Incident Investigation Alpha"
  }
}
```

### Error Model (RFC 7807 Problem Details):
```json
{
  "type": "https://soc-dfir.local/errors/bad-request",
  "title": "Bad Request",
  "status": 400,
  "detail": "Unsupported API version: expected 1, got 2",
  "invalid_params": ["api_version"]
}
```
