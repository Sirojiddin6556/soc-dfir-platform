# 27. Infrastructure Architecture & Packaging: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-27-INFRAARCH`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/04-solution-architect.md` & `docs/it-company/00-requirements-contract.md`

---

## 1. Toolchain & Build Environment

- **Rust Toolchain**: `1.80+` (stable channel) with `rustfmt`, `clippy`, and `llvm-tools`.
- **Target Triples**:
  - `x86_64-pc-windows-msvc` (Primary Windows Workstation)
  - `x86_64-unknown-linux-gnu` (Linux Forensics Workstation / Kali / Ubuntu)
  - `x86_64-apple-darwin` / `aarch64-apple-darwin` (macOS Incident Response)

---

## 2. Packaging & Privilege Installation Topology

```
+-------------------------------------------------------------+
| Desktop Application Package (.msi / .deb / .dmg)            |
|                                                             |
|  [User Space Directory: %LOCALAPPDATA% or ~/.config]        |
|    ├── soc-dfir-cockpit (Desktop GUI binary - Unprivileged) |
|    ├── cases/           (SQLite WAL databases)              |
|    └── cas/             (Content-Addressed Storage)         |
|                                                             |
|  [Elevated System Service / Daemon Directory]               |
|    └── soc-dfir-broker  (Hardened Local Broker - Elevated)   |
|         └── Windows: LocalSystem / Windows Service          |
|         └── Linux:   root / systemd service                 |
|         └── macOS:   root / launchd daemon                  |
+-------------------------------------------------------------+
```

---

## 3. GitHub Actions CI/CD Pipeline Blueprint

1. **Lint & Security Gate**:
   - `cargo fmt -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo audit` (scanning crates for CVEs)
2. **Multi-OS Test Matrix**:
   - Runs `cargo test --workspace` on `windows-latest`, `ubuntu-latest`, `macos-latest`.
3. **Deterministic Verification Check**:
   - Executes integration test suite against sample malicious dataset fixtures.
4. **Artifact Release Build**:
   - Stripped release binaries with LTO (Link-Time Optimization) and reproducible build flags.
