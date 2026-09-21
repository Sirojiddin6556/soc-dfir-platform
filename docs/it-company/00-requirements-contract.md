# REQUIREMENTS CONTRACT
## Stage 4 — Investigation Engine Reliability & Hardening
### v0.3 Scope: Reliable Network Discovery (First Release)

> **Revision**: 1.0 | **Owner**: Product | **Status**: DRAFT → GATE 1

---

## 1. Problem Statement

Платформа SOC/DFIR находится в состоянии "хорошего прототипа": UI работает, базовая корреляция
работает, сбор телеметрии с localhost работает — но данным нельзя доверять на production-уровне.

**Ключевые проблемы (по приоритету):**
1. Network scanner работает только на localhost через `TcpStream::connect()` — нет реального CIDR-discovery
2. CVE engine содержит захардкоженные demo-данные в LIVE-режиме (VULN-001)
3. Correlation rules — только string matching без multi-fact chains
4. EVTX/PCAP parsers есть, но нет UI-pipeline для ingestion
5. Код: 2 unreachable_code warnings + clippy не запущен с `-D warnings`

**Архитектурный принцип (обязательный, в контракт):**
> The platform must never claim more visibility than it actually obtained.
> Every security conclusion must expose its source, collection method,
> coverage, confidence and supporting evidence.
> LIVE mode must contain zero synthetic security data.

---

## 2. Business Goals

| # | Цель | Метрика успеха |
|---|------|----------------|
| G1 | Аналитик может видеть реальную инфраструктуру по CIDR | Discovery 254 хостов за < 60 сек (Quick) |
| G2 | Нулевые синтетические CVE в LIVE-режиме | `grep -r "CVE-202" src/ --include="*.rs"` → только в tests/fixtures/ |
| G3 | 0 warnings при `cargo clippy -D warnings` | CI обязателен |
| G4 | Каждый Finding имеет traceable evidence chain | Каждый fact содержит `tool_run_id`, `collector_version`, `confidence` |

---

## 3. Actors

| Актор | Описание |
|-------|----------|
| **SOC Analyst** | Основной пользователь; проводит расследование |
| **DFIR Investigator** | Загружает EVTX/PCAP, работает с артефактами |
| **Platform Admin** | Обновляет VulnDB, управляет настройками |
| **Rust Engine** | Фоновый процесс, выполняет сканирование и корреляцию |

---

## 4. Functional Requirements — v0.3 Scope

### HARD: Baseline Hardening (P0)
| ID | Требование |
|----|-----------|
| HARD-001 | Исправить 2 `unreachable_code` warnings в `crates/platform-windows/src/discovery.rs` |
| HARD-002 | `cargo clippy --workspace --all-targets -- -D warnings` = 0 warnings (CI gate) |
| HARD-003 | `cargo fmt --all -- --check` = clean |
| HARD-004 | `cargo test --workspace` = all pass |
| HARD-005 | Git tag `v0.2-live-baseline`, branch `stage4-investigation-hardening` |

### SCAN: Scanner Subsystem Redesign (P0)
| ID | Требование |
|----|-----------|
| SCAN-001 | Доменные типы: `ScanJob`, `ScanTarget`, `ScanProfile` (`Quick`/`Standard`/`Deep`), `ScanStage`, `ScanObservation`, `ScanCoverage`, `ScanError`, `ToolRun` |
| SCAN-002 | `ScanOrchestrator` — координирует Discovery → Services → HostInspect → Observations → Facts |
| SCAN-003 | CIDR/Target parser: поддержка `192.168.1.0/24`, range, single IP, hostname |
| SCAN-004 | Remote host discovery: ARP/neighbour table + ICMP ping + TCP SYN probe |
| SCAN-005 | Port scan: Quick (top-100), Standard (top-1000), Deep (1-65535) |
| SCAN-006 | Port state model: `OPEN`, `CLOSED`, `FILTERED`, `OPEN_FILTERED`, `TIMEOUT`, `UNREACHABLE`, `UNKNOWN` — `timeout != closed` |
| SCAN-007 | `NmapAdapter`: `ScanRequest → profile → PrivilegeBroker → nmap XML → Observation[]` |
| SCAN-008 | Service fingerprinting: SSH/TLS/HTTP/SMB/RDP probes через `trait ServiceProbe` |
| SCAN-009 | DNS PTR / NetBIOS / hostname resolution per discovered host |
| SCAN-010 | `AssetResolver`: дедупликация по IP+MAC+hostname+FQDN+cert SAN → `CanonicalAssetId` |
| SCAN-011 | `ScanCoverageReport`: targets total/responsive, ports scanned, services identified %, OS identified, filtered/timeout/errors |

### VULN: CVE Engine (P0 — только первый шаг)
| ID | Требование |
|----|-----------|
| VULN-001 | Убрать demo CVE из LIVE-кода; demo-данные только в `tests/fixtures/` |

---

## 5. Non-Functional Requirements (NFR)

| # | NFR |
|---|-----|
| NFR-1 | `#![forbid(unsafe_code)]` во всех новых крейтах |
| NFR-2 | Quick scan: < 60 сек на /24 |
| NFR-3 | Все данные в LIVE-режиме — только реально собранные |
| NFR-4 | `ScanCoverage.confidence` обязательно для каждого Finding |
| NFR-5 | Nmap вызывается только через `PrivilegeBroker` |
| NFR-6 | UI передаёт только `target + profile + budget`, аргументы формирует backend |

---

## 6. Acceptance Criteria

| ID | Критерий |
|----|---------|
| AC-1 | `cargo clippy --workspace --all-targets -- -D warnings` → 0 errors, 0 warnings |
| AC-2 | `cargo test --workspace` → all green |
| AC-3 | IPC `scan.network {"subnet":"192.168.1.0/24","profile":"quick"}` → реальный ответ с `coverage` полем |
| AC-4 | Grep на demo CVE в `src/` → 0 совпадений вне `tests/fixtures/` |
| AC-5 | Каждый Observation содержит: `collector`, `collector_version`, `method`, `confidence`, `tool_run_id` |
| AC-6 | `AssetResolver` правильно дедуплицирует один хост с разными идентификаторами (test) |
| AC-7 | Git history: tag `v0.2-live-baseline` существует, ветка `stage4-investigation-hardening` создана |

---

## 7. Constraints

- **Стек**: Rust (stable), Cargo workspace, SQLite, JSON-RPC 2.0 over TCP
- **Платформа**: Windows-first, Linux parity roadmap
- **Nmap**: опциональная зависимость — если нет в PATH, scanner fallback на Rust-native
- **Offline/Local-First**: никаких внешних API без явного действия пользователя
- **Файлы**: <= 500 строк, `#![forbid(unsafe_code)]`

---

## 8. Out of Scope для v0.3

- Remote host inspection via WinRM/SSH (→ v0.6)
- Live PCAP capture (→ v0.5)
- Memory forensics / Volatility (→ v0.5)
- Full VulnDB с NVD/OSV importers (→ v0.4)
- Linux Tier-1 collector (→ v0.5)
- UI v2 redesign (→ v0.7)
- SRE / мониторинг

---

## 9. Release Plan (контекст)

| Релиз | Фокус |
|-------|-------|
| **v0.3** | ← **CURRENT SCOPE** — Reliable Network Discovery |
| v0.4 | Real Vulnerability Intelligence |
| v0.5 | DFIR Evidence Pipeline |
| v0.6 | Multi-host Investigation |
| v0.7 | Investigation Workspace v2 |

---

## 10. Conditional Roles Decision

| Роль | Статус | Причина |
|------|--------|---------|
| ML/CV (13-15) | SKIPPED | Нет ML/CV компонентов |
| Data Viz (20a) | SKIPPED | UI не в скоупе v0.3 |
| Accessibility (26a) | SKIPPED | Internal tool, MVP |
| SRE (31) | SKIPPED | No production load SLA |

---

*Сформирован: 2026-09-21 | Роли: 01 PRD-01-DISCOVERY + 02 PRF-02-ANALYST + 03 PRF-03-PRODUCT*
