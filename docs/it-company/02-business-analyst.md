# 02. Business Analyst: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-02-ANALYST`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/01-product-discovery-manager.md` & `D:\BlueTeam_CyberRange_TZ_v1.0.docx`

---

## 1. User Stories & Use Cases

### User Stories
- **US-01 (Analyst / Case Management)**: As a SOC/DFIR analyst, I want to create an isolated investigation case and import raw forensic artifacts (PCAP, EVTX, logs) so that evidence is securely preserved with cryptographic hashes and metadata.
- **US-02 (Analyst / Fact Pipeline)**: As an analyst, I want the system to parse raw observations into structured facts with confidence scores, so that I can filter out noise and focus on verified indicators.
- **US-03 (Analyst / Attack Graph)**: As an investigator, I want to see an automatically generated Attack Graph connecting hosts, processes, accounts, and network sockets, so that I can trace the root cause and lateral movement of an adversary.
- **US-04 (Analyst / Multi-Framework Projection)**: As an investigator, I want to project my attack graph onto MITRE ATT&CK techniques, Cyber Kill Chain stages, and Pyramid of Pain levels, so that I can generate industry-standard threat reports.
- **US-05 (CTF Operator / Verification)**: As a Cyber Range instructor, I want student answers/flags to be verified deterministically against graph facts, so that grading is objective and reproducible.

### Use Cases
- **UC-01 (Evidence Ingestion & Hashing)**:
  - *Trigger*: User drags and drops EVTX/PCAP file into Case Workspace.
  - *Main Flow*: System computes SHA-256/BLAKE3, stores file in Content-Addressed Storage (CAS), creates immutable `Artifact` record, and registers ingestion task in Workflow DAG.
- **UC-02 (Automated Fact Extraction & Correlation)**:
  - *Trigger*: Task Scheduler executes parser tool for ingested artifact.
  - *Main Flow*: Parser emits `Observation` records. Correlation rules match observations into `Fact` objects with confidence $\in [0.0, 1.0]$.
- **UC-03 (Attack Graph Construction & Expansion)**:
  - *Trigger*: Facts are written to the case database.
  - *Main Flow*: Graph Engine merges entities (Identity, Host, Process, Network, File) into graph nodes and creates typed, directional edges with full provenance.
- **UC-04 (Privileged Tool Execution)**:
  - *Trigger*: User triggers live memory/network capture on local machine.
  - *Main Flow*: Unprivileged UI sends request to Local Privilege Broker via IPC. Broker checks command allowlist, validates parameters, runs process under elevated privileges, and returns sanitized stream to UI.

---

## 2. Requirements Catalog (REQ-XXX-NN)

| ID | TZ Source | Описание | Приоритет | Acceptance Criteria (Given/When/Then) |
|---|---|---|---|---|
| `REQ-CASE-01` | FR-CASE-001 | Создание и изоляция кейса (SQLite WAL + CAS) | **P0** | **Given** открытое приложение, **When** пользователь создает кейс "Incident-2026", **Then** создается изолированная БД SQLite и папка CAS; статус кейса `Active`. |
| `REQ-CASE-02` | FR-CASE-002 | Криминалистический Chain of Custody для артефактов | **P0** | **Given** входной файл, **When** файл импортируется, **Then** вычисляется SHA-256, файл переносится в CAS по хешу и делается запись в лог целостности. |
| `REQ-DATA-01` | FR-DATA-001 | 4-уровневая модель данных (Observation/Fact/Inference/Hypothesis) | **P0** | **Given** сырой лог EVTX, **When** парсер отрабатывает, **Then** создаются `Observation` (сырые), затем `Fact` (с confidence 0..1), без смешивания типов. |
| `REQ-GRAPH-01` | FR-GRAPH-001 | Построение детерминированного графа атаки | **P0** | **Given** набор фактов процесса и сети, **When** запускается Graph Engine, **Then** строятся типизированные узлы и ребра с обязательной ссылкой на факт-обоснование (`fact_id`). |
| `REQ-MAP-01` | FR-MAP-001 | Синхронная проекция на MITRE ATT&CK и Kill Chain | **P0** | **Given** готовый Attack Graph, **When** пользователь переключает таб на "MITRE Matrix", **Then** подсвечиваются точные техники (T-номера) с сылкой на узлы графа. |
| `REQ-WORK-01` | FR-WORK-001 | Workflow DAG с бюджетированием ресурсов (CPU/IO/Net) | **P0** | **Given** 10 тяжелых задач парсинга, **When** планировщик запускает их, **Then** соблюдаются семафоры классов ресурсов, без зависания UI; доступна отмена задач. |
| `REQ-SEC-01` | FR-SEC-001 | Разделение привилегий (Unprivileged UI + Local Broker) | **P0** | **Given** UI запущен от непривилегированного пользователя, **When** требуется запуск с правами (raw socket/ETW), **Then** вызов идет через Broker с проверкой allowlist. |
| `REQ-VIZ-01` | NFR-UX-002 | Доступность визуализации (A11y / Форма + Цвет) | **P1** | **Given** граф или таймлайн, **When** отрисовываются узлы различных типов/статусов, **Then** они различимы по форме узла и текстовому бейджу, а не только по цвету. |

---

## 3. Негативные сценарии и граничные условия (Edge Cases)
1. **Поврежденный артефакт (Corrupted EVTX/PCAP)**:
   - *Поведение*: Парсер регистрирует ошибку валидации заголовка, помечает `Observation` как `Malformed`, не падает аварийно (panic) и информирует аналитика.
2. **Превышение лимита ресурсов (Resource Exhaustion / OOM)**:
   - *Поведение*: Планировщик отслеживает лимиты памяти/времени. При исчерпании квоты задача принудительно переводится в статус `TIMEOUT` или `RESOURCE_EXCEEDED` с возможностью возобновления с чекпоинта.
3. **Попытка инъекции команды в Broker**:
   - *Поведение*: Любые параметры проверяются по строгому регулярному выражению и whitelist; аргументы передаются в OS exec как вектор `argv[]` без вызова командной оболочки (`cmd.exe` / `/bin/sh`).
