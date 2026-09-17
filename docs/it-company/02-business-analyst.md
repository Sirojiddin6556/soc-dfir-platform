# 02. Business Analyst: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-02-ANALYST`  
**Status**: `APPROVED / SCOPE FROZEN`  
**Baseline**: Human Gate 1 Scope Freeze

---

## 1. User Stories

- **US-01 (Automated Infrastructure Discovery)**: As a SOC analyst, I want the system to scan and catalog all network hosts, open ports, OS versions, routing tables, and firewall rules automatically, so that I have a complete infrastructure baseline.
- **US-02 (Deep Host Inspection)**: As a DFIR specialist, I want automatic inspection of processes, services, cron/systemd timers, Windows Scheduled Tasks, autoruns, and active network sockets on target hosts without manual intervention.
- **US-03 (Software Inventory & Vulnerability Triage)**: As a security engineer, I want the platform to extract software packages into SBOM (CPE/PURL) and correlate with CVE, CVSS, EPSS, and CISA KEV, accounting for Linux backport patches to eliminate false positives.
- **US-04 (Automated Workflow Escalation)**: As an incident responder, I want the engine to run multi-stage investigation profiles (`Quick → Standard → Deep`) with resource budgets, so that suspect assets are deeply analyzed while preserving system stability.
- **US-05 (Deterministic Attack Graph & Timeline)**: As an investigator, I want an automatically generated, explainable Attack Graph and forensic timeline where every relationship points to verified evidence facts.
- **US-06 (Scenario Evaluation & Ground Truth)**: As an instructor / blue-team evaluator, I want student findings to be scored against sealed Ground Truth across 10 dimensions (assets, facts, evidence, relationships, timeline, ATT&CK, containment).

---

## 2. Requirements Catalog (REQ-XXX-NN)

| ID | Область | Описание | Приоритет | Измеримый Acceptance Criteria (Given/When/Then) |
|---|---|---|---|---|
| `REQ-DISC-01` | Discovery | Автоматическая инвентаризация сети и хостов | **P0** | **Given** целевая подсеть, **When** запущен профиль Quick, **Then** за $\le 60$ сек обнаруживаются 100% активных IP, открытых портов и OS fingerprints. |
| `REQ-HOST-01` | Host Insp | Глубокий сбор хостовых артефактов (процессы, автозапуск) | **P0** | **Given** исследуемый хост, **When** агент инспектирует систему, **Then** извлекаются процессы, сервисы, Scheduled Tasks/cron, autoruns, сокеты в нормализованные `Observation`. |
| `REQ-VULN-01` | Vulnerability | SBOM (CPE/PURL) и корреляция CVE/CVSS/EPSS/KEV | **P0** | **Given** список установленных пакетов, **When** отрабатывает сканер уязвимостей, **Then** генерируется SBOM, находятся CVE, а для Debian/RHEL backports отфильтровываются false positives. |
| `REQ-DATA-01` | Data Pipeline | Конвейер: Artifact $\rightarrow$ Obs $\rightarrow$ Fact $\rightarrow$ Evidence $\rightarrow$ Graph | **P0** | **Given** сырой артефакт, **When** конвейер обрабатывает данные, **Then** факты получают типизацию (`Fact`/`Inference`/`Hypothesis`) и состояние (`Candidate`/`Corroborated`/`Confirmed`). |
| `REQ-AUTO-01` | Workflow | Conditional DAG и профили Quick/Standard/Deep | **P0** | **Given** подозрительная аномалия в Quick, **When** срабатывает conditional edge, **Then** задача эскалируется в Standard/Deep с соблюдением 6 ресурсных семафоров. |
| `REQ-GRAPH-01`| Graph Engine | Детерминированный граф атаки с provenance | **P0** | **Given** факты расследования, **When** строится Attack Graph, **Then** каждое ребро содержит список `supported_by` fact IDs с возможностью drill-down. |
| `REQ-TAX-01`  | Taxonomy | Версионируемые проекции (MITRE, Kill Chain, Pyramid) | **P0** | **Given** Attack Graph и Evidence, **When** запускается проектор, **Then** формируются `TaxonomyCandidate` с фиксацией `taxonomy_version` и `mapping_rule_version`. |
| `REQ-SEC-01`  | Security | Непривилегированный UI + брокер с типизированными операциями | **P0** | **Given** UI без прав root/admin, **When** требуется privileged probe, **Then** брокер принимает строго `PrivilegedOperation` после проверки `BrokerCapability`. Запрещён shell (`no sh -c`). |
| `REQ-SCEN-01` | Verification | Scenario Verifier со скрытым Ground Truth и scoring | **P0** | **Given** завершённый кейс расследования, **When** вызывается верификатор, **Then** Ground Truth остаётся изолированным от игрока, а отчёт даёт объяснимый скоринг по критериям. |
| `REQ-VIZ-01`  | Visual Intel | Автоматические проекции и карты с геометрическим кодированием | **P0** | **Given** данные кейса, **When** открыт интерфейс, **Then** отображаются Infrastructure Map, Attack Graph, Timeline, MITRE Matrix. Сущности кодируются фигурами (NFR-UX-002). |

---

## 3. Измеримые нефункциональные требования (NFR)

- **NFR-PERF-001 (Ingestion Throughput)**: $\ge 50{,}000$ events/sec на эталонном 4-ядерном x86_64 с NVMe накопителем при потоковом парсинге EVTX/PCAP.
- **NFR-PERF-002 (Query Latency)**: Время отклика графовых и табличных запросов $<100$ мс (p95) для $10^6$ проиндексированных фактов в SQLite WAL при тёплом кэше.
- **NFR-DET-001 (Canonical Determinism)**: 100% эквивалентность выводимых `Fact`, `AttackGraph` и `TaxonomyCandidate` при повторном прогоне на идентичных `dataset_version + engine_version + rules_version + taxonomy_version` (независимо от runtime UUID и timestamp генерации).
- **NFR-SEC-001 (Privilege Isolation)**: Zero unvalidated argv execution; 100% вызовов повышенных привилегий проходят через `PrivilegedOperation`.
- **NFR-UX-002 (Visual Accessibility)**: Различение сущностей и их состояний на диаграммах геометрической формой (круг, шестиугольник, ромб, квадрат, восьмиугольник) и текстовыми бейджами, а не только цветом.
