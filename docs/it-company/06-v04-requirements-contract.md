# REQUIREMENTS CONTRACT & SCOPE SPECIFICATION
## Stage 4 / Release v0.4: Real Vulnerability Intelligence

> **Document**: `06-v04-requirements-contract.md`  
> **Status**: GATE 1 — PROPOSED FOR APPROVAL  
> **Target Release**: `v0.4.0`  
> **Parent Milestone**: Stage 4 — Investigation Engine Reliability & Hardening  

---

## 1. Problem Statement & Mission

Текущий сканер периметра (релиз `v0.3.0`) научился достоверно обнаруживать реальные хосты, открытые порты и верифицировать сервисы по бинарным хэндшейкам (`TLS`, `SMB`, `SSH`, `HTTP`).
Однако сопоставление уязвимостей в прототипе страдало от двух критических недостатков, типичных для слабых сканеров:
1. **Примитивное сопоставление**: простое сопоставление `порт + продукт -> CVE -> CRITICAL` без учета дистрибутивных бэкпортов (например, `nginx 1.18.0-0ubuntu1.6` на Ubuntu 22.04 уже имеет исправленную уязвимость, но наивный сканер кричит о CRITICAL).
2. **Ложное чувство безопасности**: возвращение статуса `SECURE (CVE-FREE)`, когда база данных пуста или продукт не распознан.

### Главный архитектурный принцип v0.4:
> **The platform must never claim a system is secure when vulnerabilities are merely unknown.**  
> `vulnerable != exploited`.  
> Любой вердикт об уязвимости обязан проходить через многослойный Applicability Engine с учетом дистрибутивных патчей и контекста риска.

---

## 2. Архитектурный поток Vulnerability Intelligence

```text
                  SoftwareObservation / CPE / PURL
                                │
                                ▼
                         Product Resolver
                                │
               ┌────────────────┼────────────────┐
               ▼                ▼                ▼
           NVD Feed         OSV Feed        Vendor Feeds
        (CVE/CPE 2.3)    (Open Source)   (Ubuntu/Debian/RHEL)
               │                │                │
               └────────────────┼────────────────┘
                                ▼
                    Local Vulnerability DB
                      (SQLite / Schema v2)
                                │
                                ▼
                       Applicability Engine
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
    AFFECTED                  FIXED               NOT_AFFECTED
 (Real exposure)       (Backport confirmed)    (Feature disabled/mitigated)
        │                       │
        │                       └────────────────────────┐
        ▼                                                ▼
 Contextual Risk Engine                           ExploitationState
        │                                         - NO_EVIDENCE
 Risk = CVSS + EPSS + KEV                         - SUSPECTED
        + Exposure + Asset Criticality            - CORROBORATED
        + Patch State + Exploit Evidence          - CONFIRMED
```

---

## 3. Объем задач (Scope v0.4: VULN-002..012)

| Задача | Наименование | Описание |
|---|---|---|
| **`VULN-002`** | **Local VulnDB Schema v2** | Нормализованная реляционная схема в SQLite (`data/vulndb/vuln.db`): таблицы `cve_metadata`, `cpe_matches`, `osv_records`, `cisa_kev`, `epss_scores`, `vendor_fixes`, `vulndb_manifest`. |
| **`VULN-003`** | **NVD Feed Importer** | Потоковый импортер NVD JSON 2.0 / 1.1 с извлечением CVSS v3.1, векторных строк, CPE конфигураций и CWE. |
| **`VULN-004`** | **OSV Importer** | Импортер формата Open Source Vulnerabilities (OSV) для экосистем (crates.io, npm, PyPI, Go, Debian, Ubuntu). |
| **`VULN-005`** | **CISA KEV Importer** | Импортер каталога Known Exploited Vulnerabilities от CISA (актуальные флаги `known_exploited`, `date_added`, `required_action`). |
| **`VULN-006`** | **EPSS Importer** | Импортер вероятностей эксплуатации Exploit Prediction Scoring System (EPSS score + percentile). |
| **`VULN-007`** | **Vendor Advisory Model** | Модель сопоставления исправлений в дистрибутивах (Debian Security Tracker, Ubuntu Security Notices, Red Hat OVAL). |
| **`VULN-008`** | **Applicability Engine** | Движок сопоставления со статусами: `AFFECTED`, `FIXED`, `NOT_AFFECTED`, `UNKNOWN`. Устранение ложных срабатываний из-за backports. |
| **`VULN-009`** | **Contextual Risk Engine** | Расчет риска: `Risk = CVSS + EPSS + KEV + Exposure (Internet/Internal) + Asset Tier + Patch Status + Exploitation Evidence`. |
| **`VULN-010`** | **Metadata & Versioning** | Аудит состояния датасета: дата выгрузки, версия схемы, хеши фидов, статус свежести (`STALE` при >30 дней). |
| **`VULN-011`** | **Offline Bundle Ingest** | Возможность оффлайн-загрузки архива уязвимостей (`vulndb-bundle-{date}.tar.gz` / zip) для изолированных сетей. |
| **`VULN-012`** | **Vulnerability Provenance** | Полная цепочка доказательств: каждый вердикт содержит источник (`NVD`/`OSV`/`Vendor`), версию фида, правило матчинга и хэш записи. |

---

## 4. Строгие правила UI и API (Запрет на псевдо-безопасность)

1. **Никаких `SECURE` / `CVE FREE`**:
   - Если совпадений нет: **`NO_KNOWN_MATCHED_VULNERABILITIES`**.
   - Обязательно выводятся метаданные: дата датасета, задействованные источники, confidence матчинга.
2. **Неопределенные состояния**:
   - Неопознанный софт: **`UNMAPPED_SOFTWARE`**.
   - Не определена точная версия: **`VERSION_UNKNOWN`**.
   - База данных не обновлялась > 30 дней: **`DATASET_STALE`**.
3. **Разделение уязвимости и эксплуатации**:
   - Поле `exploitation_state`:
     - `NO_EVIDENCE` (уязвимость есть, следов атаки нет),
     - `SUSPECTED` (подозрительная сетевая активность на уязвимом порту),
     - `CORROBORATED` (обнаружены артефакты эксплойта в логах/PCAP),
     - `CONFIRMED` (успешное выполнение кода/захват сессии подтвержден).

---

## 5. Формула Contextual Risk

В отличие от статического базового балла CVSS (от вендора в вакууме), платформа вычисляет **Contextual Risk**:

$$\text{ContextualRisk} = f(\text{CVSS}, \text{EPSS}, \text{KEV}, \text{Exposure}, \text{AssetTier}, \text{PatchState}, \text{Exploitation})$$

Примеры поведения:
- `CVSS 9.8` + `EPSS 0.01` + `KEV: NO` + `Exposure: Internal` + `Patch: FIXED (Backported)` → **Contextual Risk: LOW**.
- `CVSS 7.5` + `EPSS 0.94` + `KEV: YES` + `Exposure: Internet-Facing` + `Asset: Tier-0 (Domain Controller)` + `Exploit: CORROBORATED` → **Contextual Risk: CRITICAL**.

---

## 6. Критерии приемки Gate 2 для v0.4 (Acceptance Criteria)

```text
[ ] NVD feed (JSON 2.0) реально импортируется в local SQLite
[ ] OSV feed реально импортируется в local SQLite
[ ] CISA KEV каталог реально импортируется и выставляет флаги
[ ] EPSS CSV реально импортируется и связывается с CVE
[ ] DB содержит манифест: sources / versions / timestamps / blake3 hashes
[ ] Один программный компонент может иметь несколько источников (NVD + OSV + Vendor)
[ ] CPE 2.3 и PURL сопоставление работает детерминированно
[ ] Ubuntu / Debian backport (например, 1.18.0-0ubuntu1.6) помечается как FIXED, а не AFFECTED
[ ] UNKNOWN никогда не превращается в SAFE / SECURE
[ ] FIXED строго отделен от NOT_AFFECTED
[ ] CVSS score и Contextual Risk score разделены на уровне типов и UI
[ ] Флаг CISA KEV и EPSS percentile отображаются отдельно
[ ] Реализован импорт оффлайн-бандла датасетов
[ ] Каждая найденная уязвимость содержит полный provenance (feed source + rule hash)
[ ] Создан Golden Test Corpus (набор известных пакетов affected / fixed / not_affected)
[ ] cargo check, fmt, clippy (-D warnings) и cargo test проходят на 100%
```
