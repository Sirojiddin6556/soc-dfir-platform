# ARCHITECTURE SPECIFICATION
## Stage 4 / Release v0.4: Real Vulnerability Intelligence

> **Document**: `07-v04-architecture-specification.md`  
> **Status**: ARCHITECTURE FROZEN (Roles 04 & 09)  
> **Target Release**: `v0.4.0`  
> **Parent Contract**: `06-v04-requirements-contract.md`  

---

## 1. Фундаментальные инварианты Vulnerability Intelligence

1. **`CVSS != Risk`**: Базовый балл CVSS отражает техническую строгость уязвимости в вакууме. Реальный риск определяется контекстом: сетевая доступность (Exposure), ценность актива (Asset Criticality), факт эксплуатации в дикой природе (CISA KEV), вероятность эксплуатации (EPSS), статус патча (Patch State) и наличие телеметрии атаки (Exploitation Evidence).
2. **`CVE Match != Affected`**: Факт наличия CVE в кодовой базе не означает уязвимость конкретной инсталляции. Если в Ubuntu/Debian бэкпортирован фикс без изменения мажорного номера версии (напр., `1.18.0-0ubuntu1.6`), система классифицируется как **`FIXED`**.
3. **`Affected != Exploited`**: Наличие уязвимости отделено от состояния атаки (`ExploitationState`: `NO_EVIDENCE`, `SUSPECTED`, `CORROBORATED`, `CONFIRMED`).
4. **`No CVE Match != Secure`**: Отсутствие найденных уязвимостей отражается как **`NO_KNOWN_MATCHED_VULNERABILITIES`** с указанием даты датасета и степени покрытия.
5. **`Unknown != Not Affected`**: Неопознанный софт или неизвестная версия помечаются как `UNMAPPED_SOFTWARE` или `VERSION_UNKNOWN`.
6. **`Vendor Advisory > Generic Version Heuristic`**: При наличии информации от поставщика ОС (Ubuntu OVAL/USN, Debian Security Tracker, Red Hat RHSA) её вердикт имеет высший приоритет по сравнению с общим диапазоном NVD.
7. **`Traceable Provenance`**: Каждый результат содержит ссылку на источник фида, дату обновления, хэш правила и идентификатор совета вендора.
8. **`LIVE Zero-Mock`**: В боевом режиме строго 0 синтетических CVE, EPSS и KEV.

---

## 2. Доменная модель и контракты типов (Domain Layer)

### 2.1. Идентификация продукта и пакета
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageEcosystem {
    Debian,
    Ubuntu,
    RedHat,
    Windows,
    CratesIo,
    Npm,
    PyPI,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductIdentity {
    pub raw_name: String,
    pub raw_version: String,
    pub publisher: Option<String>,
    pub ecosystem: PackageEcosystem,
    pub cpe: Option<String>,          // CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
    pub purl: Option<String>,         // Package URL: pkg:deb/ubuntu/nginx@1.18.0-0ubuntu1.6
}
```

### 2.2. Записи об уязвимостях и источники
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilitySource {
    Nvd,
    Osv,
    UbuntuUsn,
    DebianSecurity,
    RedHatOval,
    CisaKev,
    Epss,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedRange {
    pub ecosystem: PackageEcosystem,
    pub package_name: String,
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityRecord {
    pub id: String,                    // CVE-YYYY-NNNN or OSV-ID
    pub aliases: Vec<String>,          // GHSA, OSV, RHSA, USN aliases
    pub source: VulnerabilitySource,
    pub summary: String,
    pub details: String,
    pub cvss_v3_score: Option<f32>,    // 0.0 .. 10.0
    pub cvss_v3_vector: Option<String>,// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    pub epss_score: Option<f32>,       // 0.0 .. 1.0 probability
    pub epss_percentile: Option<f32>,  // 0.0 .. 1.0
    pub cisa_kev: bool,                // In CISA KEV catalog?
    pub kev_due_date: Option<String>,
    pub affected_ranges: Vec<AffectedRange>,
    pub cpe_matches: Vec<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub raw_hash: String,              // BLAKE3 hash of source record
}
```

### 2.3. Applicability Assessment (Оценка применимости)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplicabilityStatus {
    Affected,       // Уязвимость физически присутствует и не устранена
    Fixed,          // Уязвимость устранена официальным патчем или бэкпортом вендора
    NotAffected,    // Не уязвим (уязвимый модуль отключен, архитектура/ОС не совпадает)
    Unknown,        // Недостаточно данных для категоричного вывода
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicabilityAssessment {
    pub vulnerability_id: String,
    pub status: ApplicabilityStatus,
    pub reason: String,
    pub confidence: f32,               // 0.0 .. 1.0
    pub source_priority: u32,          // 1 = Vendor Advisory, 2 = OSV, 3 = NVD
    pub matched_version: String,
    pub fixed_version: Option<String>,
    pub vendor_advisory_id: Option<String>, // e.g. "USN-4899-1"
    pub evidence: Vec<String>,
}
```

### 2.4. Exploitation State & Contextual Risk
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitationState {
    NoEvidence,     // Следов эксплуатации не обнаружено
    Suspected,      // Подозрительный сетевой трафик к уязвимому порту
    Corroborated,   // В журналах/дампе обнаружены артефакты выполнения эксплойта
    Confirmed,      // Подтвержден успешный захват сессии / RCE / privilege escalation
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExposureLevel {
    InternetFacing, // Сервис доступен из внешнего периметра / публичный IP
    InternalNetwork,// Сервис в закрытой корпоративной подсети
    LocalOnly,      // Сервис доступен только на 127.0.0.1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetCriticality {
    Tier0,          // Domain Controllers, PKI, Hypervisors, IAM (Вес 1.5)
    Tier1,          // Базы данных, критичные серверы приложений (Вес 1.2)
    Tier2,          // Рабочие станции сотрудников, тестовые стенды (Вес 1.0)
    Tier3,          // Изолированные сегменты, IoT (Вес 0.8)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub vulnerability_id: String,
    pub cvss_score: f32,               // Базовый CVSS
    pub contextual_risk_score: f32,    // 0.0 .. 10.0 динамический контекстный риск
    pub severity_label: String,        // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    pub epss_score: Option<f32>,
    pub cisa_kev: bool,
    pub exposure: ExposureLevel,
    pub asset_criticality: AssetCriticality,
    pub applicability: ApplicabilityStatus,
    pub exploitation_state: ExploitationState,
    pub rationale: String,             // Человекочитаемое обоснование расчета
}
```

### 2.5. Манифест и версионирование датасета (VulnDbSnapshot)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedMetadata {
    pub name: String,                  // "NVD", "OSV", "CISA-KEV", "EPSS", "UBUNTU-OVAL"
    pub version_or_date: String,       // "2026-09-21"
    pub records_count: u64,
    pub content_hash: String,          // BLAKE3
    pub imported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnDbSnapshot {
    pub schema_version: u32,           // 2
    pub snapshot_id: String,           // UUID v7
    pub created_at: DateTime<Utc>,
    pub feeds: Vec<FeedMetadata>,
    pub is_stale: bool,                // > 30 days old
}
```

---

## 3. Схема базы данных SQLite (`data/vulndb/vuln.db`)

Изолированная локальная база SQLite с включенным WAL-режимом:

```sql
-- Манифест и фиды
CREATE TABLE IF NOT EXISTS vulndb_manifest (
    feed_name TEXT PRIMARY KEY,
    version_date TEXT NOT NULL,
    records_count INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    imported_at TEXT NOT NULL
);

-- Основная таблица уязвимостей
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,               -- CVE-2023-4863
    aliases_json TEXT NOT NULL,        -- ["GHSA-...", "OSV-..."]
    primary_source TEXT NOT NULL,      -- "NVD"
    summary TEXT,
    details TEXT,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    epss_score REAL,
    epss_percentile REAL,
    cisa_kev INTEGER DEFAULT 0,
    kev_due_date TEXT,
    published_at TEXT,
    updated_at TEXT NOT NULL,
    raw_hash TEXT NOT NULL
);

-- Сопоставления CPE 2.3
CREATE TABLE IF NOT EXISTS cpe_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT NOT NULL,
    cpe_uri TEXT NOT NULL,             -- cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cpe_uri ON cpe_matches(cpe_uri);

-- Специфичные диапазоны пакетов (OSV / Vendor Advisories)
CREATE TABLE IF NOT EXISTS package_advisories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,           -- "Ubuntu", "Debian", "crates.io"
    package_name TEXT NOT NULL,        -- "nginx"
    introduced_version TEXT,
    fixed_version TEXT,                -- "1.18.0-0ubuntu1.6"
    vendor_advisory_id TEXT,           -- "USN-4899-1"
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pkg_lookup ON package_advisories(ecosystem, package_name);
```

---

## 4. Алгоритм парсинга версий и устранения False Positives (Backports)

### 4.1. Разрешение версий Debian / Ubuntu
В пакетах Debian/Ubuntu версия имеет формат: `[epoch:]upstream_version[-debian_revision]`.
Пример:
- Исходный NVD CVE указывает: уязвимы версии `< 1.19.0`.
- В Ubuntu 22.04 LTS установлен пакет `nginx: 1.18.0-0ubuntu1.6`.
- `upstream_version` = `1.18.0`.
- Наивный сканер сравнивает `1.18.0 < 1.19.0` и рапортует `CRITICAL`.
- **Applicability Engine**:
  1. Определяет экосистему пакета (`Ubuntu 22.04`).
  2. Запрашивает `package_advisories` для `(Ubuntu, nginx)`.
  3. Находит advisory: исправлено в `1.18.0-0ubuntu1.5`.
  4. Сравнивает версии по алгоритму сравнения версий Debian: `1.18.0-0ubuntu1.6 >= 1.18.0-0ubuntu1.5`.
  5. Присваивает статус: **`ApplicabilityStatus::Fixed`**.
  6. Причина: `"Security fix backported in Ubuntu package 1.18.0-0ubuntu1.5 (USN-4899-1)"`.
  7. Контекстный риск снижается до **`LOW / INFORMATIONAL`**.

---

## 5. Алгоритм расчета Contextual Risk

$$\text{Base} = \text{CVSS} \times \text{AssetWeight} \times \text{ExposureMultiplier}$$

1. **Множитель доступности (Exposure)**:
   - `InternetFacing`: $1.3$
   - `InternalNetwork`: $0.8$
   - `LocalOnly`: $0.5$
2. **Множитель актива (Asset Criticality)**:
   - `Tier0`: $1.5$
   - `Tier1`: $1.2$
   - `Tier2`: $1.0$
   - `Tier3`: $0.8$
3. **Модификаторы угрозы (Threat Modifiers)**:
   - Если `cisa_kev == true` (активно эксплуатируется в мире): $+1.5$ балла к риску.
   - Если `epss_score > 0.5` (высокая вероятность эксплойта): $+1.0$ балл.
   - Если `epss_score < 0.05` и нет KEV: $-0.5$ балла.
4. **Статус патча (Patch Factor)**:
   - Если `ApplicabilityStatus::Fixed`: итоговый балл принудительно ограничивается максимумом $1.0$ (уязвимость устранена бэкпортом).
   - Если `ApplicabilityStatus::NotAffected`: итоговый балл $0.0$.
5. **Состояние атаки (Exploitation Evidence)**:
   - Если `ExploitationState::Confirmed`: статус риска немедленно повышается до **`CRITICAL (10.0)`**.
   - Если `ExploitationState::Corroborated`: статус риска повышается минимум до **`HIGH (8.5)`**.

---

## 6. Модульная структура в кодовой базе

Создается новый специализированный крейт в Cargo workspace:
[`crates/vulnerability-engine`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/vulnerability-engine)

```text
crates/vulnerability-engine/
├── Cargo.toml
└── src/
    ├── lib.rs                      // Точка входа, re-exports
    ├── types.rs                    // Все доменные структуры (раздел 2)
    ├── db/
    │   ├── mod.rs                  // Менеджер подключения к SQLite
    │   ├── schema.rs               // Миграции и создание таблиц
    │   └── repository.rs           // CRUD и транзакционные операции
    ├── version/
    │   ├── mod.rs                  // Version comparator trait
    │   ├── debian.rs               // Парсер версий Debian/Ubuntu
    │   ├── rpm.rs                  // Парсер версий RPM/RHEL
    │   └── semver.rs               // Стандартный SemVer 2.0
    ├── importers/
    │   ├── mod.rs
    │   ├── nvd.rs                  // NVD JSON 2.0 streaming importer
    │   ├── osv.rs                  // OSV format importer
    │   ├── cisa_kev.rs             // CISA KEV JSON importer
    │   ├── epss.rs                 // EPSS CSV importer
    │   └── vendor.rs               // Vendor advisory importer
    ├── applicability.rs            // Applicability Engine
    ├── contextual_risk.rs          // Contextual Risk Calculator
    ├── bundle.rs                   // Оффлайн бандлы (tar.gz / zip manifest)
    └── tests/                      // Golden corpus test suite
```

Спецификация архитектуры полностью покрывает инварианты Gate 1 и подготовлена к детальной имплементации.
