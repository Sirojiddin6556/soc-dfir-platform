# ARCHITECTURE SPECIFICATION (REVISED)
## Stage 4 / Release v0.4: Real Vulnerability Intelligence

> **Document**: `07-v04-architecture-specification.md`  
> **Status**: ARCHITECTURE APPROVED WITH REQUIRED AMENDMENTS  
> **Target Release**: `v0.4.0`  
> **Parent Contract**: `06-v04-requirements-contract.md`  

---

## 1. Фундаментальные архитектурные инварианты

1. **`CVSS != Risk`**: Базовый балл CVSS отражает теоретическую тяжесть ошибки. Реальный контекстный риск рассчитывается на основе экспозиции (Exposure), ценности актива (Criticality), вероятности эксплуатации (EPSS), факта эксплойтов в дикой природе (CISA KEV), статуса патча (Patch State) и телеметрии атаки (Exploitation Evidence).
2. **`CVE Match != Affected`**: Совпадение версии в upstream NVD не означает уязвимость хоста. Если дистрибутив выпустил бэкпорт с исправлением (например, `1.18.0-0ubuntu1.6`), статус классифицируется как **`Fixed`**.
3. **`Affected != Exploited`**: Наличие уязвимости строго отделено от факта эксплуатации (`ExploitationState`: `NoEvidence`, `Suspected`, `Corroborated`, `Confirmed`).
4. **`Fixed != Low Incident Risk`**: Если уязвимость устранена (`Fixed`), но обнаружены следы её успешной эксплуатации (`Confirmed`), актив маркируется как скомпрометированный (инцидент расследования).
5. **`No CVE Match != Secure`**: Отсутствие совпадений возвращает вердикт **`NO_KNOWN_MATCHED_VULNERABILITIES`** с аудиторскими метаданными датасета.
6. **`Unknown != Not Affected`**: Неопознанный софт или неизвестная версия маркируются как `UNMAPPED_SOFTWARE` или `VERSION_UNKNOWN`.
7. **Specificity-Based Matching**:
   $$\text{Exact Distro + Package + Fix} > \text{Vendor Advisory} > \text{OSV Ecosystem Range} > \text{NVD CPE Range} > \text{Generic Heuristic}$$
8. **Ecosystem-Specific Version Comparison**: Никаких универсальных строковых сравнений версий. Каждая экосистема (Debian, RPM, Windows, SemVer) имеет собственный детерминированный компаратор.
9. **Typed Provenance**: Любой вердикт применимости сопровождается типизированной цепочкой ссылок `VulnerabilityEvidenceRef` с BLAKE3-хэшами.
10. **Atomic Versioned Snapshots**: Обновление VulnDB происходит транзакционно по модели staging snapshot -> validation -> atomic commit / rollback.
11. **Разделение слоев**: KEV и EPSS **не входят** в Applicability Engine (они отвечают на вопрос «насколько опасна в мире», а не «уязвим ли хост») и подключаются на слое Exploit Intelligence и Contextual Risk.

---

## 2. Архитектурный конвейер

```text
               SoftwareObservation / Package Info
                               │
                               ▼
                        Product Resolver
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
        NVD Feeds          OSV Feeds        Vendor Advisories
     (Generic CPE)      (Ecosystem PURL)   (Debian/Ubuntu/RHEL/MS)
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
                     VulnerabilityCandidate
                               │
                               ▼
                     Applicability Engine
       (Debian dpkg / RPM evr / Windows UBR & KB Supersedence)
                               │
      ┌────────────────────────┼────────────────────────┐
      ▼                        ▼                        ▼
  CANDIDATE                 AFFECTED                  FIXED
(Range matched,          (Vulnerable &            (Backported /
 unverified)               unpatched)              superseded)
                               │                        │
                               ▼                        ▼
                      Exploit Intelligence      [Incident State Check]
                      - CISA KEV (in the wild)  (Was it exploited
                      - EPSS (exploit prob.)     prior to patch?)
                               │                        │
                               ▼                        ▼
                      Exposure & Criticality ───────────┘
                               │
                               ▼
                        Contextual Risk
                               │
                               ▼
                    Typed Provenance Chain
```

---

## 3. Доменная модель (Domain Layer)

### 3.1. Экосистемы и идентификация продукта
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub cpe: Option<String>,          // cpe:2.3:a:vendor:product:version:...
    pub purl: Option<String>,         // pkg:deb/ubuntu/nginx@1.18.0-0ubuntu1.6
    pub os_family: Option<String>,
    pub os_release: Option<String>,   // e.g. "jammy", "bookworm", "el9"
    pub os_build: Option<u32>,        // Windows build e.g. 22631
    pub os_ubr: Option<u32>,          // Windows UBR e.g. 3880
    pub installed_kbs: Vec<String>,   // ["KB5039212", "KB5040442"]
}
```

### 3.2. Статусы применимости и типизированные доказательства
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplicabilityStatus {
    Candidate,      // Потенциально уязвим по общему диапазону upstream NVD, но вендорный фикс не проверен
    Affected,       // Точно уязвим: диапазон подтвержден, патч/бэкпорт отсутствует
    Fixed,          // Безопасен: подтвержден бэкпорт вендора или кумулятивный фикс
    NotAffected,    // Не уязвим: код не скомпилирован, флаг отключен, ОС не поддерживается
    Unknown,        // Недостаточно данных для категоричного вердикта
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    NvdCpeRangeMatch,
    OsvPackageRangeMatch,
    VendorAdvisoryBackport,
    WindowsKbSupersedence,
    ManualAnalystOverride,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityEvidenceRef {
    pub source_id: String,             // "NVD", "UBUNTU-USN", "MSRC"
    pub source_record_id: String,      // "CVE-2021-23017", "USN-4965-1", "KB5039212"
    pub feed_snapshot_id: String,      // Snapshot UUID
    pub raw_hash: String,              // BLAKE3 hash of source raw payload
    pub evidence_type: EvidenceType,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicabilityAssessment {
    pub vulnerability_id: String,
    pub status: ApplicabilityStatus,
    pub reason: String,
    pub confidence: f32,               // 0.0 .. 1.0
    pub specificity_rank: u32,         // 1 = Exact Distro+Pkg, 2 = Vendor Adv, 3 = OSV, 4 = NVD, 5 = Heuristic
    pub matched_version: String,
    pub fixed_version: Option<String>,
    pub vendor_advisory_id: Option<String>,
    pub evidence: Vec<VulnerabilityEvidenceRef>,
}
```

### 3.3. Exploit Intelligence, Exposure и Contextual Risk
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitationState {
    NoEvidence,
    Suspected,
    Corroborated,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExposureLevel {
    InternetFacing, // 1.3x
    InternalNetwork,// 0.8x
    LocalOnly,      // 0.5x
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetCriticality {
    Tier0, // 1.5x (DC, PKI, IAM)
    Tier1, // 1.2x (DB, Prod App)
    Tier2, // 1.0x (Workstation)
    Tier3, // 0.8x (Lab, IoT)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub vulnerability_id: String,
    pub cvss_base_score: f32,
    pub contextual_risk_score: f32,    // 0.0 .. 10.0
    pub severity_label: String,
    pub epss_score: Option<f32>,
    pub cisa_kev: bool,
    pub exposure: ExposureLevel,
    pub asset_criticality: AssetCriticality,
    pub applicability: ApplicabilityStatus,
    pub exploitation_state: ExploitationState,
    pub rationale: String,
}
```

### 3.4. Политики свежести фидов (Feed Freshness Policies)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshnessPolicy {
    Volatile,   // EPSS: устаревает через 2 дня
    HighFreq,   // CISA KEV: устаревает через 7 дней
    Standard,   // NVD / OSV: устаревает через 14 дней
    Slow,       // Vendor Advisories: устаревает через 30 дней
}

impl FreshnessPolicy {
    pub fn max_age_days(&self) -> i64 {
        match self {
            FreshnessPolicy::Volatile => 2,
            FreshnessPolicy::HighFreq => 7,
            FreshnessPolicy::Standard => 14,
            FreshnessPolicy::Slow => 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedMetadata {
    pub name: String,
    pub policy: FreshnessPolicy,
    pub version_date: String,
    pub records_count: u64,
    pub content_hash: String,
    pub imported_at: DateTime<Utc>,
    pub is_stale: bool,
}
```

---

## 4. Специфичные компараторы версий (Ecosystem Comparators)

### 4.1. Трейт `VersionComparator`
```rust
pub trait VersionComparator: Send + Sync {
    fn compare(&self, v1: &str, v2: &str) -> Result<std::cmp::Ordering, VersionParseError>;
    fn is_in_range(&self, version: &str, introduced: Option<&str>, fixed: Option<&str>) -> bool;
}
```

### 4.2. Экосистемы:
1. **`DebianComparator`**:
   - Реализует нативную семантику `dpkg --compare-versions`.
   - Разбор триплета: `[epoch:]upstream_version[-debian_revision]`.
   - Сравнение чанков: цифры как числа, нецифры лексикографически, символ `~` сортируется раньше любого символа (даже пустой строки).
2. **`RpmComparator`**:
   - Реализует нативную логику `rpmvercmp`.
   - Разбор: `[epoch:]version[-release]`.
3. **`WindowsComparator`**:
   - Учитывает: OS Build + UBR (Update Build Revision), установленные KB и граф суперсессии (KB Supersedence).
   - Если требуемый KB отсутствует, но установлен более новый Cumulative Update, закрывающий эту ревизию — возвращает `Fixed`.
4. **`SemverComparator`**:
   - Семантическое версионирование SemVer 2.0 (Major.Minor.Patch-PreRelease).

---

## 5. Атомарная модель импорта (Transaction & Staging Snapshots)

```text
1. Import Request (Feed files / Tar.gz Bundle)
2. Validate Headers & Content Hashes (BLAKE3)
3. Open Staging SQLite Connection (data/vulndb/staging.db)
4. Stream Parse & Batch Insert in Staging
5. Integrity & Golden Corpus Verification on Staging
6. BEGIN EXCLUSIVE TRANSACTION on Main DB (data/vulndb/vuln.db)
7. ATTACH DATABASE 'staging.db' AS staging;
8. INSERT OR REPLACE INTO main FROM staging;
9. Update vulndb_manifest & Commit Transaction
10. DETACH DATABASE staging; Clean temp files.
```
При любой ошибке валидации выполняется немедленный откат (`Rollback`), а рабочая база продолжает обслуживать запросы без деградации.
