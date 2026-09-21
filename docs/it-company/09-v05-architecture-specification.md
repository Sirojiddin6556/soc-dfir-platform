# ARCHITECTURE SPECIFICATION & SYSTEM DESIGN
## Stage 4 / Release v0.5: DFIR Evidence Pipeline & Forensic Artifacts Hardening

> **Document**: `09-v05-architecture-specification.md`  
> **Status**: GATE 1 — PROPOSED FOR APPROVAL  
> **Target Release**: `v0.5.0`  
> **Parent Contract**: `08-v05-requirements-contract.md`  

---

## 1. Архитектурная топология и разделение Plane-ов

Для обеспечения стабильной работы при анализе дампов трафика и логов размером от сотен мегабайт до десятков гигабайт архитектура v0.5 строго разделяет **Control Plane** и **Data Plane**:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE (JSON-RPC)                        │
│                                                                        │
│  evidence.ingest.begin      --> выделение ingest_session_id            │
│  evidence.ingest.status     --> опрос прогресса, метрик и хешей        │
│  evidence.ingest.complete   --> запуск валидации, CAS-коммита и парсинга│
│  evidence.ingest.cancel     --> отмена сессии и очистка staging        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   DATA PLANE (Streaming Chunked I/O)                   │
│                                                                        │
│  evidence.ingest.chunk(session_id, offset, binary_chunk)               │
│                                                                        │
│  ├── Чтение чанка (рекомендованный размер: 1 - 8 МБ)                  │
│  ├── Инкрементальное обновление SHA-256 (std::crypto / sha2)           │
│  ├── Инкрементальное обновление BLAKE3 (blake3::Hasher)                │
│  ├── Запись в staging/{session_id}.part                                │
│  └── Потребление памяти процессом: O(chunk_size)                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        VALIDATION & ATOMIC CAS                         │
│                                                                        │
│  ├── Проверка размера: bytes_written == declared_size                  │
│  ├── Сигнатурный анализ (Magic bytes detection):                      │
│  │     • 45 6C 66 46 69 6C 65 00 ("ElfFile\0")    --> EVTX             │
│  │     • A1 B2 C3 D4 / D4 C3 B2 A1 / A1 B2 3C 4D  --> PCAP             │
│  │     • 0A 0D 0D 0A                             --> PCAP-NG          │
│  ├── Атомарный перенос: rename(staging_path, cas_target_path)          │
│  └── Генерация Artifact + CustodyEvent(COMMITTED_TO_CAS) в SQLite      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 PARSER DISPATCH & EVIDENCE REFINEMENT                  │
│                                                                        │
│      ┌────────────────────────────┴────────────────────────────┐       │
│      ▼                                                         ▼       │
│ EvtxAdapter (BinXML)                                  PcapAdapter      │
│  ├── Чанки по 64 КБ                                   ├── PCAP / PCAPNG│
│  ├── Шаблоны подстановок                              ├── IPv4 / IPv6  │
│  └── Windows/Sysmon события                           ├── TCP Assembly │
│                                                       └── DNS/HTTP/TLS │
│      └────────────────────────────┬────────────────────────────┘       │
│                                   ▼                                    │
│                 Canonical Observation & TimelineEvent                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Модульная организация кодовой базы

Для соблюдения лимита $< 500$ строк на файл и принципа единственной ответственности модули распределяются следующим образом:

### 2.1. `crates/storage-cas` (Storage Hardening)
- `stream.rs` — поддержка потоковой записи в CAS напрямую из стримов с одновременным dual-hashing без материализации полного буфера в RAM.

### 2.2. `crates/tool-adapters` (Forensic Adapters)
- `registry.rs` — определение типа файла по magic bytes (`detect_artifact_type`), интерфейс `ToolAdapter`.
- `evtx/header.rs` — парсинг заголовка файла EVTX (4096 байт), структуры чанков (65536 байт), CRC32 и номеров записей.
- `evtx/binxml.rs` — декодер токенов Microsoft BinXML (Open Start Element, Close Element, Value, Attribute, TemplateInstance).
- `evtx/template.rs` — кеш и резолвер шаблонов BinXML, подстановка строковых и бинарных значений параметров.
- `evtx/sysmon.rs` — нормализация событий Sysmon (ProcessCreate, NetworkConnect, ImageLoad) и Windows Security (4624 Logon, 4688 Process).
- `pcap/common.rs` — базовые типы: `Packet`, `FlowKey` (5-tuple), `FlowSummary`, `ProtocolType`.
- `pcap/pcap_reader.rs` — потоковый разбор классического Libpcap (Endianness, Nanosecond resolution).
- `pcap/pcapng_reader.rs` — парсинг блоков PCAP-NG (Section Header, Interface Description, Enhanced Packet Block).
- `pcap/reassembly.rs` — сборка TCP-потоков: отслеживание порядковых номеров (`seq/ack`), дедупликация повторов, обнаружение пропусков (`GAPPED`, `TRUNCATED`, `COMPLETE`).
- `pcap/dns.rs` — парсинг пакетов DNS (RFC 1035): вопросы, A/AAAA, CNAME, PTR ответы, rcode.
- `pcap/http.rs` — парсинг заголовков HTTP/1.0 и HTTP/1.1 (Method, Host, URI, Status, User-Agent).
- `pcap/tls.rs` — парсинг TLS ClientHello / ServerHello: SNI, версия протокола, наборы шифров, разбор X.509 сертификатов (Subject, Issuer, SAN, Fingerprint).

### 2.3. `crates/timeline-engine` (Forensic Timeline)
- `model.rs` — каноническая модель `TimelineEvent` со строгим сохранением `source_timestamp`, `ingest_timestamp` и связей с улик-сетом.
- `projection.rs` — преобразование разнородных `Observation` в единую временную шкалу.

### 2.4. `crates/engine-server` (Ingest Session & RPC)
- `evidence/session.rs` — менеджер сессий загрузки, конечный автомат состояний (`IngestSessionManager`).
- `evidence/staging.rs` — управление временными файлами, очистка при прерывании или ошибке.
- `evidence/rpc.rs` — JSON-RPC контроллеры `evidence.ingest.*`.

---

## 3. Схема данных (SQLite Migrations v3)

Для поддержки непрерывной цепочки владения (Chain of Custody) и сессий загрузки в базу данных добавляются новые таблицы:

```sql
-- Таблица сессий потоковой загрузки
CREATE TABLE IF NOT EXISTS evidence_ingest_sessions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    declared_size_bytes INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    staging_path TEXT NOT NULL,
    status TEXT NOT NULL, -- CREATED, RECEIVING, RECEIVED, VALIDATING, HASHED, COMMITTED, PARSING, NORMALIZING, READY, FAILED, CANCELLED, QUARANTINED
    sha256 TEXT,
    blake3 TEXT,
    artifact_id TEXT REFERENCES artifacts(id),
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Таблица событий цепочки владения (Chain of Custody)
CREATE TABLE IF NOT EXISTS evidence_custody_events (
    event_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    action TEXT NOT NULL, -- RECEIVED, HASHED, VALIDATED, COMMITTED_TO_CAS, PARSER_DISPATCHED, PARSED, NORMALIZED, DERIVED, QUARANTINED
    actor TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    blake3 TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    session_id TEXT,
    details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custody_artifact ON evidence_custody_events(artifact_id, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_custody_case ON evidence_custody_events(case_id);

-- Таблица канонических таймлайн-событий
CREATE TABLE IF NOT EXISTS forensic_timeline_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    timestamp_utc TEXT NOT NULL,
    end_timestamp_utc TEXT,
    category TEXT NOT NULL, -- Process, Network, Auth, File, Persistence, Vulnerability
    source_type TEXT NOT NULL, -- EVTX, PCAP, TELEMETRY, SCAN
    description TEXT NOT NULL,
    entity_refs_json TEXT NOT NULL,
    observation_refs_json TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timeline_case_time ON forensic_timeline_events(case_id, timestamp_utc);
```

---

## 4. Спецификация структур данных и API

### 4.1. Канонический `EvtxRecord`
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvtxRecord {
    pub record_id: u64,
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub version: u8,
    pub level: u8,
    pub computer: String,
    pub user_sid: Option<String>,
    pub source_timestamp: chrono::DateTime<chrono::Utc>,
    pub execution_process_id: u32,
    pub execution_thread_id: u32,
    pub event_data: serde_json::Value,
    pub system_data: serde_json::Value,
    pub raw_record_hash: String,
}
```

### 4.2. Сетевой поток и сборка TCP (`PcapFlow` & `TcpReassembly`)
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FlowKey {
    pub src_ip: std::net::IpAddr,
    pub dst_ip: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReassemblyQuality {
    Complete,
    Partial,
    Truncated,
    Gapped,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowSummary {
    pub key: FlowKey,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub packets_forward: u64,
    pub packets_reverse: u64,
    pub bytes_forward: u64,
    pub bytes_reverse: u64,
    pub quality: ReassemblyQuality,
    pub application_protocol: Option<String>,
}
```

### 4.3. Каноническое событие таймлайна (`TimelineEvent`)
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineEvent {
    pub id: core_domain::id::EntityId,
    pub case_id: core_domain::id::EntityId,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub end_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub category: String,
    pub source_type: String,
    pub entity_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub description: String,
    pub confidence: f32,
}
```

---

## 5. План поэтапной реализации и Gate 2 Acceptance

Разработка выполняется итеративно по компонентам:

1. **Фаза 1: Streaming Ingest & Chain of Custody (`EVID-001..009`)**
   - Реализация сессионного менеджера и временного staging.
   - Dual-hashing (SHA-256 + BLAKE3) при чтении чанков.
   - Криптографический хеш-чейн в таблице `evidence_custody_events`.
   - CAS commit без повторных аллокаций.

2. **Фаза 2: Нативный парсер Windows EVTX (`EVTX-001..003`)**
   - Чтение чанков по 64 КБ с валидацией контрольных сумм.
   - Декодирование токенов BinXML и инстанцирование шаблонов.
   - Извлечение событий Sysmon и Windows Security с сохранением `source_timestamp`.

3. **Фаза 3: Сетевой анализатор PCAP / PCAP-NG (`PCAP-001..007`)**
   - Разбор заголовков PCAP и блоков PCAP-NG (IPv4/IPv6).
   - Сборка TCP-сессий с дедупликацией и фиксацией `ReassemblyQuality`.
   - Протокольные парсеры DNS (запросы/ответы), HTTP/1.x (заголовки) и TLS (ClientHello/ServerHello/Certs).

4. **Фаза 4: Канонический Timeline & Форензик-корпус (`TIME-001`, `QA-DFIR-001..003`)**
   - Проекция наблюдений в `forensic_timeline_events`.
   - Формирование тестового корпуса `tests/fixtures/forensics/` (EVTX, Sysmon, PCAP, PCAPNG).
   - Интеграционный сквозной тест: Ingest $\to$ CAS $\to$ Parse $\to$ Custody $\to$ Timeline $\to$ Restart recovery.
