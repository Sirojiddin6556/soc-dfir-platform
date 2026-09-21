# ARCHITECTURE SPECIFICATION & SYSTEM DESIGN
## Stage 4 / Release v0.5: DFIR Evidence Pipeline & Forensic Artifacts Hardening
### (Amended with Architecture Review v0.5-A1)

> **Document**: `09-v05-architecture-specification.md`  
> **Status**: GATE 1 — APPROVED WITH AMENDMENTS  
> **Target Release**: `v0.5.0`  
> **Parent Contract**: `08-v05-requirements-contract.md`  

---

## 1. Архитектурная топология и разделение Plane-ов

Для обеспечения стабильной работы при анализе дампов трафика и логов размером от сотен мегабайт до десятков гигабайт архитектура v0.5 строго разделяет **Control Plane** и **Data Plane**:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE (JSON-RPC)                        │
│                                                                        │
│  POST /rpc                                                             │
│  ├── evidence.ingest.begin(case_id, filename, declared_size)           │
│  │     └── returns { session_id, upload_url, upload_token, chunk_size }│
│  ├── evidence.ingest.status(session_id)                                │
│  │     └── returns progress, speed, bytes_received, hashes, status     │
│  ├── evidence.ingest.complete(session_id)                              │
│  │     └── triggers validation, atomic CAS commit, custody update      │
│  └── evidence.ingest.cancel(session_id)                                │
│        └── allowed ONLY before COMMITTED; cleans up staging file       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   DATA PLANE (Binary Streaming I/O)                    │
│                                                                        │
│  PUT /ingest/{session_id}/chunk                                        │
│  Headers:                                                              │
│    Authorization: Ingest <capability_token>                            │
│    Upload-Offset: <bytes_offset>                                       │
│    Content-Type: application/octet-stream                              │
│  Body: RAW BYTES (No JSON, No Base64)                                  │
│                                                                        │
│  ├── Проверка токена (session, case, actor, expiry, max_size)          │
│  ├── Проверка смещения: Upload-Offset == session.bytes_received        │
│  ├── Инкрементальное обновление SHA-256 (sha2::Sha256)                 │
│  ├── Инкрементальное обновление BLAKE3 (blake3::Hasher)                │
│  ├── Запись в staging/{session_id}.part                                │
│  └── Потребление памяти процессом: строго O(chunk_size)                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   STAGING VALIDATION & ATOMIC CAS                      │
│                                                                        │
│  1. Проверка размера: staging.len() == declared_size_bytes             │
│  2. Сигнатурный анализ (Magic bytes ground-truth):                     │
│       • 45 6C 66 46 69 6C 65 00 ("ElfFile\0")    --> EVTX              │
│       • A1 B2 C3 D4 (Microsecond BE)             --> PCAP              │
│       • D4 C3 B2 A1 (Microsecond LE)             --> PCAP              │
│       • A1 B2 3C 4D (Nanosecond BE)              --> PCAP              │
│       • 4D 3C B2 A1 (Nanosecond LE)              --> PCAP              │
│       • 0A 0D 0D 0A                              --> PCAP-NG           │
│  3. Дедупликация CAS:                                                  │
│       Если объект с полученным BLAKE3 уже в CAS:                       │
│       ├── Проверить размер и целостность существующего объекта         │
│       ├── Удалить временный staging-файл                               │
│       └── Создать ArtifactReference на существующий CAS-хеш            │
│       Иначе:                                                           │
│       ├── Записать в temp-файл в том же томе/файловой системе CAS      │
│       ├── fsync()                                                      │
│       └── Атомарный rename() в cas/objects/{b3_prefix}/{b3_hash}       │
│  4. Фиксация в БД:                                                     │
│       Вставка Artifact + CustodyEvent(COMMITTED_TO_CAS) в SQLite       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   PARSER PIPELINE (Phases 2 & 3)                       │
│                                                                        │
│  В Phase 1:                                                            │
│    status = COMMITTED, parser_status = PENDING_IMPLEMENTATION          │
│    (никаких пустых или синтетических Observation не создается)         │
│                                                                        │
│  В Phases 2 & 3:                                                       │
│    COMMITTED -> PARSER_QUEUED -> PARSING -> NORMALIZING -> READY       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Модульная организация кодовой базы Phase 1

Для соблюдения лимита $< 500$ строк на файл и строгой типизации:

### 2.1. `crates/engine-server/src/evidence/`
- `session.rs` — конечный автомат и структура `IngestSession` (`CREATED`, `RECEIVING`, `RECEIVED`, `VALIDATING`, `HASHED`, `COMMITTED`, `QUARANTINED`, `FAILED`, `CANCELLED`).
- `staging.rs` — `StagingManager`: создание, дозапись чанков, проверка смещений, восстановление после сбоя сервера (потоковый перерасчет хешей).
- `token.rs` — криптографический генератор и валидатор capability upload токенов (`UploadToken { session_id, case_id, actor_id, expires_at, max_size }`).
- `custody.rs` — модуль канонического расчета и верификации хеш-цепочки `CustodyChain` и функции `verify_custody_chain(artifact_id)`.
- `data_plane.rs` — HTTP обработчик `PUT /ingest/{session_id}/chunk` с чтением raw stream и обновлением хешей.
- `rpc.rs` — контроллеры JSON-RPC Control Plane (`evidence.ingest.begin`, `status`, `complete`, `cancel`).

### 2.2. `crates/storage-cas/`
- `ContentAddressedStorage` расширяется методом фиксации валидированного staging-файла `commit_file(staging_path, blake3_hash)` с поддержкой дедупликации и атомарного перемещения.

### 2.3. `crates/storage-sqlite/`
- Репозиторные методы для работы с таблицами `evidence_ingest_sessions` и `evidence_custody_events` с защитой от каскадного удаления (`ON DELETE RESTRICT`).

---

## 3. Схема данных SQLite (Migrations v3)

```sql
-- Таблица сессий потоковой загрузки
CREATE TABLE IF NOT EXISTS evidence_ingest_sessions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    filename TEXT NOT NULL,
    declared_size_bytes INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    staging_path TEXT NOT NULL,
    status TEXT NOT NULL, -- CREATED, RECEIVING, RECEIVED, VALIDATING, HASHED, COMMITTED, FAILED, CANCELLED, QUARANTINED
    sha256 TEXT,
    blake3 TEXT,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    actor_id TEXT NOT NULL,
    upload_token_hash TEXT NOT NULL,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingest_case ON evidence_ingest_sessions(case_id);
CREATE INDEX IF NOT EXISTS idx_ingest_status ON evidence_ingest_sessions(status);

-- Таблица цепочки владения (Chain of Custody)
CREATE TABLE IF NOT EXISTS evidence_custody_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES evidence_ingest_sessions(id) ON DELETE RESTRICT,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL,
    action TEXT NOT NULL, -- RECEIVED, HASHED, VALIDATED, COMMITTED_TO_CAS, PARSER_DISPATCHED, PARSED, NORMALIZED, DERIVED, QUARANTINED
    actor_id TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    blake3 TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    details_hash TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custody_artifact_seq ON evidence_custody_events(artifact_id, sequence_no);
CREATE INDEX IF NOT EXISTS idx_custody_session_seq ON evidence_custody_events(session_id, sequence_no);

-- Триггеры защиты неизменяемости цепочки владения (Append-Only Invariant)
CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_update
BEFORE UPDATE ON evidence_custody_events
BEGIN
    SELECT RAISE(ABORT, 'Forensic Invariant Violation: evidence_custody_events is append-only; updates are strictly forbidden.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_custody_delete
BEFORE DELETE ON evidence_custody_events
BEGIN
    SELECT RAISE(ABORT, 'Forensic Invariant Violation: evidence_custody_events is append-only; deletions are strictly forbidden.');
END;
```

---

## 4. Канонический алгоритм расчета хеш-цепочки Custody

Для исключения атак расширения длины и неоднозначностей конкатенации строк каждое поле сериализуется в канонический бинарный формат с префиксом длины:

```rust
pub fn compute_event_hash(
    previous_event_hash: &str,
    sequence_no: u64,
    event_id: &str,
    session_id: &str,
    artifact_id: Option<&str>,
    case_id: &str,
    action: &str,
    actor_id: &str,
    timestamp_utc: &str,
    sha256: &str,
    blake3: &str,
    details_hash: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SOCDFIR-CUSTODY-V1\0");

    let append_field = |hasher: &mut blake3::Hasher, field: &[u8]| {
        let len = (field.len() as u32).to_be_bytes();
        hasher.update(&len);
        hasher.update(field);
    };

    append_field(&mut hasher, previous_event_hash.as_bytes());
    hasher.update(&sequence_no.to_be_bytes());
    append_field(&mut hasher, event_id.as_bytes());
    append_field(&mut hasher, session_id.as_bytes());
    append_field(&mut hasher, artifact_id.unwrap_or("").as_bytes());
    append_field(&mut hasher, case_id.as_bytes());
    append_field(&mut hasher, action.as_bytes());
    append_field(&mut hasher, actor_id.as_bytes());
    append_field(&mut hasher, timestamp_utc.as_bytes());
    append_field(&mut hasher, sha256.as_bytes());
    append_field(&mut hasher, blake3.as_bytes());
    append_field(&mut hasher, details_hash.as_bytes());

    hasher.finalize().to_hex().to_string()
}
```

### Верификатор цепочки (`verify_custody_chain`):
1. Выбирает все события для `artifact_id` (или `session_id`), упорядоченные по `sequence_no ASC`.
2. Проверяет непрерывность номеров `sequence_no` начиная с 1: $seq_{i} = seq_{i-1} + 1$.
3. Для первого события ($seq=1$) проверяет `previous_event_hash == "GENESIS"`.
4. Для каждого последующего события проверяет `previous_event_hash == event_hash[i-1]`.
5. Повторно вычисляет `compute_event_hash(...)` и сверяет с записанным `event_hash`.
6. При малейшем расхождении возвращает `Err(CustodyChainBroken { sequence_no, reason })`.

---

## 5. Восстановление при рестарте сервера (Crash & Resume Semantics)

При запуске сервера или получении чанка после рестарта:
1. Менеджер сессий проверяет сессии в статусе `RECEIVING`.
2. Проверяет наличие файла `staging/{session_id}.part` на диске и получает его точную длину: `actual_len = metadata.len()`.
3. Если `actual_len > 0`, потоково считывает файл блоками по 64 КБ через `sha2::Sha256` и `blake3::Hasher` для восстановления промежуточных хешей.
4. Обновляет `bytes_received = actual_len` в SQLite.
5. Клиент, запрашивая `evidence.ingest.status(session_id)`, получает актуальный `bytes_received` и возобновляет передачу со следующего байта.
