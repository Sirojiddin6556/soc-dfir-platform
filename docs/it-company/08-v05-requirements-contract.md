# REQUIREMENTS CONTRACT & SCOPE SPECIFICATION
## Stage 4 / Release v0.5: DFIR Evidence Pipeline & Forensic Artifacts Hardening
### (Amended with Architecture Review v0.5-A1)

> **Document**: `08-v05-requirements-contract.md`  
> **Status**: GATE 1 — APPROVED WITH AMENDMENTS  
> **Target Release**: `v0.5.0`  
> **Parent Milestone**: Stage 4 — Investigation Engine Reliability & Hardening  

---

## 1. Problem Statement & Mission

В релизах `v0.3.0` и `v0.4.0` платформа получила надежный сканер периметра и детерминированный движок анализа уязвимостей. 
Однако обработка форензик-артефактов (DFIR Ingestion) оставалась прототипной:
1. **Перегрузка Control Plane**: передача файлов происходила через JSON-RPC Base64 в теле одного запроса, что приводило к аллокациям памяти $O(file\_size)$, раздуванию JSON на 33% и крашам на файлах более 200 МБ.
2. **Отсутствие бинарного EVTX**: бинарный формат Microsoft BinXML (`ElfFile\0`) не декодировался нативно, требуя предварительной ручной конвертации через сторонние утилиты.
3. **Ограниченность сетевого анализа**: парсер PCAP не поддерживал формат PCAP-NG (`0x0A0D0D0A`), трафик IPv6, сборку TCP-сессий (stream reassembly) и прикладные метаданные (DNS/HTTP/TLS).
4. **Утрата семантики времени**: не разделялись время фиксации события источником, время загрузки артефакта и нормализованное время таймлайна.
5. **Слабая цепочка владения (Chain of Custody)**: отсутствовало криптографическое связывание событий аудита артефакта (hash chaining).

### Главный архитектурный принцип v0.5:
> **Forensic Integrity & Non-Fabrication**:
> 1. Входящие байты не становятся уликой (Evidence) до валидации, хеширования и фиксации в CAS.
> 2. Потоковый Ingestion обязан потреблять память $O(chunk\_size)$, а не $O(file\_size)$.
> 3. Каждая Observation обязана иметь неразрывную связь с исходным артефактом (`artifact_id`, `record_locator`, `source_timestamp`, `raw_record_hash`).
> 4. Платформа никогда не фабрикует отсутствующие поля и сообщает точный статус полноты реконструкции потока (`COMPLETE`, `PARTIAL`, `TRUNCATED`, `GAPPED`).

---

## 2. Сквозной поток Forensic Ingestion

```text
FORENSIC ARTIFACT (EVTX / PCAP / PCAP-NG)
                   │
                   ▼
       INGEST SESSION (Control Plane)
      [POST /rpc: evidence.ingest.begin(case_id, filename, declared_size)]
        ├── Returns: session_id, upload_url, upload_token, chunk_size
                   │
                   ▼
     STREAMING STAGING (Data Plane)
      [PUT /ingest/{session_id}/chunk]
        ├── Headers: Upload-Offset, Authorization: Ingest <token>
        ├── Body: RAW OCTET-STREAM (No JSON, No Base64)
        ├── Memory: O(chunk_size)
        ├── Dual Hashing on fly: BLAKE3 + SHA-256
        └── Temp Staging Storage (staging/{session_id}.part)
                   │
                   ▼
       VALIDATION & TYPE DETECTION (evidence.ingest.complete)
        ├── Magic bytes verification:
        │     • EVTX: 45 6C 66 46 69 6C 65 00 ("ElfFile\0")
        │     • PCAP: A1 B2 C3 D4 (BE usec) | D4 C3 B2 A1 (LE usec)
        │             A1 B2 3C 4D (BE nsec) | 4D 3C B2 A1 (LE nsec)
        │     • PCAP-NG: 0A 0D 0D 0A
        └── Strict size & offset integrity check
                   │
                   ▼
         CAS ATOMIC FINALIZE
        ├── Verify existing size/hash in CAS (Dedup)
        ├── Atomic move from staging to CAS directory
        ├── Create Artifact record
        └── CustodyEvent (COMMITTED_TO_CAS, tamper-evident hash chain)
                   │
                   ▼
           PARSER PIPELINE (Phase 2/3)
        ┌──────────┴──────────┐
        ▼                     ▼
   EvtxAdapter           PcapAdapter
   (Native BinXML)     (PCAP / PCAP-NG)
        │                     │
        ▼                     ▼
   Raw Records           Flows / Reassembled Streams
        │                     │
        └──────────┬──────────┘
                   ▼
         NORMALIZATION ENGINE
        ├── source_timestamp preservation
        ├── Provenance linking
        └── ArtifactObservation[]
                   │
                   ▼
          EVIDENCE & TIMELINE
        ┌──────────┴──────────┐
        ▼                     ▼
   EvidenceEngine        TimelineEngine
   (Fact grouping)     (CanonicalTimelineEvent)
        │                     │
        └──────────┬──────────┘
                   ▼
       CORRELATION & ATTACK GRAPH
```

---

## 3. Детализированный объем задач (Scope v0.5)

### 3.1. Ingestion Pipeline & Chain of Custody (`EVID-001..009`)

| ID | Требование | Описание |
|---|---|---|
| **`EVID-001`** | **Typed Ingest Control Plane** | RPC методы: `evidence.ingest.begin`, `evidence.ingest.status`, `evidence.ingest.complete`, `evidence.ingest.cancel`. `begin` возвращает `session_id`, `upload_url` и capability `upload_token`. |
| **`EVID-002`** | **Binary Streaming Data Plane** | Потоковый endpoint `PUT /ingest/{session_id}/chunk` (raw `application/octet-stream`), `Upload-Offset: <bytes>`, токен авторизации. Память строго $O(chunk\_size)$. Никакого Base64. |
| **`EVID-003`** | **Staging & Atomic CAS** | Запись в `staging/{session_id}.part`. CAS не изменяется до валидации. При коммите: атомарный перенос через temp на той же файловой системе с fsync. При совпадении BLAKE3 — дедупликация объекта с созданием новой ссылки. |
| **`EVID-004`** | **Dual Hashing on Stream** | Инкрементальный параллельный расчет `SHA-256` (судебный стандарт) и `BLAKE3` (адресация CAS) на лету при поступлении байтов. |
| **`EVID-005`** | **Tamper-Evident Chain of Custody** | Append-only журнал с канонической бинарной сериализацией полей (length-prefixed) и хеш-цепочкой. Обеспечивает обнаружение изменений при верификации от доверенного chain head. Включает функцию `verify_custody_chain(artifact_id)`. Запрет `ON DELETE CASCADE`. |
| **`EVID-006`** | **Forensic Magic Detection** | Распознавание 4 вариантов классического PCAP (BE/LE usec/nsec), PCAP-NG (`0x0A0D0D0A`) и EVTX (`ElfFile\0`). Расширение файла — только подсказка, истина — сигнатура. Невалидные/битые файлы переходят в `QUARANTINED`. |
| **`EVID-007`** | **Data Plane Security & Capabilities** | Capability-токен загрузки привязан к `(session_id, case_id, actor_id, expiry, max_size)`. Доступ только по loopback, санитарная очистка имени файла (отсутствие path traversal), запрет свободного CORS. |
| **`EVID-008`** | **Resume & Restart Semantics** | Разрешена только последовательная запись (`chunk.offset == bytes_received`). При рестарте сервера незавершенная сессия восстанавливается: чтение размера staging-файла с диска и потоковый перерасчет хешей без сериализации hasher state в БД. |
| **`EVID-009`** | **Phase 1 Ingestion Status** | В Phase 1 после коммита артефакта возвращается статус `COMMITTED` с `parser_status = PENDING_IMPLEMENTATION`. Платформа не фабрикует пустые наблюдения до реализации парсеров. `evidence.ingest.complete` идемпотентен. |

---

### 3.2. Windows Event Log Engine (`EVTX-001..003`) — Phase 2

| ID | Требование | Описание |
|---|---|---|
| **`EVTX-001`** | **Native EVTX Ingestion** | Декодирование бинарных файлов Windows Event Log (`.evtx`) со структурой чанков по 64 КБ, проверкой контрольных сумм заголовков и обработкой BinXML. |
| **`EVTX-002`** | **BinXML & Template Engine** | Парсинг шаблонов подстановки, строковых таблиц и системных дескрипторов событий в каноническую структуру `EvtxRecord`. |
| **`EVTX-003`** | **Security & Sysmon Normalization** | Нормализация ключевых событий безопасности Windows (4624 Logon, 4688 Process Creation, 7045 Service Install, 4697, 4720) и Sysmon (Event 1, 3, 7, 10, 11, 22) в типизированные `Observation`. Разделение `source_timestamp` и `ingest_timestamp`. |

---

### 3.3. Network Packet & Flow Engine (`PCAP-001..007`) — Phase 3

| ID | Требование | Описание |
|---|---|---|
| **`PCAP-001`** | **PCAP & PCAP-NG Ingestion** | Чтение классического Libpcap (Microsecond/Nanosecond, Little/Big Endian) и современного PCAP-NG (Section Header, Interface Description, Enhanced Packet Blocks). |
| **`PCAP-002`** | **Multi-layer Packet Decoding** | Декодирование Ethernet, 802.1Q (VLAN), IPv4, IPv6, TCP, UDP, ICMP. |
| **`PCAP-003`** | **Flow & Session Reconstruction** | Группировка пакетов в двунаправленные сессии (5-tuple: src/dst IP, src/dst port, protocol). Расчет метрик: пакеты, байты, длительность, флаги завершения. |
| **`PCAP-004`** | **TCP Stream Reassembly** | Реконструкция потока данных TCP с отслеживанием sequence numbers, дедупликацией повторных передач (retransmission), сборкой пакетов вне порядка (out-of-order) и присвоением статуса сборки (`COMPLETE`, `PARTIAL`, `TRUNCATED`, `GAPPED`). |
| **`PCAP-005`** | **DNS Protocol Extraction** | Извлечение DNS-запросов и ответов: query name, qtype, A/AAAA/CNAME answers, rcode, TTL. |
| **`PCAP-006`** | **HTTP Protocol Extraction** | Парсинг HTTP/1.0 и HTTP/1.1 запросов/ответов: method, host, URI, status code, user-agent, content-type, server header (без сохранения тела по умолчанию). |
| **`PCAP-007`** | **TLS Protocol Extraction** | Извлечение ClientHello/ServerHello: SNI (Server Name Indication), список шифров, согласованная версия TLS, ALPN, сертификаты сервера (Subject, Issuer, SAN, SHA-256 fingerprint). |

---

### 3.4. Canonical Timeline & Forensics QA (`TIME-001`, `QA-DFIR-001..003`) — Phase 4

| ID | Требование | Описание |
|---|---|---|
| **`TIME-001`** | **Canonical Timeline Projection** | Преобразование наблюдений EVTX, сетевых сессий PCAP и хостовой телеметрии в унифицированную структуру `TimelineEvent` с сохранением ссылок на доказательства и исходные сущности. |
| **`QA-DFIR-001`**| **Golden Forensic Corpus** | Набор эталонных артефактов в `tests/fixtures/forensics/`: Security EVTX, Sysmon EVTX, IPv6 PCAPNG, DNS/HTTP/TLS PCAP для проверки воспроизводимости. |
| **`QA-DFIR-002`**| **Truncated & Corrupted Ingestion** | Тесты на усеченные файлы, битые заголовки, неполные TCP-потоки с проверкой корректного перехода в статус `QUARANTINED` или `PARTIAL` без паники и краша процесса. |
| **`QA-DFIR-003`**| **Streaming Ingest Benchmarks** | Тесты на обработку больших файлов с замером потребления памяти ($O(chunk\_size)$ invariant). |

---

## 4. Конечный автомат сессии Ingest (Hardened State Machine)

```text
       [POST /rpc: evidence.ingest.begin]
                        │
                        ▼
                    CREATED
                        │
                        │ [PUT /ingest/{id}/chunk]
                        ▼
                ┌── RECEIVING ◄──┐
                │       │        │ [more chunks at valid offset]
                │       └────────┘
                │
                │ [POST /rpc: evidence.ingest.complete]
                ▼
                    RECEIVED
                        │
                        ▼
                   VALIDATING ──────(magic/format mismatch)─────► QUARANTINED
                        │
                        ▼
                      HASHED
                        │
                        ▼
            ┌─────── COMMITTED ───────┐ (CAS Atomic Move + Artifact + Custody)
            │                         │
      (Phase 1: DONE)           (Phase 2/3: Parser Pipeline)
            │                         │
   [PARSER_PENDING]                   ▼
                                PARSER_QUEUED
                                      │
                                      ▼
                                   PARSING
                                      │
                                      ▼
                                 NORMALIZING
                                      │
                                      ▼
                                    READY

Правила отмены и завершения:
  * CANCEL разрешён ТОЛЬКО в состояниях: CREATED, RECEIVING, RECEIVED, VALIDATING, HASHED.
  * CANCEL СТРОГО ЗАПРЕЩЁН после перехода в COMMITTED (артефакт зафиксирован в CAS и охраняется законом целостности улик).
  * complete() идемпотентен: повторный вызов возвращает существующий результат без дублирования артефактов.
  * Любая критическая ошибка ввода-вывода или несоответствие размера переводит сессию в FAILED.
```

---

## 5. Модель Tamper-Evident Chain of Custody

События до коммита фиксируются с `session_id`, а после коммита связываются с постоянным `artifact_id`:

```rust
pub struct CustodyEvent {
    pub event_id: EntityId,
    pub session_id: EntityId,
    pub artifact_id: Option<EntityId>,
    pub case_id: EntityId,
    pub sequence_no: u64,
    pub action: CustodyAction,
    pub actor_id: String,
    pub timestamp_utc: DateTime<Utc>,
    pub sha256: String,
    pub blake3: String,
    pub previous_event_hash: String,
    pub event_hash: String,
    pub details_hash: String,
    pub details: serde_json::Value,
}
```

### Канонический расчет хеша события (Length-Prefixed Binary Serialization):
Каждое поле кодируется как `[u32_be_len][bytes]`, исключая неоднозначность конкатенации:
```text
event_hash = BLAKE3(
    "SOCDFIR-CUSTODY-V1\0" ||
    len_pref(previous_event_hash) ||
    u64_be(sequence_no) ||
    len_pref(event_id) ||
    len_pref(session_id) ||
    len_pref(artifact_id.unwrap_or("")) ||
    len_pref(case_id) ||
    len_pref(action.as_str()) ||
    len_pref(actor_id) ||
    len_pref(timestamp_utc.to_rfc3339()) ||
    len_pref(sha256) ||
    len_pref(blake3) ||
    len_pref(details_hash)
)
```

Свойство системы:
> **Обеспечивает tamper-evident chain: любое изменение или удаление ранее записанного события немедленно обнаруживается при верификации цепочки от доверенного chain head.**

---

## 6. Границы релиза (Out of Scope для v0.5)

- Захват сырого дампа оперативной памяти (Live RAM Acquisition);
- Интеграция с Volatility 3 / Rekall;
- Разбор файловых систем raw-образов дисков (`.E01`, `.raw`, `.vmdk`, NTFS MFT/UsnJrnl);
- Полнотекстовый поиск YARA по телам файлов;
- Живой сетевой захват пакетов на лету (Live PCAP Sniffing);
- Удаленный сбор артефактов через агенты (Remote Agent Collection).

---

## 7. Критерии приемки Phase 1 (Acceptance Criteria Gate 2 Phase 1)

| ID | Критерий |
|---|---|
| **`AC-P1-1`** | **Streaming Upload**: Загрузка 50 МБ артефакта чанками по 1 МБ через `PUT /ingest/{id}/chunk` с пиковым потреблением RAM $< 30$ МБ. Base64 отсутствует в Data Plane. |
| **`AC-P1-2`** | **Dual Hashing Invariant**: `SHA-256` и `BLAKE3`, вычисленные на лету во время стриминга, бит-в-бит совпадают с хешами файла. |
| **`AC-P1-3`** | **Crash & Resume Recovery**: Имитация сбоя/перезапуска сервера посередине передачи. Сервер перечитывает и перехеширует staging-файл, принимает остаток чанков с точного offset и успешно завершает сессию. |
| **`AC-P1-4`** | **Tamper-Evident Verification**: Функция `verify_custody_chain(artifact_id)` подтверждает валидность цепочки. Модификация любой строки в SQLite ломает проверку. |
| **`AC-P1-5`** | **CAS Dedup**: Повторный upload идентичного файла переиспользует объект в CAS, не тратя дополнительное дисковое пространство. |
| **`AC-P1-6`** | **FSM & Security**: Отклонение неверного offset, просроченного токена, попытки отмены после `COMMITTED`, попытки path traversal в имени файла. |
| **`AC-P1-7`** | **Code Hygiene**: `#![forbid(unsafe_code)]`, все файлы $< 500$ строк, `cargo clippy -D warnings` и `cargo test` = 100% green. |
