# REQUIREMENTS CONTRACT & SCOPE SPECIFICATION
## Stage 4 / Release v0.5: DFIR Evidence Pipeline & Forensic Artifacts Hardening

> **Document**: `08-v05-requirements-contract.md`  
> **Status**: GATE 1 — PROPOSED FOR APPROVAL  
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
      [evidence.ingest.begin(case_id)]
                   │
                   ▼
     STREAMING STAGING (Data Plane)
      [evidence.ingest.chunk(binary)]
        ├── Memory: O(chunk_size)
        ├── Dual Hashing: BLAKE3 + SHA-256
        └── Temp Staging Storage
                   │
                   ▼
       VALIDATION & TYPE DETECTION
        ├── Magic bytes verification
        └── Integrity & size check
                   │
                   ▼
         CAS ATOMIC FINALIZE
        ├── Immutable storage (.cas/objects)
        ├── Artifact record creation
        └── CustodyEvent (COMMITTED_TO_CAS, hash chain)
                   │
                   ▼
           PARSER DISPATCH
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
| **`EVID-001`** | **Typed Ingest API** | Реализация RPC методов: `evidence.ingest.begin`, `evidence.ingest.chunk`, `evidence.ingest.complete`, `evidence.ingest.cancel`, `evidence.ingest.status`. |
| **`EVID-002`** | **Streaming Data Plane** | Потоковая передача чанков бинарных данных без накладных расходов Base64. Потребление памяти строго $O(chunk\_size)$. |
| **`EVID-003`** | **Staging Lifecycle** | Изоляция незавершенных загрузок в директории `staging/`. Защита CAS от мусорных и невалидных данных. Атомарный перенос в CAS при завершении. |
| **`EVID-004`** | **Dual Hashing on Stream** | Инкрементальное вычисление криптографических хешей `SHA-256` (судебный стандарт) и `BLAKE3` (внутренняя адресация CAS) на лету при приеме чанков. |
| **`EVID-005`** | **Append-Only Chain-of-Custody** | Хранение полной цепочки владения: `previous_event_hash`, `event_hash`, `action`, `actor`, `timestamp_utc`, `sha256`, `blake3`, `session_id`. Хеш-чейн гарантирует невозможность подделки истории. |
| **`EVID-006`** | **Magic Byte & Type Detection** | Автоматическая идентификация типов: `ElfFile\0` (EVTX), `0xA1B2C3D4` / `0x4D3CB2A1` (PCAP), `0x0A0D0D0A` (PCAP-NG). Неизвестные/битые файлы переводятся в `QUARANTINED`. |
| **`EVID-007`** | **Parser Registry & Dispatch** | Типизированный диспетчер адаптеров `ToolAdapterRegistry`, направляющий валидированный артефакт в соответствующий парсер. |
| **`EVID-008`** | **Provenance Tracking** | Каждая `Observation` содержит `artifact_id`, `record_locator`, `source_timestamp`, `parser_version` и `raw_record_hash`. |
| **`EVID-009`** | **UI Ingest State & Progress** | Передача прогресса загрузки, скорости, хешей и детальных ошибок валидации в UI через IPC-статусы. |

---

### 3.2. Windows Event Log Engine (`EVTX-001..003`)

| ID | Требование | Описание |
|---|---|---|
| **`EVTX-001`** | **Native EVTX Ingestion** | Декодирование бинарных файлов Windows Event Log (`.evtx`) со структурой чанков по 64 КБ, проверкой контрольных сумм заголовков и обработкой BinXML. |
| **`EVTX-002`** | **BinXML & Template Engine** | Парсинг шаблонов подстановки, строковых таблиц и системных дескрипторов событий в каноническую структуру `EvtxRecord`. |
| **`EVTX-003`** | **Security & Sysmon Normalization** | Нормализация ключевых событий безопасности Windows (4624 Logon, 4688 Process Creation, 7045 Service Install, 4697, 4720) и Sysmon (Event 1, 3, 7, 10, 11, 22) в типизированные `Observation`. Разделение `source_timestamp` и `ingest_timestamp`. |

---

### 3.3. Network Packet & Flow Engine (`PCAP-001..007`)

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

### 3.4. Canonical Timeline & Forensics QA (`TIME-001`, `QA-DFIR-001..003`)

| ID | Требование | Описание |
|---|---|---|
| **`TIME-001`** | **Canonical Timeline Projection** | Преобразование наблюдений EVTX, сетевых сессий PCAP и хостовой телеметрии в унифицированную структуру `TimelineEvent` с сохранением ссылок на доказательства и исходные сущности. |
| **`QA-DFIR-001`**| **Golden Forensic Corpus** | Набор эталонных артефактов в `tests/fixtures/forensics/`: Security EVTX, Sysmon EVTX, IPv6 PCAPNG, DNS/HTTP/TLS PCAP для проверки воспроизводимости. |
| **`QA-DFIR-002`**| **Truncated & Corrupted Ingestion** | Тесты на усеченные файлы, битые заголовки, неполные TCP-потоки с проверкой корректного перехода в статус `QUARANTINED` или `PARTIAL` без паники и краша процесса. |
| **`QA-DFIR-003`**| **Streaming Ingest Benchmarks** | Тесты на обработку больших файлов с замером потребления памяти ($O(chunk\_size)$ invariant). |

---

## 4. Конечный автомат сессии Ingest (State Machine)

Каждая загрузка артефакта управляется строгим конечным автоматом:

```text
       [evidence.ingest.begin]
                  │
                  ▼
              CREATED
                  │
                  │ [chunk received]
                  ▼
          ┌── RECEIVING ◄──┐
          │       │        │ [more chunks]
          │       └────────┘
          │
          │ [evidence.ingest.complete]
          ▼
              RECEIVED
                  │
                  ▼
             VALIDATING ──────(format/magic mismatch)─────► QUARANTINED
                  │
                  ▼
                HASHED
                  │
                  ▼
              COMMITTED (Atomic CAS Store)
                  │
                  ▼
               PARSING
                  │
                  ▼
             NORMALIZING
                  │
                  ▼
                READY

Исключительные состояния:
  * ANY STATE ──(client error / abort)──► CANCELLED
  * VALIDATION / PARSER FATAL ERROR   ──► FAILED
```

---

## 5. Модель Chain of Custody (Судебный аудит)

Каждое действие над артефактом генерирует неизменяемую запись аудита с криптографическим хешированием предшествующего события (Hash Chaining):

```rust
pub struct CustodyEvent {
    pub event_id: EntityId,
    pub artifact_id: EntityId,
    pub case_id: EntityId,
    pub action: CustodyAction,
    pub actor: String,
    pub timestamp_utc: DateTime<Utc>,
    pub sha256: String,
    pub blake3: String,
    pub previous_event_hash: String,
    pub event_hash: String,
    pub details: serde_json::Value,
}

pub enum CustodyAction {
    Received,
    Hashed,
    Validated,
    CommittedToCas,
    ParserDispatched,
    ParsedSuccessfully,
    Normalized,
    DerivedArtifactCreated,
    Quarantined,
    Exported,
}
```

Формула хеша события:
$$\text{event\_hash} = \text{BLAKE3}(\text{previous\_event\_hash} \parallel \text{action} \parallel \text{timestamp\_utc} \parallel \text{sha256} \parallel \text{blake3})$$

---

## 6. Границы релиза (Out of Scope для v0.5)

Во избежание распыления фокуса из v0.5 исключены следующие компоненты (перенесены на `v0.5.1` / `v0.6`):
- Захват сырого дампа оперативной памяти (Live RAM Acquisition);
- Интеграция с Volatility 3 / Rekall;
- Разбор файловых систем raw-образов дисков (`.E01`, `.raw`, `.vmdk`, NTFS MFT/UsnJrnl);
- Полнотекстовый поиск YARA по телам файлов;
- Живой сетевой захват пакетов на лету (Live PCAP Sniffing);
- Удаленный сбор артефактов через агенты (Remote Agent Collection).

---

## 7. Критерии приемки релиза (Acceptance Criteria Gate 2)

| ID | Критерий |
|---|---|
| **`AC-DFIR-1`** | **Streaming Chunking**: Загрузка 50 МБ артефакта через чанки по 1 МБ с пиковым потреблением RAM $< 30$ МБ. Отсутствие Base64 в Data Plane. |
| **`AC-DFIR-2`** | **Dual Hashing Invariant**: `SHA-256` и `BLAKE3`, вычисленные на лету во время стриминга, бит-в-бит совпадают с хешами файла на диске. |
| **`AC-DFIR-3`** | **CAS Immutability**: Повторная загрузка идентичного файла возвращает тот же CAS-объект, но регистрирует новую запись артефакта и новую цепочку владения. |
| **`AC-DFIR-4`** | **Native EVTX**: Корректный разбор реального бинарного файла Windows `Security.evtx` с извлечением записей 4624/4688 без вызова внешних процессов. |
| **`AC-DFIR-5`** | **PCAP/PCAP-NG Parity**: Декодирование как классического `.pcap`, так и `.pcapng` с извлечением TCP/UDP сессий, DNS QNAME и TLS SNI. |
| **`AC-DFIR-6`** | **Reassembly Quality**: Точное указание качества сборки потока (`COMPLETE`, `PARTIAL`, `TRUNCATED`, `GAPPED`). |
| **`AC-DFIR-7`** | **Observation Provenance**: Каждое наблюдение, факт и таймлайн-событие содержат `artifact_id` и `record_locator`. |
| **`AC-DFIR-8`** | **Quality Gate**: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` проходят со 100% успехом. Все файлы строго $< 500$ строк. |
