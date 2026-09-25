# 11. Отчет разработчика API: Реализация транспортного слоя IPC и JSON-RPC 2.0 (Contract B)

**Документ**: Отчет о реализации API слоя, DTO и JSON-RPC диспетчеризации  
**Версия**: 1.0.0-final  
**Инженер**: Роль 11 (Backend API Layer Developer)  
**Статус**: COMPLETED / APPROVED  
**Связанные документы**: [`09-backend-architect.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/09-backend-architect.md), [`10-backend-logic-developer.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/10-backend-logic-developer.md), [`05-security-architect.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/05-security-architect.md), [`project_state.json`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/project_state.json)

---

## 1. Обзор выполненных работ

В соответствии со спецификацией Contract B из [`09-backend-architect.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/09-backend-architect.md) и бизнес-логикой Contract A из [`10-backend-logic-developer.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/10-backend-logic-developer.md), полностью реализован транспортный слой межпроцессного взаимодействия (IPC) и диспетчеризации JSON-RPC 2.0 команд для платформы CTF Unified Workspace Platform.

Слой реализован с соблюдением 100% обратной совместимости с существующей инфраструктурой SOC/DFIR, строгой изоляцией процессов и нулевой терпимостью к инъекциям (Zero Shell Injection по SEC-ARCH-01).

### Ключевые компоненты:
1. **`crates/ipc-protocol`**:
   - [`src/jsonrpc.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/jsonrpc.rs): спецификация JSON-RPC 2.0 (`JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError`, `JsonRpcNotification`), нормализованные коды ошибок (-32700..-32005) и транслятор ошибок `DomainError` $\to$ `JsonRpcError` / `ProblemDetails`.
   - [`src/ctf_dto.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/ctf_dto.rs): типизированные структуры запросов и ответов с валидацией для пространств `competitions`, `challenges`, `artifacts`, `tools`, `jobs`, `recipes`, `flags`, `writeups`.
   - [`src/events.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/events.rs): потоковые нотификации `job.output`, `job.status_changed`, `job.progress` с троттлингом 16 мс (60 FPS) и лимитом чанков (16 KB).
2. **`crates/engine-server`**:
   - [`src/ctf_dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/ctf_dispatch.rs): модульный обработчик команд пространств CTF, интегрированный с сервисным слоем `WorkspaceService`, `CasStorageService`, `LocalJobEngine`, `FlagService`, `WriteupService` и репозиториями SQLite/CAS.
   - [`src/dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/dispatch.rs): гибридный шлюз диспетчеризации, поддерживающий как современные запросы JSON-RPC 2.0, так и унаследованные пакеты `IpcRequest`.
   - [`tests/ctf_api_test.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/tests/ctf_api_test.rs): набор интеграционных тестов для проверки всех пространств имен и граничных сценариев безопасности.

---

## 2. Реализация задач декомпозиции

### 2.1. TASK-BE-11-01: JSON-RPC 2.0 фрейминг, сериализаторы и маршрутизатор
- В [`crates/ipc-protocol/src/jsonrpc.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/jsonrpc.rs) реализованы строгие структуры:
  * `JsonRpcRequest<T>` (`jsonrpc: "2.0"`, `id`, `method`, `params`).
  * `JsonRpcResponse<T>` (`jsonrpc: "2.0"`, `id`, `result`, `error`).
  * `JsonRpcError` (`code`, `message`, `data`).
  * `JsonRpcNotification<T>` (`jsonrpc: "2.0"`, `method`, `params`).
- В [`crates/engine-server/src/ctf_dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/ctf_dispatch.rs) функция `try_dispatch_jsonrpc` обеспечивает распознавание JSON-RPC 2.0 пакетов, валидацию заголовка `"2.0"`, вызов соответствующего сервиса и формирование специфицированного ответа.
- В [`crates/engine-server/src/dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/dispatch.rs) добавлена прозрачная поддержка гибридного роутинга: если входящий запрос содержит `"jsonrpc"`, он обрабатывается по спецификации JSON-RPC 2.0; иначе обрабатывается как `IpcRequest` (с сохранением поддержки DFIR-клиентов).

### 2.2. TASK-BE-11-02: Request/Response DTO с валидацией для Core CTF пространств
В [`crates/ipc-protocol/src/ctf_dto.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/ctf_dto.rs) созданы DTO с инвариантами валидации:
- **`competitions.*`**:
  * `CompetitionCreateReq`: валидация длины имени (1..120 символов), компиляция регулярного выражения шаблона флага (`Regex::new`).
  * `CompetitionGetReq`, `CompetitionListReq` (фильтрация по статусу).
- **`challenges.*`**:
  * `ChallengeCreateReq`: непустой `competition_id`, валидация имени (1..120 символов), проверка допустимости категории (`crypto`, `pwn`, `web`, `rev`, `forensics`, `misc`), опциональный `TargetScopeDto`.
  * `ChallengeGetReq`, `ChallengeListReq`, `ChallengeUpdateStatusReq` (строгая смена статуса через стейт-машину), `ChallengeUpdateTargetReq`.
- **`artifacts.*`**:
  * `ArtifactSliceReq`: проверка `artifact_id`, ограничение среза `length` от 1 до 65 536 байт (64 KB). При превышении генерируется ошибка валидации.
  * `ArtifactVerifyReq`, `ArtifactUnpackReq` (блокировка Path Traversal `..`), `ArtifactLinkChallengeReq` (привязка роли артефакта), `ArtifactListForChallengeReq`.

### 2.3. TASK-BE-11-03: RPC-обработчики пространств Tools, Jobs, Recipes, Flags, Writeups
В [`crates/engine-server/src/ctf_dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/ctf_dispatch.rs) реализована диспетчеризация:
- **`tools.list`**: возвращает манифесты зарегистрированных утилит и адаптеров (`evtx_parser`, `pcap_parser`, `host_discovery`, `strings`).
- **`jobs.*`**:
  * `jobs.submit`: валидация argv на отсутствие шелл-оболочек (`sh`, `bash`, `cmd`, `powershell`), запуск через `LocalJobEngine`, сохранение метаданных задачи в SQLite `jobs`.
  * `jobs.cancel`: отмена запущенного процесса через oneshot-канал и каскадный kill, обновление статуса в `Cancelled`.
  * `jobs.get_state`: получение runtime-статуса, времени выполнения и объемов вывода.
  * `jobs.get_output`: чтение среза вывода из кольцевого буфера (`BoundedOutputBuffer`).
- **`recipes.*`**:
  * `recipes.preview`: предварительный расчет конвейера (`Hex`, `Base64`, `XOR`, `Rot13`, `zlib`, `url`) и автоматический сканер кандидатов флагов (`scan_flags`).
  * `recipes.execute`: применение цепочки трансформаций к артефакту в CAS с атомарным сохранением результирующего артефакта.
  * `recipes.save_step`, `recipes.list_steps`: ведение DAG-истории шагов трансформации улик.
- **`flags.*`**:
  * `flags.register`: регистрация кандидата с проверкой дубликатов.
  * `flags.accept`: принятие флага и автоматический перевод задачи в статус `Solved`.
  * `flags.reject`: отклонение кандидата с фиксацией причины.
  * `flags.list`: извлечение списка всех кандидатов задачи.
- **`writeups.*`**:
  * `writeups.generate_draft`: компиляция Markdown-отчета из данных задачи, улик и DAG-шагов.
  * `writeups.export`: экспорт Markdown-файла в файловую систему с проверкой безопасности пути.
  * `writeups.update_section`: обновление секций отчета.

### 2.4. TASK-BE-11-04: Маппинг доменных ошибок `DomainError` $\to$ `JsonRpcError`
В [`crates/ipc-protocol/src/jsonrpc.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/jsonrpc.rs) реализована таблица соответствия:

| Доменная ошибка | JSON-RPC код | Символическая константа | HTTP ProblemDetails статус |
|---|:---:|---|:---:|
| Некорректный JSON синтаксис | `-32700` | `PARSE_ERROR` | `400 Bad Request` |
| Нарушена структура конверта | `-32600` | `INVALID_REQUEST` | `400 Bad Request` |
| Метод не найден (`entity == "Method"`) | `-32601` | `METHOD_NOT_FOUND` | `404 Not Found` |
| `DomainError::Validation` | `-32602` | `INVALID_PARAMS` | `400 Bad Request` |
| `DomainError::SecurityViolation` | `-32001` | `SECURITY_VIOLATION` | `403 Forbidden` |
| `DomainError::ResourceLimit` | `-32002` | `RESOURCE_EXHAUSTED` | `429 Too Many Requests` |
| `DomainError::Execution` | `-32003` | `EXECUTION_FAILED` | `500 Internal Error` |
| `DomainError::NotFound` (сущности) | `-32004` | `ENTITY_NOT_FOUND` | `404 Not Found` |
| `DomainError::Conflict` | `-32005` | `CONFLICT_STATE` | `409 Conflict` |
| `DomainError::Storage` | `-32603` | `INTERNAL_ERROR` | `500 Internal Error` |

### 2.5. TASK-BE-11-05: Потоковые события (Streaming Notifications)
В [`crates/ipc-protocol/src/events.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/events.rs) реализованы:
- `JobOutputEvent` (`job_id`, `stream`, `data`, `offset`, `is_eof`) $\to$ нотификация `job.output`.
- `JobStatusEvent` (`job_id`, `previous_status`, `new_status`, `exit_code`, `elapsed_ms`) $\to$ нотификация `job.status_changed`.
- `JobProgressEvent` (`job_id`, `stage`, `percentage`, `bytes_processed`) $\to$ нотификация `job.progress`.
- `EventThrottler`: утилита троттлинга потокового вывода с интервалом 16 мс (60 FPS) и автоматическим сбросом буфера при превышении 16 KB (`MAX_CHUNK_BYTES`).

---

## 3. Соблюдение метрик и лимитов размера файлов

Все модули спроектированы в строгом соответствии с лимитом **< 500 строк на файл**:

| Файл | Строк | Назначение |
|---|:---:|---|
| [`crates/ipc-protocol/src/jsonrpc.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/jsonrpc.rs) | 240 | Конверты JSON-RPC 2.0, коды ошибок, мапперы ошибок |
| [`crates/ipc-protocol/src/ctf_dto.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/ctf_dto.rs) | 369 | DTO сущностей CTF и правила валидации |
| [`crates/ipc-protocol/src/events.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/events.rs) | 152 | Стриминговые нотификации и 60 FPS троттлер |
| [`crates/ipc-protocol/src/lib.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/lib.rs) | 314 | Корневой модуль протокола IPC |
| [`crates/engine-server/src/ctf_dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/ctf_dispatch.rs) | 393 | Диспетчер обработчиков команд CTF |
| [`crates/engine-server/src/dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/dispatch.rs) | 486 | Шлюз диспетчеризации запросов сервера |
| [`crates/engine-server/tests/ctf_api_test.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/tests/ctf_api_test.rs) | 208 | Интеграционные тесты CTF API |

---

## 4. Верификация и результаты тестирования

Проведены все необходимые проверки:
1. `cargo check --workspace` — **0 ошибок, 0 предупреждений**.
2. `cargo test -p ipc-protocol` — **14 unit-тестов passed, 0 failed**.
3. `cargo test -p engine-server` — **30 тестов passed (14 unit + 16 integration), 0 failed**:
   - `ctf_api_test.rs`: 4 passed (жизненный цикл соревнований, кодирование ошибок, артефакты, обратная совместимость).
   - `dispatch_tests.rs`: 5 passed.
   - `phase1_streaming_ingest_test.rs`: 2 passed.
   - `phase4_golden_corpus_test.rs`: 1 passed.
   - `phase4_local_corpus_test.rs`: 1 passed.
   - `live_network_test.rs`: 2 passed.

---

## 5. Матрица передачи артефактов (Handover to Role 12)

| Роль-получатель | Передаваемый компонент | Файлы | Назначение |
|---|---|---|---|
| **12-backend-integration-engineer** | Маршрутизатор JSON-RPC | [`crates/engine-server/src/ctf_dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/ctf_dispatch.rs), [`dispatch.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/src/dispatch.rs) | Интеграция с платформенным `Runner` (Job Object / cgroups) и сквозными тестами жизненного цикла. |
| **12-backend-integration-engineer** | Потоковые нотификации | [`crates/ipc-protocol/src/events.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/ipc-protocol/src/events.rs) | Подключение `SecretRedactor` (Aho-Corasick) в потоковый конвейер вывода. |
| **12-backend-integration-engineer** | Интеграционные тесты | [`crates/engine-server/tests/ctf_api_test.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/engine-server/tests/ctf_api_test.rs) | Расширение для E2E тестов полного цикла расследования. |

> [!NOTE]
> Все задачи Роли 11 (TASK-BE-11-01 .. TASK-BE-11-05) успешно завершены. API и JSON-RPC диспетчеризация готовы к интеграции платформенных исполнителей и сквозным испытаниям.
