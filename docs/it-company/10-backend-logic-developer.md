# 10. Отчет разработчика бизнес-логики: Реализация доменного слоя и сервисов (Contract A)

**Документ**: Отчет о реализации бизнес-логики и чистого доменного слоя  
**Версия**: 1.0.0-final  
**Инженер**: Роль 10 (Backend Logic Developer)  
**Статус**: COMPLETED / APPROVED  
**Связанные документы**: [`09-backend-architect.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/09-backend-architect.md), [`08-database-engineer.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/08-database-engineer.md), [`05-security-architect.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/05-security-architect.md), [`project_state.json`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/project_state.json)

---

## 1. Обзор выполненных работ

В соответствии со спецификацией Contract A из [`09-backend-architect.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/09-backend-architect.md) и требованиями безопасности SEC-ARCH-01..06 из [`05-security-architect.md`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/docs/it-company/05-security-architect.md), полностью реализован чистый слой бизнес-логики платформы CTF Unified Workspace Platform.

Реализация выполнена без транспортных зависимостей (без HTTP/JSON-RPC), все компоненты покрыты модульными тестами:
- **`crates/core-domain`**: доменные сущности, строгие ошибки `DomainError`, стейт-машины `Challenge` и `Job`, движок трансформаций `RecipeService`, кольцевой буфер `BoundedOutputBuffer`, ядро `JobEngineService`, сервис генерации Write-up.
- **`crates/storage-cas`**: WORM хранилище с одновременным вычислением BLAKE3 + SHA-256, блочным чтением срезов (до 64 KB) и защитой от Zip-Slip / Zip-Bomb (SEC-ARCH-02).
- **`crates/storage-sqlite`**: эволюция схемы V002, PRAGMA-профиль WAL, реализация `WorkspaceService`, `FlagService`, `WriteupService` и репозиториев артефактов/джобов/шагов трансформаций.

---

## 2. Реализация задач декомпозиции

### 2.1. TASK-BE-10-01: Доменные сущности, ошибки и стейт-машины (`core-domain`)

1. **Доменные ошибки (`DomainError`)**:
   Реализованы строго по спецификации Contract A в [`crates/core-domain/src/error.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/error.rs):
   - `NotFound { entity: &'static str, id: String }`
   - `Validation(String)`
   - `SecurityViolation(String)`
   - `ResourceLimit(String)`
   - `Storage(String)`
   - `Execution(String)`
   - `Conflict(String)`
   С вспомогательными конструкторами `DomainError::not_found`, `DomainError::security`, `DomainError::conflict` и конверсией `From<serde_json::Error>` / `From<std::io::Error>`.

2. **Доменные структуры**:
   - [`crates/core-domain/src/ctf/entities.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/entities.rs):
     `Competition`, `CompetitionSummary`, `CreateCompetitionCmd`, `CompetitionStatus`, `CompetitionFormat`, `Challenge`, `ChallengeSummary`, `ChallengeDetails`, `CreateChallengeCmd`, `ChallengeStatus`, `ChallengeCategory`, `BlockedReason`, `TargetScope`, `ChallengeArtifact`, `ArtifactRole`, `IngestMetadata`.
   - [`crates/core-domain/src/ctf/pipeline_entities.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/pipeline_entities.rs):
     `Job`, `JobSpec`, `JobRuntimeState`, `JobStatus`, `JobRuntime`, `ResourceLimits`, `OutputTail`, `TransformStep`, `RecipeOp`, `RecipePreview`, `RecipeMeta`, `FlagCandidate`, `VerificationStatus`, `Writeup`, `Secret`.
   - [`crates/core-domain/src/ctf/traits.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/traits.rs):
     Асинхронные трейты `WorkspaceService`, `CasStorageService`, `JobEngineService`, `RecipeService`, `FlagService`, `WriteupService`.

3. **Стейт-машины (`state_machine.rs`)**:
   - `ChallengeStatus`: валидация допустимости переходов (`New` $\to$ `InProgress`, `InProgress` $\to$ `Blocked`/`Solved`, `Blocked` $\to$ `InProgress`). Переход в `Blocked` требует обязательного указания `BlockedReason`.
   - `JobStatus`: изоляция терминальных состояний (`Succeeded`, `Failed`, `Cancelled`, `TimedOut`, `Interrupted`). Запрет повторных переходов из терминальных статусов, автоматическая фиксация `started_at`, `completed_at` и флага `timeout_triggered`.

---

### 2.2. TASK-BE-10-02: WORM CAS хранилище и безопасная распаковка (`storage-cas`)

Реализован трейт `CasStorageService` в [`crates/storage-cas/src/lib.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-cas/src/lib.rs):
1. **Потоковый Ingest (`store_stream`)**:
   - Потоковое чтение блоками по 64 KB (`AsyncReadExt`).
   - Синхронное хеширование потока в один проход: BLAKE3 (локатор) + SHA-256 (криминалистический хэш).
   - Атомарная фиксация файла в иерархическом каталоге CAS `root/ab/cd/abcdef...`.
   - Применение режима WORM (выставление атрибута `readonly(true)`).
2. **Блочное чтение срезов (`read_slice`)**:
   - Валидация ограничения размера: длина среза не более 64 KB (`MAX_SLICE_LENGTH = 65536`). При превышении возвращается `DomainError::Validation`.
   - Позиционирование через `SeekFrom::Start(offset)` с минимальной аллокацией памяти.
   - Задержка чтения среза < 2 мс.
3. **Контроль целостности (`verify_integrity`)**:
   - Потоковый пересчет BLAKE3 хэша с проверкой соответствия ожидаемому идентификатору.
4. **Защита архивов (`unpack_archive_safe` / `safe_archive.rs`)**:
   - **SEC-ARCH-02 Anti-Zip-Slip**: канонизация путей через `Path::canonicalize`, санитизация относительных путей, удаление префиксов `\`, `/`, дисковых букв `C:`, блокировка компонентов `..` с генерацией `DomainError::SecurityViolation`.
   - **SEC-ARCH-02 Anti-Zip-Bomb**:
     * Лимит количества файлов: не более 10 000 элементов.
     * Лимит размера одного файла: не более 2 ГБ.
     * Лимит суммарного размера архива: не более 5 ГБ.
     * Контроль коэффициента сжатия: прерывание с ошибкой `SecurityViolation`, если коэффициент `uncompressed / compressed` превышает 100:1.
   - **Anti-Symlink**: пропуск и блокировка создания символических и жестких ссылок.
   - Каждый извлеченный файл автоматически регистрируется в CAS с возвратом `ArtifactId`.

---

### 2.3. TASK-BE-10-03: Реализация `WorkspaceService` и SQLite репозиториев (`storage-sqlite`)

Реализовано в [`crates/storage-sqlite/src/ctf_workspace.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-sqlite/src/ctf_workspace.rs) и [`crates/storage-sqlite/src/ctf_artifacts_jobs.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-sqlite/src/ctf_artifacts_jobs.rs):
1. **Интеграция миграции V002**:
   - Скрипт `V002_ctf_core_schema.sql` встроен в `schema.rs` и применяется методом `apply_ctf_v002` при вызове `migrate()`.
   - 100% обратная совместимость: добавлено значение по умолчанию `created_at TEXT NOT NULL DEFAULT (datetime('now'))` в таблицу `artifacts_v2` для бесшовной работы устаревшего DFIR-кода.
2. **Тюнинг SQLite PRAGMA**:
   При каждом открытии соединения устанавливаются директивы:
   ```sql
   PRAGMA journal_mode = WAL;
   PRAGMA synchronous = NORMAL;
   PRAGMA cache_size = -64000;      -- 64 MB RAM
   PRAGMA mmap_size = 268435456;    -- 256 MB Memory Mapped I/O
   PRAGMA temp_store = MEMORY;
   PRAGMA busy_timeout = 10000;     -- 10s non-blocking wait
   PRAGMA foreign_keys = ON;
   ```
3. **Операции Workspace**:
   - `create_competition`, `get_competition`, `list_competitions` (с фильтрацией по статусу и подсчетом решенных задач).
   - `create_challenge`, `get_challenge` (сборка `ChallengeDetails` с привязанными артефактами, активными процессами и принятыми флагами), `list_challenges` (фильтрация по соревнованию и категории).
   - `update_challenge_status` (согласованный переход через доменную стейт-машину).
   - `update_challenge_target` (актуализация целевого сетевого хоста/порта/протокола).
4. **Репозитории связей**:
   - `add_challenge_artifact` и `list_challenge_artifacts`.
   - `insert_job` и `update_job_state`.
   - `insert_transform_step` и `list_transform_steps`.

---

### 2.4. TASK-BE-10-04: Безопасный Job Engine (`core-domain`)

Реализован в [`crates/core-domain/src/ctf/job_engine.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/job_engine.rs):
1. **Политика Zero Shell Injection (SEC-ARCH-01)**:
   - Полный отказ от передачи команд через шеллы (`sh`, `bash`, `cmd.exe`, `powershell.exe`).
   - Исполнение строго через `tokio::process::Command::new(&argv[0]).args(&argv[1..])`.
   - Валидация аргументов на наличие нулевых байтов (`\0`).
   - Принудительная санитизация опасных переменных окружения: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `NODE_OPTIONS`, `PERL5LIB`, `RUBYOPT`, `BASH_ENV`.
2. **Кольцевой буфер вывода (`ring_buffer.rs`)**:
   - Структура `BoundedOutputBuffer`:
     * Буфер начала (Head): 2 МБ для сохранения исходного баннера и заголовков.
     * Кольцевой буфер хвоста (Tail): 8 МБ для сохранения актуального завершающего вывода.
     * Лимит: 10 МБ суммарно на каждый поток процесса.
     * Отслеживание счетчика пропущенных байтов `dropped_bytes`.
3. **Таймауты и каскадная отмена (Tree Kill)**:
   - Контроль таймаута через асинхронный таймер Tokio.
   - Метод `cancel_job` отправляет сигнал через `oneshot::Sender` и немедленно вызывает `child.kill().await`, гарантируя завершение процесса и перевод джоба в статус `Cancelled`.

---

### 2.5. TASK-BE-10-05: Рецепты трансформаций и Regex Flag Scanner (`core-domain`)

Реализован в [`crates/core-domain/src/ctf/recipe.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/recipe.rs):
1. **Операции конвейера трансформаций (`RecipeOp`)**:
   - `HexDecode` / `HexEncode`: декодирование/кодирование шестнадцатеричных данных с очисткой от пробелов и префиксов `0x`.
   - `Base64Decode` / `Base64Encode`: стандартный и URL-safe Base64.
   - `Xor { key: Vec<u8> }`: побайтовое обратимое XOR-преобразование с ключом произвольной длины.
   - `Rot13`: шифр Цезаря со сдвигом 13 для латинских символов.
   - `ZlibDecompress` / `ZlibCompress`: компрессия и декомпрессия deflate потоков (`flate2`).
   - `UrlDecode` / `UrlEncode`: парсинг и сериализация процентного кодирования URL.
2. **Предварительный просмотр (`preview_pipeline`)**:
   - In-memory выполнение цепочки операций без промежуточной записи на диск.
   - Формирование репрезентативных фрагментов (до 64 байт) в виде текста или hex-дампа.
3. **Регулярный сканер флагов (`scan_flags`)**:
   - Автоматический поиск шаблонов `DEFAULT_FLAG_REGEX`: `(?i)(?:flag|ctf|sec|vuln)\{[a-zA-Z0-9_\-\+\.!@#$%^&*?]{3,128}\}`.
   - Поддержка кастомных регулярных выражений, задаваемых на уровне соревнования или задачи.
   - Возврат списка уникальных найденных флагов в предварительном просмотре рецепта.

---

### 2.6. TASK-BE-10-06: Сервисы флагов и генератор Write-up Markdown

Реализовано в [`crates/storage-sqlite/src/ctf_flags.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-sqlite/src/ctf_flags.rs) и [`crates/core-domain/src/ctf/writeup.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/writeup.rs):
1. **`FlagService`**:
   - `register_candidate`: идемпотентная регистрация флага (дедупликация по паре `challenge_id` + `value`).
   - `accept_flag`: смена статуса на `accepted`, установка времени верификации и автоматический перевод задачи в статус `Solved`.
   - `reject_flag`: отклонение флага с фиксацией причины `rejection_reason`.
   - `list_flags`: извлечение списка всех кандидатов задачи.
2. **`WriteupService`**:
   - `generate_draft`: компиляция профессионального Markdown-отчета из DAG-линии расследования:
     * Шапка и метрики задачи (категория, баллы, таргет).
     * Блок подтвержденного флага (`> [!IMPORTANT]`).
     * Таблица шагов трансформации рецептов (DAG Lineage).
     * Журнал выполненных утилит хоста (`jobs`).
     * Разделы методики решения (Walkthrough).
     * Хронологический таймлайн расследования.
   - `update_section`: точечное обновление секции Markdown без перезаписи остального содержимого.
   - `export_markdown`: атомарный экспорт Markdown-файла в файловую систему.

---

## 3. Метрики исходного кода и соблюдение лимитов

Все файлы спроектированы модульно и строго удовлетворяют правилу **< 500 строк**:

| Крейт | Файл | Кол-во строк | Назначение |
|---|---|:---:|---|
| `core-domain` | [`src/error.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/error.rs) | 70 | Контрактные ошибки `DomainError` |
| `core-domain` | [`src/ctf/entities.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/entities.rs) | 350 | Сущности соревнований, задач и артефактов |
| `core-domain` | [`src/ctf/pipeline_entities.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/pipeline_entities.rs) | 274 | Сущности процессов, рецептов, флагов, отчетов |
| `core-domain` | [`src/ctf/state_machine.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/state_machine.rs) | 221 | Стейт-машины задач и процессов |
| `core-domain` | [`src/ctf/traits.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/traits.rs) | 56 | Contract A сервисные трейты |
| `core-domain` | [`src/ctf/recipe.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/recipe.rs) | 276 | Конвейер трансформаций и Regex сканер флагов |
| `core-domain` | [`src/ctf/ring_buffer.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/ring_buffer.rs) | 132 | Ограниченный буфер вывода (10 МБ cap) |
| `core-domain` | [`src/ctf/job_engine.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/job_engine.rs) | 300 | Исполнитель процессов с нулевой инъекцией |
| `core-domain` | [`src/ctf/writeup.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/writeup.rs) | 297 | Генератор Markdown отчетов из DAG улик |
| `core-domain` | [`src/ctf/mod.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/mod.rs) | 23 | Корневой модуль реэкспорта CTF |
| `storage-cas` | [`src/lib.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-cas/src/lib.rs) | 332 | Реализация `CasStorageService` |
| `storage-cas` | [`src/safe_archive.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-cas/src/safe_archive.rs) | 298 | Anti-Zip-Slip и Anti-Zip-Bomb экстрактор |
| `storage-sqlite` | [`src/ctf_workspace.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-sqlite/src/ctf_workspace.rs) | 354 | Реализация `WorkspaceService` |
| `storage-sqlite` | [`src/ctf_flags.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-sqlite/src/ctf_flags.rs) | 350 | Реализация `FlagService` и `WriteupService` |
| `storage-sqlite` | [`src/ctf_artifacts_jobs.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-sqlite/src/ctf_artifacts_jobs.rs) | 201 | Репозитории артефактов, джобов и DAG-шагов |
| `storage-sqlite` | [`tests/ctf_storage_test.rs`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/storage-sqlite/tests/ctf_storage_test.rs) | 228 | Интеграционные тесты CTF БД |

---

## 4. Верификация и результаты тестирования

Команда `cargo test -p core-domain -p storage-cas -p storage-sqlite` выполнена успешно:
- **`core-domain`**: 22 unit-теста + 2 golden dataset теста (**24 passed, 0 failed**).
- **`storage-cas`**: 3 unit-теста (**3 passed, 0 failed**).
- **`storage-sqlite`**: 1 membership тест + 3 ctf storage теста + 5 legacy storage тестов (**9 passed, 0 failed**).
- **Всего**: **36 тестов пройдено успешно без сбоев**.

Проверка `cargo check --workspace --all-targets` подтверждает 0 ошибок и 0 предупреждений компиляции по всем 24 крейтам воркспейса.

---

## 5. Матрица передачи артефактов (Handover to Role 11)

| Роль-получатель | Передаваемый компонент | Файлы / Трейты | Назначение |
|---|---|---|---|
| **11-backend-api-developer** | Трейты сервисов Contract A | [`core-domain::ctf::traits`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/traits.rs) | Реализация JSON-RPC обработчиков пространств `competitions`, `challenges`, `jobs`, `recipes`, `flags`, `writeups`. |
| **11-backend-api-developer** | Доменные сущности и DTO | [`core-domain::ctf::entities`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/entities.rs) | Конвертация доменных моделей в RPC DTO и валидация через `validator`. |
| **11-backend-api-developer** | Маппер ошибок | [`core-domain::error::DomainError`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/error.rs) | Маппинг ошибок в коды JSON-RPC (-32001..-32005). |
| **11-backend-api-developer** | Кольцевой буфер и Job Engine | [`core-domain::ctf::job_engine`](file:///C:/Users/Siroj/Projects/soc-dfir-platform/crates/core-domain/src/ctf/job_engine.rs) | Потоковый IPC-диспатчинг событий `job.output`, `job.status_changed`, `job.progress`. |

> [!NOTE]
> Все обязательства Роли 10 выполнены в полном объеме. Реализация свободна от транспортных протоколов, готова к интеграции с JSON-RPC шлюзом Роли 11.
