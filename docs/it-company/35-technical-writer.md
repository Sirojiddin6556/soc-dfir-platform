# 35. Complete Technical Documentation: CTF Unified Workspace Platform

**Profile ID**: `PRF-35-TECHWRITER`  
**Status**: `COMPLETED`  
**Role**: Technical Writer (Технический писатель)  
**Input Documents**:  
- `docs/it-company/01-product-discovery-manager.md` (PRD)  
- `docs/it-company/04-solution-architect.md` (Architecture)  
- `docs/it-company/09-backend-architect.md`, `16-frontend-architect.md`  
- `docs/it-company/27-infrastructure-architect.md`, `28-devops-build-engineer.md`  
- `docs/it-company/36a-requirement-judge.md` (Traceability & features)  

---

## 1. Обзор платформы

**CTF Unified Workspace Platform** — это специализированное рабочее пространство для решения задач соревнований в формате Jeopardy CTF (категории Web, Crypto, Reverse, Pwn, Forensics, Stego, OSINT, Misc) и расследования инцидентов кибербезопасности.

### Ключевые возможности:
- **Challenge Matrix & Competitions**: структурированное управление соревнованиями, тасками, очками и статусами решения.
- **Content-Addressed Storage (CAS)**: неизменяемое хранение артефактов на базе хэшей BLAKE3 и SHA-256 с автоматической дедупликацией.
- **Recipe Engine**: интерактивный конвейер декодирования и деобфускации (Base64, Hex, XOR, Gunzip, URL decode) с превью в реальном времени.
- **Hex Viewer & Math Data Viz**: виртуализированный шестнадцатеричный редактор, гистограмма байт и расчет энтропии Шеннона (до 8.00 бит/байт).
- **Auto-Flag Scanner & Lifecycle**: автоматическое обнаружение флагов в выводе утилит по настраиваемому регулярному выражению (`candidate` $\rightarrow$ `accepted` $\rightarrow$ `Solved`).
- **Zero-Shell Job Runner**: безопасный запуск внешних инструментов анализа (`tshark`, `strings`, `binwalk`) с таймаутами и экстренным прерыванием дерева процессов (горячая клавиша **F9**).
- **Write-up Studio**: автоматическая генерация воспроизводимых отчетов Markdown со сквозной родословной улик (Lineage) и автоматическим маскированием паролей и секретных токенов `[REDACTED:...]`.

---

## 2. Архитектура и структура каталогов

```
soc-dfir-platform/
├── apps/
│   └── desktop-ui/                 # Frontend SPA (Vanilla JS ES Modules + CSS)
│       ├── css/ctf.css             # Стили и токены темы CTF Workspace
│       ├── js/ctf/
│       │   ├── components/         # UI компоненты (Matrix, Workspace, Hex, Recipes, Writeup)
│       │   ├── *_store.js          # Реактивные сторы состояния (Workspace, Jobs, Recipes, Flags)
│       │   └── ctf_app.js          # Корневой контроллер приложения и хэш-роутер
│       └── scripts/                # Скрипты тестирования UI и E2E
├── crates/
│   ├── engine-server/              # Ядро бэкенда, маршрутизация задач и CLI
│   ├── ipc-protocol/               # DTO модели, JSON-RPC кодеки, RFC 7807 ошибки
│   ├── storage-sqlite/             # Репозитории SQLite WAL и миграции (V002 / U002)
│   ├── storage-cas/                # Неизменяемое блочное хранилище BLAKE3
│   └── tool-adapters/              # Адаптеры форензик-инструментов (PCAP, EVTX)
├── config/
│   ├── docker/                     # Multi-stage Dockerfile и docker-compose.yml
│   ├── nginx/                      # Nginx reverse proxy и SPA routing fallback
│   └── .env.example                # Шаблон конфигурации переменных окружения
├── docs/it-company/                # Артефакты всех этапов конвейера IT-Company
└── scripts/
    ├── run-all-tests.ps1           # Единый кросс-платформенный скрипт тестирования
    └── check-syntax.mjs            # AST-валидатор JavaScript модулей
```

---

## 3. Руководство по запуску и разработке

### 3.1. Быстрый запуск в среде разработки
1. **Запуск тестов платформы**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/run-all-tests.ps1
   ```
2. **Запуск фронтенда**:
   ```bash
   cd apps/desktop-ui
   npm test        # Проверка синтаксиса и E2E сьюта
   npm start       # Запуск локального сервера (порт 8080/3000)
   ```
3. **Запуск в контейнерах (Docker Compose)**:
   ```bash
   docker compose -f config/docker/docker-compose.yml up --build -d
   ```
   Фронтенд и прокси доступны по адресу `http://localhost`, пробы состояния по адресу `http://localhost/health/live`.

---

## 4. Горячие клавиши (Hotkeys)

- **F9**: **Emergency Panic Kill** — мгновенное завершение всех активных процессов и дочерних потоков CLI-утилит.
- **Tab / Shift+Tab**: доступная циклическая навигация по интерактивным элементам.
- **Ctrl+S / Cmd+S**: быстрое сохранение рецепта или черновика Write-up.
