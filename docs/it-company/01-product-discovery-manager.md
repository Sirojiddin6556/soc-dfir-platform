# 01. Product Discovery & Vision: CTF Unified Workspace Platform

## 1. Product Vision
Трансформация десктопного решения `soc-dfir-platform` (Rust backend + Desktop/WebView IPC + SQLite/CAS) из узкоспециализированного инструмента расследования Windows-инцидентов в универсальное, модульное рабочее место участника CTF-соревнований (Jeopardy CTF: Web, Crypto, Reverse, Pwn, Forensics, Stego, OSINT, Misc/Programming).

Цель: участник открывает условие задачи, импортирует файлы или сетевые координаты сервиса, анализирует данные, проверяет гипотезы, получает флаг-кандидат и сохраняет полностью воспроизводимое решение (write-up) в едином изолированном пространстве без хаоса ручного копирования файлов и несохранённых скриптов.

---

## 2. Product Requirements Document (PRD)

### Целевая аудитория
* CTF-игроки (соло и команды), студенты ИБ, исследователи безопасности, реверс-инженеры и специалисты DFIR.

### Ключевые роли в системе
1. **CTF Player / Investigator**: создание соревнований/задач, импорт файлов, исследование данных, запуск инструментов, выдвижение гипотез, валидация флагов, экспорт write-up.
2. **Local System / Agent**: локальный движок исполнения задач (native, container, disposable VM), изоляция процессов, сбор артефактов и логов.

### Границы системы (Scope)
* **In Scope (v1 MVP)**: Jeopardy CTF, соревнования/задачи, поддержка произвольных файлов (`stored/unclassified`), Tool Registry & Job Runner, Recipe/Transformation engine (CyberChef-like), Text/Hex viewer, Forensics (EVTX/PCAP/Images/Memory via Volatility), Web HTTP workbench, Crypto workbench, Reverse/Pwn profiles, воспроизводимые Write-ups, SQLite метаданные + CAS хранилище.
* **Out of Scope (v1)**: Attack-Defense режим с раундами и SLA, многопользовательский сервер реального времени, микросервисы/Kafka, собственный декомпилятор, «кнопка автоматического решения всех задач».

---

## 3. Требования

### Функциональные требования (FR)
* **FR-01 (Workspace & Context)**: Управление сущностями Competition -> Challenge -> Artifacts. Задачи изолированы, контексты и секреты не пересекаются.
* **FR-02 (Robust Ingest & CAS)**: Любой файл сохраняется в CAS с вычислением хэшей (BLAKE3/SHA-256) со статусом `stored/unclassified`. Отсутствие парсера не приводит к отказу хранения.
* **FR-03 (Job Engine & Tool Registry)**: Запуск инструментов с параметрами через типизированные адаптеры (массив аргументов без shell-конкатенации), таймауты, лимиты памяти/диска, перехват stdout/stderr, честная отмена деревьев процессов (`taskkill /T` / cgroups).
* **FR-04 (Common Analysis & Recipes)**: Hex/Text viewer со смещениями, извлечение строк (ASCII/UTF-8/UTF-16), кодировки (Base64, Hex, URL, XOR, zlib), распаковка архивов с защитой от zip-bomb и path traversal, конвейер трансформаций (recipes).
* **FR-05 (Category Workbenches)**:
  * *Forensics*: PCAP (потоки, сессии, DNS/HTTP), EVTX (фильтры, timeline), Memory (Volatility 3 adapter).
  * *Stego*: RGB/Alpha bit-planes, metadata, carver, аудио-спектрограммы.
  * *Web*: HTTP workbench, cURL importer, cookie manager, repeat/diff responses.
  * *Crypto*: модульная арифметика, XOR, классические шифры, Python/Sage workspace.
  * *Reverse & Pwn*: парсер PE/ELF заголовков, интеграция декомпиляторов, pwntools runner в контролируемой среде.
  * *OSINT & Misc*: карточки улик, scratchpad для скриптов.
* **FR-06 (Hypotheses & Flags)**: Регистрация гипотез, улик (Evidence), кандидатов на флаг по регулярным выражениям, статус `accepted` только по подтверждению пользователя/платформы.
* **FR-07 (Write-up Generator)**: Автоматическая генерация Markdown отчета со ссылками на шаги, артефакты, хэши и скрипты решения.

### Нефункциональные требования (NFR)
* **NFR-01 (Безопасность)**: Запуск недоверенных бинарников CTF строго вне хостовой ОС (контейнер / одноразовая VM). Предотвращение RCE через архивы и HTML preview. Секреты (токены, пароли) маскируются в логах.
* **NFR-02 (Производительность)**: Отзывчивый UI при открытии файлов до 500 МБ через chunking/streaming. Виртуализированный скроллинг для таблиц и Hex viewer.
* **NFR-03 (Целостность и откат)**: Гарантия неизменяемости оригиналов. Аддитивная схема миграции SQLite с поддержкой старых дел `soc-dfir-platform`.
* **NFR-04 (Надежность)**: Авария внешнего инструмента не роняет движок и UI. Статус job отражает `interrupted`/`timed_out`/`failed`.

---

## 4. Риски и стратегии миграции

1. **Риск потери старых данных расследований**: 
   *Решение*: Аддитивная миграция SQLite, создание backup перед миграцией, связь Cases -> Challenges без удаления таблиц.
2. **Риск застревания на недоверенных бинарниках (RCE/Host compromise)**:
   *Решение*: Разделение execution profiles: Static (host safe), Network (scoped), Dynamic (Disposable VM/Sandbox).
3. **Риск разрастания скоупа (разработка всех категорий одновременно)**:
   *Решение*: Строгий поэтапный релиз по Gate-системе (G0 -> G1 -> G2 -> G3 MVP).

---

## 5. Дорожная карта (Roadmap) и этапы

* **Этап 0 (Gate G0, 1–2 недели)**: Аудит текущего состояния, baseline сборки/тестов, фиксация схемы БД, устранение дефектов ingest.
* **Этап 1 (Gate G1, 2–3 недели)**: CTF Workspace (Competition/Challenge/Artifact/Notes), миграция Cases.
* **Этап 2 (Gate G2, 3–4 недели)**: Job Engine, Tool Registry, Native Runner, история операций, отмена процессов.
* **Этап 3 (Gate G3, 2–3 недели) — MVP Релиз**: Hex/Text viewer, Strings, поиск, кодировки/XOR/хэши, рецепты, распаковка архивов.
* **Этап 4 (Gate G4, 4–6 недель)**: Forensics (PCAP, EVTX, Volatility 3) & Steganography (bit planes, carver, audio).
* **Этап 5–6 (Gate G5-G6, 6–10 недель)**: Web Workbench & Crypto Analysis Workspace.
* **Этап 7–8 (Gate G7-G8, 8–12 недель)**: Reverse Engineering & Pwn Sandbox.
* **Этап 9–10 (Gate G9-G10, 6–8 недель)**: OSINT/Misc, детерминированные подсказки, Write-up генератор, финальная стабилизация.

---

## 6. Решение по условным ролям конвейера
* **Роли 13–15 (ML/CV)**: **ПРОПУЩЕНЫ**. Для классического Jeopardy CTF v1 тяжелые нейросетевые модели избыточны.
* **Роль 20a (Data Visualization)**: **ВКЛЮЧЕНА**. Критична для визуализации hex-дампов, энтропии данных, спектрограмм и графов зависимостей улик.
* **Роль 26a (Accessibility Auditor)**: **ВКЛЮЧЕНА В БАЗОВОМ ОБЪЕМЕ**. Контрастность терминала, темная тема для ночных CTF, читаемость моноширинных шрифтов.
* **Роль 31 (SRE)**: **ПРОПУЩЕНА**. Продукт является локальным десктопным приложением; задачи стабильности и надежности закрываются ролями 27–30 и 34.

---

## 7. Инструкция для Роли 02 (Business Analyst)
* Вход: данный документ `01-product-discovery-manager.md` и роадмап из запроса.
* Задача: Разбить проект на конкретные Epics (EP-00 до EP-04 для фазы MVP), детализировать User Stories с критериями приемки по стандарту Given-When-Then, определить Edge Cases и сценарии ошибок.
* Выход: `docs/it-company/02-business-analyst.md` и обновление `project_state.json`.
