# 01. Product Discovery: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-01-DISCOVERY`  
**Status**: `APPROVED / SCOPE FROZEN`  
**Baseline**: Human Gate 1 Scope Freeze

---

## 1. Product Vision
**SOC-DFIR Platform** — локальная deterministic desktop Blue Team-платформа, которая автоматически исследует неизвестную инфраструктуру, собирает и нормализует security evidence, определяет assets/software/vulnerabilities, строит доказуемый Attack Graph и Timeline, сопоставляет поведение противника с MITRE ATT&CK, Cyber Kill Chain и Pyramid of Pain и позволяет проводить воспроизводимые SOC/DFIR/Threat Hunting/CTF-расследования со скрытым Ground Truth и объяснимым scoring.

---

## 2. Ключевые архитектурные инварианты MVP (P0 Scope)

1. **Deterministic Architecture**:
   - Полное отсутствие недетерминированных LLM-планеров и автономных probabilistic AI-агентов. Все выводы строятся на строгих детерминированных правилах, нормализаторах и корреляторах графа.
2. **Infrastructure & Asset Discovery (P0)**:
   - Автоматическая инвентаризация неизвестной инфраструктуры: обнаружение хостов, IP, ОС, сетевых интерфейсов, маршрутов, портов, топологии сети, правил фаервола, запущенных процессов, служб, планировщиков (cron/systemd timers, Scheduled Tasks), пользователей/групп, точек автозапуска (autoruns), активных соединений, контейнеров и конфигураций.
3. **Software, SBOM & Vulnerability Pipeline (P0)**:
   - Непрерывная цепочка: `Asset → Service → Software → Version → CPE/PURL → SBOM → CVE → CVSS → EPSS → KEV → Contextual Risk`.
   - Защита от ложных срабатываний (False Positives) при анализе пакетов с Linux security backports и эвристическом фингерпринтинге версий.
4. **Автоматизированный Workflow Engine & Conditional DAG (P0)**:
   - Аналитик не запускает десятки утилит вручную. Система выполняет conditional DAG с автоэскалацией:
     `Quick (разведка) → Anomaly detected → Standard (сбор артефактов) → Suspicious asset → Deep (форензика/дампы)`.
   - Контроль 6 ресурсных классов: `CPU`, `IO`, `NET`, `MEMORY`, `FORENSIC`, `TARGET_LOAD` (защита исследуемой системы от деградации).
5. **Строгая модель данных (P0)**:
   - `Artifact` $\rightarrow$ `Observation` $\rightarrow$ `Fact` $\rightarrow$ `Evidence / EvidenceSet` $\rightarrow$ `Correlation` $\rightarrow$ `Attack Graph` $\rightarrow$ `Finding`.
   - Разделение измерений:
     - `AssertionType`: `Fact` (наблюдение), `Inference` (вывод правила), `Hypothesis` (аналитическая гипотеза).
     - `VerificationState`: `Candidate`, `Corroborated`, `Confirmed`, `Disproved`.
     - Метрики: `confidence`, `severity`, `risk_score`, `evidence_strength`, `pain_level`.
6. **Scenario Ground Truth & Investigation-Based Scoring (P0)**:
   - Отказ от flag-centric CTF. Оценка строится на сопоставлении с защищённым Ground Truth:
     `Assets discovered + Facts + Evidence coverage + Timeline correctness + Attack Graph + ATT&CK techniques + Containment actions → Explainable Score`.
7. **Privilege Broker с типизированными операциями (P0)**:
   - UI полностью непривилегирован. Брокер валидирует не command-line allowlist, а строго типизированные `PrivilegedOperation` после проверки `BrokerCapability`. UI никогда не передаёт shell commands или сырые `argv[]`.
8. **Visual Intelligence (P0/P1)**:
   - Автоматическая проекция: `Infrastructure Map`, `Attack Graph`, `Process Tree`, `Timeline`, `MITRE ATT&CK Matrix`, `Cyber Kill Chain`, `Pyramid of Pain`, `Lateral Movement Map`.
   - Каждая вершина и стрелка содержат drill-down на подтверждающие факты (`supported_by`). Многомерное кодирование: фигура = тип сущности (NFR-UX-002), цвет = severity, граница = confidence.

---

## 3. Границы платформ и условные роли

| Платформа / Роль | Статус | Обоснование |
|---|---|---|
| **Windows** | **Tier 1 (MVP)** | Основная рабочая среда расследований и хостовой телеметрии (ETW, Sysmon, EVTX, Registry). |
| **Linux** | **Tier 1 (MVP)** | Инфраструктурные сервисы, контейнеры, eBPF, auditd, сетевые шлюзы. |
| **macOS** | **Tier 2 (Future)** | Исключён из MVP во избежание распыления ресурсов до стабилизации ядра. |
| **ML/CV (13–15)** | **SKIPPED** | Полный отказ от вероятностных моделей ради юридической чистоты и 100% воспроизводимости. |
| **Data Viz (20a)**| **REQUIRED**| Сложные интерактивные графы, таймлайн, матрица ATT&CK, карты инфраструктуры. |
| **A11y (26a)**    | **REQUIRED**| Соответствие NFR-UX-002: различение состояний формой/геометрией, а не только цветом. |
| **SRE (31)**      | **SKIPPED** | Продукт является локальным десктопным приложением (Offline-first) без круглосуточного облачного SLA. |
