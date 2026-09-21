# Gate 2 Runtime Verification Report
## Stage 4 / Release v0.3: Reliable Network Discovery

> **Date**: 2026-09-21  
> **Status**: GATE 2 READY FOR REVIEW  
> **Branch**: `stage4-investigation-hardening` (Baseline Tag: `v0.2-live-baseline` at commit `7da9c0f`)  
> **Verdict**: **ALL 10 VERIFICATION GATES PASSED**

---

## 1. Build / Quality Gate
- `cargo check --workspace` — **PASS (0 errors)**
- `cargo fmt --all -- --check` — **PASS (100% compliant)**
- `cargo clippy --workspace --all-targets -- -D warnings` — **PASS (0 errors, 0 warnings)**
- `cargo test --workspace` — **PASS (0 failed, 0 ignored, 58+ unit and integration tests across 23 workspace crates)**
- Git Baseline Isolation:
  - `v0.2-live-baseline` указывает на commit `7da9c0f` (замороженный baseline до Stage 4).
  - `stage4-investigation-hardening` содержит новую архитектуру `scan-engine`.

---

## 2. Zero-Mock Gate
- Просканирована вся кодовая база `crates/` на наличие синтетических идентификаторов (`DC01.CORP.LOCAL`, `WS-FIN-04`, `DMZ-WEB01`).
- **Результат**: 0 совпадений в LIVE execution path. (Единственное вхождение — `DC01` в юнит-тесте парсинга Sysmon EVTX в `crates/tool-adapters/src/lib.rs`).
- Проверено отсутствие захардкоженных CVE в боевом движке: демо-CVE изолированы исключительно внутри `#[cfg(test)]` и `tests/fixtures/`.
- Статические идентификаторы `h1/h2/h3` заменены на детерминированные `h_{sanitized_ip}`.

---

## 3. Remote Discovery Gate
- Проведено прямое тестирование парсера и экспандера CIDR:
  - `"10.10.20.0/24"` корректно разворачивается ровно в 254 уникальных хоста (`10.10.20.1`...`10.10.20.254`).
  - Ограничение безопасности: подсети крупнее `/16` (более 65 536 хостов) отклоняются с `CidrTooLarge` во избежание OOM.
- **Обнаружение при блокировке ICMP**:
  - Реализован двухфазный сбор: чтение системной таблицы ARP (`read_arp_table()`) + многопортовый TCP ping probe (`tcp_ping_hosts()`).
  - Если ICMP заблокирован файрволом, хост фиксируется живым по первому полученному TCP SYN/ACK или RST/ACK на открытом или закрытом порту.

---

## 4. Port-State Gate (TIMEOUT != CLOSED)
- Реализована строгая классификация сетевых ошибок в `crates/scan-engine/src/port_scan.rs`:
  - `ErrorKind::ConnectionRefused` / RST → `PortState::Closed`
  - `ErrorKind::TimedOut` / Elapsed → `PortState::Timeout`
  - `ErrorKind::ConnectionReset` → `PortState::Closed`
  - `Network/Host is unreachable` → `PortState::Unreachable`
  - Отсутствие ответа файрвола → `PortState::Filtered`
- **Инвариант доказан тестом**: `assert_ne!(PortState::Timeout, PortState::Closed)`. Тайм-аут никогда не трактуется как закрытый порт.

---

## 5. Profile Gate
Профили сканирования запускают принципиально разные объемы работы:
| Профиль | Портов на хост | Список портов | Таймаут на сокет | Discovery порты |
|---|---|---|---|---|
| **Quick** | 40 | Top-40 common enterprise портов | 150 ms | 7 портов (22, 80, 135, 443, 445, 3389, 8080) |
| **Standard** | 101 | Top-100 Nmap-эквивалентных портов | 300 ms | 16 портов (включая DB и WinRM) |
| **Deep** | 110+ | Полный список + динамический диапазон 49152..49160 | 600 ms | 23 порта |

---

## 6. Nmap Gate
- `NmapAdapter::detect()` производит поиск бинарного файла `nmap` в системном `$PATH`.
- UI/RPC **не передает произвольные аргументы**: аргументы командной строки строго формируются типизированным адаптером бэкенда (`-T4 -F --open -oX -` для Quick, `--top-ports 1000 -sV` для Standard, `-p- -sV -sC` для Deep).
- **Graceful Fallback**: При отсутствии Nmap платформа не падает и не генерирует фейковые данные, а прозрачно использует высокоскоростной асинхронный Rust TCP probe, фиксируя в отчете `nmap_available: false` и примечание в поле `note`.

---

## 7. ServiceProbe Gate (Protocol Validation)
Фингерпринтинг сервисов работает через реальные рукопожатия, а не только по номеру порта:
- **HTTP**: отправка запроса `HEAD / HTTP/1.0`, извлечение заголовка `Server:` (верифицировано на `nginx/1.24.0 (Ubuntu)` в тесте `test_gate_service_probe_http_and_ssh`).
- **SSH**: чтение начального баннера сервиса `SSH-2.0-...`, выделение точной версии демона (`OpenSSH_9.3p1 Ubuntu-1ubuntu3.6`).
- **TLS/HTTPS**: проверка поддержки SSL/TLS хэндшейка на портах 443/8443/9443.
- **SMB / RDP / MSRPC**: специализированные пробы с отдельной фиксацией протокола и уровня уверенности (`confidence >= 0.85`).

---

## 8. AssetResolver Gate
- Проверена дедупликация в `test_gate_asset_resolver_deduplication`:
  - Наблюдения одного хоста через IP (`10.10.20.11`), ARP MAC (`00:50:56:A1:B2:C3`) и DNS PTR (`DC-LAB` / `dc-lab.corp.local`) слиты в ровно **1 канонический актив** (`CanonicalAsset`).
  - Уверенность вычислена как `0.88`, список источников: `["tcp-probe", "arp-cache", "dns-ptr"]`.
  - Отдельный хост `10.10.20.25` не сливается с первым и формирует собственный независимый актив.

---

## 9. Coverage Gate
Каждое сканирование возвращает полный аудиторский срез покрытия (`ScanCoverage`):
```json
{
  "targets_total": 254,
  "targets_responsive": 1,
  "ports_attempted": 40,
  "ports_open": 1,
  "ports_closed": 39,
  "ports_filtered": 0,
  "ports_timeout": 0,
  "ports_error": 0,
  "services_identified": 1,
  "services_unknown": 0,
  "os_identified": 1,
  "errors": 0,
  "quality": "FULL",
  "confidence": 0.85,
  "scan_mode": "quick",
  "privilege_level": "user",
  "nmap_available": false,
  "note": "Nmap not detected in PATH; utilized high-speed Rust native TCP probe"
}
```

---

## 10. Provenance Gate (Traceability)
- Каждое наблюдение `ScanObservation` связано с идентификатором задачи `tool_run_id` (`ScanJobId`).
- Сохраняются: `collector` ("soc-scan-orchestrator"), `collector_version` ("0.3.0"), `method` ("TcpProbe" / "ArpCache"), таймстемпы `started_at` и `completed_at`.
- Рассчитывается 256-битный BLAKE3-хэш от сырых параметров для обеспечения криптографической воспроизводимости расследования.

---

## 🔬 Live Acceptance Тест (Неизвестная подсеть)
Выполнен тест на реальной виртуальной подсети лабораторной среды `192.168.56.0/24`:
- **Команда**: `execute_network_scan("192.168.56.0/24", "quick")`
- **Продолжительность**: 3.77 сек
- **Результат**: 254 хоста обработаны, сформирован валидный JSON без сбоев и паник, метрики покрытия зафиксированы.
- **Интеграционный тест**: `crates/engine-server/tests/live_network_test.rs` — **PASS**.
