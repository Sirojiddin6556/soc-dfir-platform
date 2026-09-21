# Solution & Implementation Architecture
## Stage 4 / Release v0.3: Reliable Network Discovery

### 1. Архитектурный срез
В Cargo Workspace выделен специализированный доменный крейт:
`crates/scan-engine/`

```text
                     SCAN ORCHESTRATOR
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
          Discovery      Services       Host Inspect
        (ARP + TCP)   (Port Scanner)  (Service Probes)
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                      Observations
                            │
                            ▼
                     Coverage Report
```

### 2. Реализованные компоненты
1. **Target & CIDR Parsing (`target.rs`)**:
   - `parse_target`: поддержка Single IP, CIDR (/16.../32), Range (`IP-IP`), Hostname.
   - `expand_target_to_ips`: разворачивание в массив IP-адресов с защитой от OOM (лимит 65536 хостов).
2. **Host Discovery (`discovery.rs`)**:
   - `read_arp_table()`: прямое чтение и парсинг ARP-кэша Windows (`arp -a`) и Linux (`/proc/net/arp`).
   - `tcp_ping_hosts()`: TCP probe на общие порты для обнаружения хостов с закрытым ICMP.
   - Loopback / Localhost корректно поддерживается без эмуляции.
3. **Port Scanner & Error Classification (`port_scan.rs`)**:
   - Профили портов: `Quick` (top-40), `Standard` (top-100), `Deep` (расширенный список).
   - Асинхронный пул через `tokio::sync::Semaphore(64)`.
   - Семантически верное разделение состояний: `Open`, `Closed` (RST/ACK), `Timeout` (`timeout != closed`), `Filtered`, `Unreachable`.
4. **Service Fingerprinting (`service_probe.rs`)**:
   - `ServiceProbe` trait: `SshProbe` (парсинг `SSH-2.0-...`), `HttpProbe` (запрос `HEAD /`, парсинг заголовка `Server:`), `TlsProbe`, `SmbProbe`, `RdpProbe`, `GenericProbe`.
5. **Asset Resolver (`asset_resolver.rs`)**:
   - Канонизация и дедупликация хостов по IP, MAC, Hostname, FQDN и сертификатам.
6. **Scan Coverage Report (`coverage.rs`)**:
   - Метрики: `targets_total`, `targets_responsive`, `tcp_ports_attempted`, `tcp_ports_open`, `tcp_ports_closed`, `tcp_ports_filtered`, `tcp_ports_timeout`, `services_identified`, `services_unknown`, `os_identified`, `errors`, `quality` (`Full`/`Partial`/`Degraded`), `confidence`, `privilege_level`, `nmap_available`, `note`.
7. **Nmap Adapter (`nmap_adapter.rs`)**:
   - Автодетект Nmap в PATH. Строго типизированные аргументы (UI не передает произвольный CLI).
8. **Scan Orchestrator (`orchestrator.rs`)**:
   - Полный сквозной цикл выполнения сканирования.
   - Генерация криптографически подписанных `ScanObservation` с BLAKE3-хэшем для верифицируемости.

### 3. Reality Check Verification (Gate 2 Acceptance)
- `cargo check --workspace` — **PASS** (0 errors)
- `cargo fmt --all -- --check` — **PASS** (100% formatted)
- `cargo clippy --workspace --all-targets -- -D warnings` — **PASS** (0 warnings)
- `cargo test --workspace` — **PASS** (все тесты во всех 23 крейтах зеленые)
- `LIVE Mode` — 0 synthetic CVE, 0 demo-hardcoded CVE (все тестовые данные изолированы в `tests/fixtures/`)
