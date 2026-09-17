# 36. UI/UX Functional Specification v1.1 — Desktop Cockpit Contract

**Artifact ID**: `ART-36-UIUXSPEC`  
**Revision**: `r2`  
**Status**: `VERIFIED / BASELINE CONTRACT`  
**Target Platform**: Native Desktop Cockpit (`desktop-app.exe`, Tao + Wry)  
**Standard**: WCAG 2.1 AA Compliant, Color-Blind Safe (Shape Badges `NFR-UX-002`)

---

## 1. Information Architecture (13 Primary Sections)

```text
SOC/DFIR PLATFORM
├── 1. Home / Dashboard (Global posture, active cases, stats, investigation progress, recent findings)
├── 2. Cases (Case Overview, triage queue, metadata, case switcher, investigator notes)
├── 3. Infrastructure (Subnet discovery, network topology map, host cards, port/service scans)
├── 4. Asset Details (12-tab deep dive: Overview, Processes, Network, Services, Users, Persistence, SBOM, CVE)
├── 5. Investigation & Graph (Incident attack graph, clickable relation edges with epistemic proofs)
├── 6. Forensic Timeline (Multi-host chronological lanes, sub-ms scrubber, event zoom 1m..All)
├── 7. Evidence & Custody (5-tier pipeline: Artifact->Observation->Fact->Evidence->Finding, Merkle CoC)
├── 8. Software & CVE (Software inventory grid, EPSS, CISA KEV, contextual exploitation risk)
├── 9. MITRE ATT&CK (Enterprise matrix heatmap, tactic columns, technique cards with evidence count)
├── 10. Diagrams (Visual Intelligence: Kill Chain, Pyramid of Pain, Process Tree, Lateral Movement)
├── 11. Automation / DAG (Interactive execution graph, task states, resource permits, task inspector)
├── 12. CTF / Cyber Range (Scenario briefing, hypothesis submission, ground truth distance scorecard)
└── 13. Reports & Settings (Executive summary, technical annex, STIX2/JSON export, broker policies)
```

---

## 2. Core Workspace Layout Contract (`UI-CASE-002`)

The primary desktop work area enforces an immutable 3-pane structure with high-density forensic layouts:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [Case: INC-2026-001] [STANDARD] [00:34:17] [Search Ctrl+K] [+ Ingest] [Quick Scan]     │
├──────────────────┬──────────────────────────────────────────┬──────────────────────────┤
│ SIDEBAR (240px)  │ CANVAS (Center Flex, Virtualized)        │ INSPECTOR (360px)        │
│ • Home           │ Dynamic View Container:                  │ Context-sensitive panel: │
│ • Cases          │ • Dashboard / Metric Widgets             │ • Entity / Task / Edge   │
│ • Infrastructure │ • Network Topology Map (Interactive)     │ • Epistemic Proofs       │
│ • Asset Details  │ • Attack Graph / Kill Chain / Pyramid    │ • Supporting Evidence    │
│ • Investigation  │ • Multi-Lane Host Timeline               │ • Resource Permits       │
│ • Timeline       │ • Evidence Ingestion & Custody Table     │ • Contextual Action Bar  │
│ • Evidence       │ • Software & Correlated CVE Grid         │   [Corroborate]          │
│ • Software & CVE │ • MITRE ATT&CK Matrix Heatmap            │   [Disprove]             │
│ • MITRE ATT&CK   │ • Automation DAG Pipeline Visualizer     │   [Cancel Task]          │
│ • Diagrams       │ • Cyber Range Hypothesis Scorecard       │   [Open Evidence]        │
│ • Automation/DAG │                                          │   [Export STIX2]         │
│ • CTF / Range    │                                          │                          │
│ • Reports        │                                          │                          │
├──────────────────┴──────────────────────────────────────────┴──────────────────────────┤
│ Workflow: 27/41 completed │ 4 running │ 2 blocked │ Risk: HIGH │ CAS: 1.2 GB │ Engine: LOCAL │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Screen Specifications (All 13 Modules)

### 3.1 `UI-HOME-001`: Home / Dashboard
- **Header**: Active Case badge `INC-2026-001`, Global Risk Level `HIGH (8.4)`.
- **Key Metrics Grid**:
  - `Assets: 23` | `Findings: 8` | `Critical: 2` | `Evidence: 97` | `CVE: 31` | `ATT&CK Techniques: 9`.
- **Investigation Progress**: Radial/Horizontal Gauge (`76% Resolved`).
- **Recent Findings Feed**:
  1. `PowerShell Execution (Encoded Command)` — WS-01 — CRITICAL
  2. `Scheduled Task Persistence (SecurityAuditCollector)` — DC-01 — HIGH
  3. `C2 Outbound Beaconing (198.51.100.44:443)` — WS-01 — HIGH
  4. `Credential Access (LSASS Memory Read)` — DC-01 — CRITICAL
- **Attack Progression Strip**: `Initial Access` ➔ `Execution` ➔ `Persistence` ➔ `C2` ➔ `[Exfiltration ?]`.

### 3.2 `UI-CASE-001`: Cases Overview & Triage
- **Left Panel**: Active case filter (`Open`, `Under Investigation`, `Closed`, `Archived`).
- **Center Canvas**: Case triage table (Case ID, Title, Severity, Lead Analyst, Assigned Assets, Ingested MB, SLA Timer).
- **Actions**: `[Create New Case]`, `[Switch Case]`, `[Archive Case]`, `[Export Case Package]`.
- **Inspector**: Case metadata, incident responders list, chain of custody summary, hash sealed timestamp.

### 3.3 `UI-INFRA-001`: Infrastructure & Network Topology
- **Top Toolbar**:
  - Actions: `[Quick Discover]`, `[Standard Scan]`, `[Deep Scan]`, `[Remote Service Scan]`.
  - Search: `Search host (IP, Hostname, MAC)...`.
  - Filters: OS (`Windows`, `Linux`, `Embedded`), Risk (`Critical`, `High`, `Med`, `Low`), Status (`Online`, `Offline`).
  - Metrics Strip: `Hosts: 23` | `Online: 19` | `Unknown: 4` | `Critical: 2`.
- **Center Canvas**: Hierarchical / Force-Directed Network Topology:
  ```text
                           INTERNET
                              │
                              ▼
                        ┌──────────┐
                        │  FW-01   │
                        └────┬─────┘
                             │
               ┌─────────────┼──────────────┐
               ▼             ▼              ▼
          ┌────────┐    ┌────────┐     ┌────────┐
          │ DC-01  │    │ WEB-01 │     │ WS-01  │
          │10.0.0.5│    │10.0.0.8│     │10.0.0.21
          └────────┘    └────────┘     └────────┘
  ```
- **Interaction**: Clicking any host selects it in the right inspector and allows direct jumping to `Asset Details`.

### 3.4 `UI-ASSET-001`: Asset Details (12 Forensic Tabs)
- **Header**: `DC01.CORP.LOCAL` | `192.168.1.10` | `Windows Server 2022 Datacenter` | Risk: `HIGH` | State: `INVESTIGATING`.
- **12 Granular Sub-Tabs**:
  1. **Overview**: Host role (`Domain Controller`), OS build (`20348`), Open ports (`53, 88, 135, 389, 445, 636`), Critical CVEs (`3`), Findings (`7`), Linked Evidence (`29`).
  2. **Processes**: Snapshot tree (PID, PPID, Image path, User context, CLI args, BLAKE3 dual hash).
  3. **Network**: Interface list, MTU, listening sockets, active connections, routing table.
  4. **Services**: Active background daemons/services, startup mode, service account.
  5. **Persistence**: Registry Run keys, Scheduled tasks, Linux systemd timers, Cron entries.
  6. **Software**: SBOM CycloneDX table, vendors, package versions, CPE 2.3 identifiers.
  7. **Vulnerabilities**: Correlated CVE list, CVSS v3.1, EPSS %, CISA KEV exploitation flags.
  8. **Users**: Local/domain user accounts, SID/UID, administrator groups, last logon.
  9. **Firewall**: Profiles (Domain/Private/Public), active rules, dropped connection counters.
  10. **Filesystem**: Critical directory audit, hash verification status, modified system files.
  11. **Logs**: Local security log stream filtered specifically to this host.
  12. **Evidence**: Cryptographic artifacts stored in CAS originating from this asset.

### 3.5 `UI-INV-001`: Investigation & Attack Graph
- **Center Canvas**: Interactive Attack Provenance Graph:
  ```text
               phishing.docx
                    │
                 opened
                    │
                    ▼
                WINWORD
                    │
                  spawned
                    │
                    ▼
               PowerShell
               /         \
          downloaded    connected
             │             │
             ▼             ▼
        payload.exe   evil.example
             │
        persistence
             │
             ▼
        Scheduled Task
  ```
- **Edge Inspector Contract**: Every arrow/edge answers: *"Why does the system believe this relationship exists?"*
  - `Relation`: `spawned` | `Confidence`: `0.99`
  - `Supported by`: Sysmon Event 1, EVTX Security 4688, PID ancestry match
  - `First Seen`: `10:32:44 UTC`
  - `Actions`: `[Open Evidence]`, `[Open Timeline]`, `[Corroborate]`, `[Disprove]`.

### 3.6 `UI-TIME-001`: Forensic Timeline
- **Multi-Host Lanes Layout**:
  ```text
  TIME       WS-01                DC-01            WEB-01
  ──────────────────────────────────────────────────────────
  10:31      Email received
  10:32      WINWORD started
             PowerShell started
  10:33      payload.exe
  10:35      Scheduled Task
  10:41                           Authentication
  10:42                           SMB session
  10:50                                            HTTPS
  ```
- **Controls**: Zoom presets (`1m` | `5m` | `30m` | `1h` | `All`), Sub-ms scrubber, Bookmark epoch, Filter by severity.

### 3.7 `UI-EVID-001`: Evidence & Merkle Chain of Custody
- **5-Stage Evidentiary Progression Pipeline**:
  `Artifact (Raw)` ➔ `Observation (Parsed)` ➔ `Fact (Correlated)` ➔ `Evidence (Verified)` ➔ `Finding (Actionable)`.
- **Artifacts Ledger**:
  - File name, Size, Source host, Ingestion timestamp, Parser adapter, BLAKE3 path key, SHA-256 hash.
- **Merkle Chain of Custody**: Cryptographically sealed log verifying block hashes and immutability.
- **Inspector**: Hex preview, raw header parsing, signature validation, export sealed copy.

### 3.8 `UI-VULN-001`: Software & CVE Inventory
- **Table Columns**: `HOST` | `PRODUCT` | `VERSION` | `CVE` | `CVSS` | `EPSS` | `KEV`.
- **Contextual CVE Inspector**:
  - `CVE ID`: e.g. `CVE-2023-36884` (CVSS `8.3`, EPSS `82%`, KEV: `YES`).
  - `Installed Asset`: `WS-01` | `Package Source`: `Office 365 Click-to-Run`.
  - `Internet Exposed`: `YES` | `Evidence of Active Exploitation`: `DETECTED (Process: powershell.exe)`.
  - `Contextual Risk Score`: `CRITICAL`.

### 3.9 `UI-MITRE-001`: MITRE ATT&CK Matrix Navigator
- **Enterprise Tactic Columns**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact.
- **Technique Cards**:
  - `T1566 Phishing` (CONFIRMED, 4 Evidence items)
  - `T1059.001 PowerShell` (CONFIRMED, 7 Evidence items)
  - `T1053 Scheduled Task` (CORROBORATED, 3 Evidence items)
  - `T1003.001 LSASS Memory` (CONFIRMED, 6 Evidence items)
- **Technique Inspector**:
  - Affected assets list (`WS-01`, `DC-01`), Involved processes (`powershell.exe`), Detection confidence (`96%`), Quick links: `[Open Graph]`, `[Open Evidence]`, `[Open Timeline]`.

### 3.10 `UI-DIAG-001`: Visual Intelligence (Diagrams)
Replaces generic architecture diagrams with incident-specific cyber visual models:
1. **Attack Graph**: Full causality and credential pivoting topology.
2. **Infrastructure Map**: Physical and logical network segmentation view.
3. **Cyber Kill Chain**: Stage-by-stage progression:
   - `Delivery (✓)` ➔ `Exploitation (✓)` ➔ `Installation (✓)` ➔ `Command & Control (✓)` ➔ `Actions on Objectives (?)`.
4. **Pyramid of Pain**: Visual tiered pyramid with clickable depth layers:
   - Level 6: `TTPs (3)`
   - Level 5: `Tools (2)`
   - Level 4: `Host/Network Artifacts (9)`
   - Level 3: `Domain Names (4)`
   - Level 2: `IP Addresses (7)`
   - Level 1: `Cryptographic Hashes (12)`
5. **Process Tree**: Hierarchical parent-child visualization.
6. **Lateral Movement**: Auth hops (Kerberos tickets, SMB sessions, WMI invocations).

### 3.11 `UI-DAG-001`: Automation & Workflow DAG
- **Profile Selector**: `[Quick]` | `[Standard]` | `[Deep]` | `[Custom]`.
- **Status Header**: `Workflow: Standard Investigation` | `Status: RUNNING` | `Progress: 27 / 41`.
- **DAG Execution Canvas**:
  ```text
          ┌───────────────┐
          │ Host Discovery│ [✓ SUCCEEDED]
          └───────┬───────┘
                  │
          ┌───────▼────────┐
          │ OS Detection   │ [✓ SUCCEEDED]
          └───────┬────────┘
             ┌────┴────┐
             │         │
        ┌────▼───┐ ┌───▼─────┐
        │Windows │ │ Linux    │
        │Collect │ │ Collect  │
        └────┬───┘ └───┬─────┘
             │         │
             └────┬────┘
                  ▼
          Software Discovery [▶ RUNNING]
                  │
                  ▼
                SBOM         [○ PENDING]
                  │
                  ▼
              CVE Scan       [○ PENDING]
                  │
                  ▼
              Correlation    [■ BLOCKED]
  ```
- **State Badges**: `✓ SUCCEEDED` (Green), `▶ RUNNING` (Blue), `○ PENDING` (Gray), `⊘ SKIPPED` (Muted), `! FAILED` (Red), `■ BLOCKED` (Orange).
- **Task Inspector**:
  - `Task`: `Software Discovery` | `Status`: `RUNNING` | `Target`: `WEB-01` | `Tool`: `Syft`.
  - `Started`: `16:21:44` | `Duration`: `00:01:37`.
  - `Dependencies`: `✓ Host Discovery`, `✓ OS Detection`.
  - `Resource Permits`: CPU: `1/4`, IO: `1/4`, NET: `0/6`, FORENSIC: `0/1`.
  - `Actions`: `[Cancel Task]`, `[Open Logs]`, `[View Output]`.

### 3.12 `UI-CTF-001`: CTF / Cyber Range Cockpit
- **Briefing Panel**: Active scenario background, target network rules, flags criteria.
- **Hypothesis Form**: Technique submission input (e.g. `T1003.001`), root-cause explanation, involved assets.
- **Automated Scorecard**:
  - Evaluates distance to sealed ground truth without leaking unrevealed scenario secrets.
  - Returns: Score (0–100), Detection Speed score, Precision score, Explanatory forensic feedback.

### 3.13 `UI-REP-001`: Incident Reports & Export
- **Export Formats**: Executive Summary (PDF/HTML), Technical Annex (Markdown), MITRE ATT&CK Layer (JSON), STIX 2.1 Bundle.
- **Settings**: Tool binary paths (`nmap`, `tshark`, `syft`), PrivilegeBroker permissions, local CAS retention.

---

## 4. Global Keyboard Shortcuts

| Shortcut | Action | Scope |
|:---|:---|:---|
| `Ctrl + K` / `Cmd + K` | Omni-Search & Command Palette | Global |
| `Ctrl + 1` .. `Ctrl + 8` | Switch Primary Navigation Views | Global |
| `Space` | Toggle Fullscreen Canvas (Fold Sidebar & Inspector) | Canvas |
| `Escape` | Clear Active Selection / Reset Filters | Global |
| `Ctrl + F` | Search within active table / graph / timeline | Active View |
| `Ctrl + E` | Ingest Evidence Dialog | Global |
| `Ctrl + P` | Export Case Report | Global |

---

## 5. Acceptance Criteria
1. **3-Pane Integrity**: Sidebar, Canvas, and Inspector maintain strict proportional layout across all 13 views.
2. **Contextual Inspector**: Inspector must switch dynamically between Host, Process, Relation Edge, CVE, and DAG Task contexts.
3. **Epistemic Explainability**: All graph relations and attack detections must present verification confidence and supporting evidence.
4. **Sovereign Local Operation**: Zero external network or cloud dependencies; all fonts, icons, styles, and engines execute locally.
