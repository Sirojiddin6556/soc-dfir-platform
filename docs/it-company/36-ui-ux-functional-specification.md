# 36. UI/UX Functional Specification v1.0 — Desktop Cockpit Contract

**Artifact ID**: `ART-36-UIUXSPEC`  
**Revision**: `r1`  
**Status**: `VERIFIED / BASELINE CONTRACT`  
**Target Platform**: Native Desktop Cockpit (`desktop-app.exe`, Tao + Wry)  
**Standard**: WCAG 2.1 AA Compliant, Color-Blind Safe (Shape Badges `NFR-UX-002`)

---

## 1. Information Architecture (13 Primary Sections)

```text
SOC/DFIR PLATFORM
├── 1. Home / Dashboard (Global posture, active cases, triage queue, system health)
├── 2. Cases (Case Overview, Case Workspace [Header + 3-Pane Cockpit + Workflow Footer])
├── 3. Infrastructure (Discovery, Asset Inventory, Network Topology Map, Asset Details)
├── 4. Investigation (Findings, Attack Graph [LoD], Process Tree, Epistemic Hypotheses)
├── 5. Timeline (Multi-host chronological lanes, sub-ms scrubber, event zoom)
├── 6. Evidence (Evidence Board, Dual-Hash Artifacts, Merkle Chain of Custody)
├── 7. Software & Vulnerabilities (Software Inventory, SBOM CycloneDX, CVE, Exploitation Risk)
├── 8. Threat Frameworks (MITRE ATT&CK Matrix, Cyber Kill Chain, Pyramid of Pain)
├── 9. Diagrams (C4 Architecture, Attack Dataflow, Network Segmentation)
├── 10. Automation (Workflow DAG, Task Queue, Tool Adapters, Scan Profiles)
├── 11. CTF / Cyber Range (Scenario Pack, Challenges, Ground Truth Verifier, Scorecard)
├── 12. Reports (Executive Summary, Technical Annex, Containment Playbooks, Export)
└── 13. Settings (General, Tool Paths, ATT&CK Versions, Broker Security, CAS Storage)
```

---

## 2. Core Workspace Layout Contract (`UI-CASE-002`)

The primary desktop work area enforces an immutable 3-pane structure with high-density forensic layouts:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [Case: INC-2026-001] [Severity: HIGH] [Profile: DEEP] [Time: 00:34:17] [Search Ctrl+K] │
├──────────────────┬──────────────────────────────────────────┬──────────────────────────┤
│ SIDEBAR (240px)  │ CANVAS (Center Flex, Virtualized)        │ INSPECTOR (360px)        │
│ • Home           │ [Tab: Infrastructure / Graph / Timeline] │ [Selected Entity Details]│
│ • Cases          │ • Graph Canvas (WebGL / Canvas2D)        │ • Identity (UUID, Name)  │
│ • Infrastructure │ • Network Map / Asset Grid               │ • Epistemic Classification│
│ • Investigation  │ • Event Grid (Virtual Scroll 100k+)      │ • Forensic Evidence Links│
│ • Timeline       │ • MITRE Matrix Heatmap                   │ • Relationships & Edges  │
│ • Evidence       │ • Cyber Range Scenario Board             │ • Contextual Action Bar  │
│ • ATT&CK         │                                          │   [Quick Inspect]        │
│ • Automation     │                                          │   [Isolate Host]         │
│ • Reports        │                                          │   [Export JSON/STIX2]    │
├──────────────────┴──────────────────────────────────────────┴──────────────────────────┤
│ Workflow: 27/41 completed │ 4 running │ 2 blocked │ Memory CAS: 1.2 GB │ Mode: OFFLINE │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Screen Specification Schema & Functional Definitions

### 3.1 `UI-INFRA-001`: Infrastructure Discovery
- **Purpose**: Network reconnaissance, host discovery, subnet enumeration, and port profiling.
- **Route ID**: `infra.discovery`
- **Layout**: 3-pane split (Left: Subnet tree; Center: Topology canvas & host cards; Right: Selected host inspector).
- **Top Actions**: `[Quick Scan (ARP/Ping)]`, `[Standard Scan (TCP Top 1000)]`, `[Deep Scan (Full + OS)]`, `[Stop Scan]`, `[Export Topology]`.
- **Center Canvas**: Interactive force-directed network graph with subnet boundary grouping.
- **IPC Methods**: `infra.discover_subnets`, `infra.scan_start`, `infra.scan_stop`, `infra.get_hosts`.
- **States**: `Empty` (No targets configured), `Scanning` (Real-time progress gauge), `Ready`, `Error` (Broker permission denied).

### 3.2 `UI-INFRA-004`: Asset Details Specification
Every discovered or imported asset provides a 12-tab granular forensic breakdown:
1. **Overview**: Hostname, Primary IP, MAC, OS version, Kernel build, Criticality tier, Investigation tag, Risk score.
2. **Network**: Interface list (MTU, speed), routing table, ARP neighbors, listening sockets, active connections.
3. **Processes**: Full process tree (PID, PPID, session, user, CLI arguments, binary path, dual hashes BLAKE3/SHA256).
4. **Services**: Service name, display label, binary path, startup mode, running state, execution account.
5. **Persistence**: Windows Registry Run keys, Scheduled Tasks, Linux systemd timers, Cron entries, Startup folder.
6. **Software & SBOM**: Installed applications, package versions, vendors, CPE v2.3, PURL, detection source.
7. **Vulnerabilities**: Correlated CVEs, CVSS v3.1 base score, EPSS probability, known exploitation status (KEV).
8. **Users & Groups**: Local accounts, security identifiers (SID/UID), privilege groups, last login timestamp.
9. **Firewall**: Active profiles (Domain, Private, Public), inbound/outbound rules, default actions.
10. **Filesystem**: Monitored system directories, critical executables, hash integrity status.
11. **Logs & Events**: Filtered security log slice pertaining strictly to this asset.
12. **Evidence**: Linked forensic artifacts (PCAP slices, EVTX dumps, memory dumps) in CAS.
- **Action Bar**: `[Quick Inspect]`, `[Deep Inspect]`, `[Collect Logs]`, `[Capture Traffic]`, `[Inspect Persistence]`, `[Generate SBOM]`, `[Scan CVE]`, `[Open Attack Graph]`, `[Open Timeline]`.

### 3.3 `UI-INV-002`: Attack Graph
- **Purpose**: Deterministic graph representation of adversary actions, impacted nodes, and credential pivot edges.
- **Route ID**: `investigation.graph`
- **Canvas Features**: Level-of-Detail (LoD) aggregation (50+ child processes grouped into clustered nodes).
- **Node Badges**: Mandatory shape encoding (Circle = Host, Diamond = Process, Square = File, Hexagon = TTP, Octagon = Indicator).
- **Inspector Data**: Supported-by facts list, verification confidence (0.00–1.00), pain level, MITRE technique ID.
- **Actions**: `[Expand Neighbors]`, `[Collapse Cluster]`, `[Highlight Kill Chain]`, `[Add Hypothesis]`, `[Export PNG/SVG]`.
- **IPC Methods**: `graph.query`, `graph.filter`, `graph.export`.

### 3.4 `UI-TIME-001`: Multi-Lane Timeline
- **Purpose**: Microsecond-accurate chronological incident reconstruction across multiple hosts.
- **Route ID**: `timeline.view`
- **Lanes**: System Host Lanes, Network Flow Lane, Security Event Lane, Analyst Annotations Lane.
- **Controls**: Zoom slider (Days -> Hours -> Minutes -> Seconds -> Milliseconds), Pin Event, Bookmark Epoch.
- **Virtualization**: Windowed rendering maintaining fixed 60 FPS DOM for 1,000,000+ observations.
- **IPC Methods**: `timeline.query_slice`, `timeline.add_annotation`.

### 3.5 `UI-EVID-001`: Evidence Board & Chain of Custody
- **Purpose**: Cryptographic custody tracking and dual-hash artifact inspection.
- **Route ID**: `evidence.board`
- **Columns**: Artifact Name, Ingest Timestamp, Source Host, File Size, BLAKE3 Path Key, SHA-256 Forensic Hash, Custody Signatures.
- **Chain of Custody Table**: Merkle-linked event log (`ArtifactIngested`, `Normalized`, `Correlated`, `Exported`).
- **Actions**: `[Ingest Artifact (EVTX/PCAP)]`, `[Verify Integrity]`, `[Download Sealed Copy]`, `[View Hex Dump]`.

### 3.6 `UI-TAX-001`: MITRE ATT&CK Matrix Navigator
- **Purpose**: Interactive heat-mapping of detected tactics and techniques against MITRE Enterprise ATT&CK v14.1.
- **Columns**: 14 Enterprise Tactics (Initial Access through Impact).
- **Cells**: Techniques color-coded by detection confidence (Gray = Unobserved, Yellow = Candidate, Red = Confirmed).
- **Overlay Toggles**: Sub-technique expansion, Cyber Kill Chain mapping, Pyramid of Pain categorization.
- **Actions**: `[Filter Graph by Technique]`, `[Export Coverage Layer (Navigator JSON)]`.

### 3.7 `UI-CTF-001`: Cyber Range & Scenario Evaluation
- **Purpose**: Educational training mode evaluating analyst findings against sealed scenario baselines.
- **Route ID**: `ctf.scenario`
- **Panels**:
  - Scenario Mission Briefing (Target network, objective, rules of engagement).
  - Hypothesis Submission Form (Root cause, entry vector, affected assets, MITRE technique).
  - Ground Truth Scorecard (Automated distance verification without answer leakage).
  - Score Breakdown: Detection speed (25%), Attribution precision (35%), Remediation validity (40%).
- **IPC Methods**: `scenario.list`, `scenario.load`, `scenario.evaluate`.

---

## 4. Primary User Workflows (End-to-End Traces)

### Workflow 1: End-to-End Incident Investigation Flow
```text
[Dashboard] ──> Create Case ("INC-2026-001")
                   │
                   ▼
[Evidence] ────> Ingest Binary EVTX / PCAP into CAS (Dual-Hash verified)
                   │
                   ▼
[Automation] ──> Trigger Normalizer & Correlation Engine (DAG Scheduler)
                   │
                   ▼
[Investigation]> Correlation generates High-Severity Fact (LSASS Memory Read)
                   │
                   ▼
[Attack Graph] > Visual pivot from Alert -> Process (powershell.exe) -> Target (lsass.exe)
                   │
                   ▼
[Asset Details]> Inspect DC01 Persistence & Active Sockets (Confirm Lateral Movement)
                   │
                   ▼
[Timeline] ────> Corroborate egress beaconing in Network Lane (Port 443)
                   │
                   ▼
[MITRE Matrix] > Map to T1003.001 (OS Credential Dumping: LSASS)
                   │
                   ▼
[Reports] ─────> Generate Incident Summary & Containment Action Plan (JSON/HTML)
```

### Workflow 2: Active Infrastructure Discovery & Triage Flow
```text
[Infrastructure Discovery] ──> Select Subnet ("192.168.1.0/24") ──> Click [Standard Scan]
                                      │
                                      ▼
[Workflow Footer] ───────────> PrivilegeBroker executes typed network probe
                                      │
                                      ▼
[Network Map Canvas] ────────> 14 Hosts plotted with open ports & OS fingerprint badges
                                      │
                                      ▼
[Asset Inspector] ───────────> Click Anomaly (Unknown SSH on non-standard port 2222)
                                      │
                                      ▼
[Action Bar] ────────────────> Click [Deep Inspect] ──> Initiates process & socket harvest
```

---

## 5. Global Keyboard Shortcuts Contract

| Shortcut | Action | Scope |
|:---|:---|:---|
| `Ctrl + K` / `Cmd + K` | Open Quick Command Palette / Omni-Search | Global |
| `Ctrl + 1` .. `Ctrl + 8` | Switch Primary Navigation Views (1:Dash, 2:Cases, 3:Infra, etc.) | Global |
| `Ctrl + N` | Create New Investigation Case | Global |
| `Space` | Toggle Fullscreen Canvas (Hide Sidebar & Inspector) | Canvas |
| `Escape` | Clear Selection / Deselect Active Node | Global |
| `Ctrl + F` | Filter items within active table or graph | Active View |
| `Ctrl + E` | Open Evidence Ingestion Dialog | Global |
| `Ctrl + P` | Export Current View / Generate Case Report | Global |

---

## 6. Acceptance Criteria for UI Implementation
1. **Zero Layout Drift**: 3-pane cockpit structure must remain intact across all primary views.
2. **Deterministic State Feedback**: Every view must visibly report `Loading`, `Empty`, `Ready`, or `Error` state.
3. **Accessibility**: Every status indicator and graph node must combine color with distinctive geometric shapes (`Circle`, `Square`, `Diamond`, `Hexagon`, `Octagon`) and textual badges.
4. **Offline Local Sovereignty**: Zero network requests to external CDNs or remote APIs; all scripts, fonts, and stylesheets must be self-contained within `apps/desktop-ui`.
