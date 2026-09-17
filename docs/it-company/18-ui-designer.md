# 18. UI Design System & Component Kit: Blue Team Cyber Range & SOC/DFIR Platform

**Profile ID**: `PRF-18-UI`  
**Status**: `COMPLETED`  
**Input**: `docs/it-company/17-ux-designer.md`

---

## 1. Color Palette & Dark Cyber Theme

- **Background Canvas**: `#0d1117` (Deep Slate / Pitch Black)
- **Card & Pane Surface**: `#161b22` (Subtle Charcoal)
- **Border & Separators**: `#30363d` (Muted Gray)
- **Typography Primary**: `#f0f6fc` (High Contrast White)
- **Typography Muted**: `#8b949e` (Secondary Gray)
- **Accents & Semantics**:
  - Critical / Threat: `#f85149` (Vibrant Coral)
  - Warning / Suspicious: `#d29922` (Warm Amber)
  - Fact / Confirmed: `#2ea043` (Emerald Green)
  - Info / Process: `#58a6ff` (Sky Blue)
  - Network / Socket: `#bc8cff` (Purple)

---

## 2. Accessibility & Shape Encoding (NFR-UX-002 / WCAG AA)

In compliance with technical specification NFR-UX-002, no state or entity type is communicated solely by color:

| Entity Type | Shape Geometry | Text Badge | Color Accent |
|---|---|---|---|
| **Host / Machine** | Circle `●` | `[HOST]` | Blue `#58a6ff` |
| **Process** | Hexagon `⬡` | `[PROC]` | Green `#2ea043` |
| **Network Socket** | Diamond `◆` | `[NET]` | Purple `#bc8cff` |
| **User Account** | Square `■` | `[USER]` | Cyan `#39c5bb` |
| **Threat / Tactic** | Octagon `🛑` | `[ATT&CK]` | Red `#f85149` |
| **File / Artifact** | Folded Sheet `📄` | `[FILE]` | Orange `#e3b341` |

---

## 3. Typography & Spacing
- **Interface Font**: System UI / Inter (`12px`, `14px`, `16px`)
- **Forensic / Code Font**: `JetBrains Mono` / `Consolas` (`11px`, `13px`) for hashes, timestamps, JSON, and network IPs.
- **Elevation**: Flat with 1px border highlights; no glossy or heavy shadows to preserve maximum data density.
