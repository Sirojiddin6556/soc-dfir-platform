# Role 20: Frontend State & API Integrator — Implementation Report

## 1. Executive Summary & Ownership
- **Role**: PRF-20-FESTATE (Frontend State & API Integrator)
- **Artifact ID**: ART-20-FESTATE
- **Revision**: r1
- **Status**: VERIFIED
- **Requires**: ART-19-FECOMP (r1), ART-11-BEAPI (r1)
- **Produces**: `apps/desktop-ui/js/ipc.js`, unified frontend state management, JSON-RPC 2.0 transport client, and RFC 7807 error handling.

---

## 2. IPC Protocol Client Implementation (`apps/desktop-ui/js/ipc.js`)

The `IpcClient` provides seamless communication with the backend engine:
- **Request Format**: Compliant with JSON-RPC 2.0 / `IpcRequest`:
  ```json
  {
    "api_version": 1,
    "request_id": "req_xyz",
    "method": "cases.list",
    "params": {}
  }
  ```
- **Error Handling**: Catches RFC 7807 Problem Details (`status`, `title`, `detail`, `invalid_params`) and translates them into user-actionable notifications.
- **Offline / Standalone Resilience**: Features deterministic local fallback dispatch when connecting in isolated air-gapped demo environments.

---

## 3. State Management
- `activeTab`: Coordinates active tab view switching.
- `selectedEntity`: Coordinates inspection between the Attack Graph Canvas, Timeline, and Right Inspector Pane.
- `hypothesisVerification`: Dispatches user hypotheses to the verification engine and displays confidence/score outcomes.
