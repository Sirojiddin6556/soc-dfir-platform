// Risk levels come from the engine's correlation (host_inspector.rs) in
// Russian; older snapshots used English. Both count as elevated from "high" up.
const ELEVATED = new Set(['ВЫСОКИЙ', 'КРИТИЧЕСКИЙ', 'HIGH', 'CRITICAL']);

export function isElevatedRisk(level) {
  return ELEVATED.has(String(level || '').toUpperCase());
}
