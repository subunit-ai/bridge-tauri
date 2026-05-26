/**
 * Access mode for Remote-Exec.
 *
 *   restricted (default) — only the read-only whitelist is allowed.
 *                          Safe default for customer machines.
 *   full                 — whitelist bypassed. Operators can run any
 *                          binary that exists on the system. Reserved
 *                          for trusted internal machines (TJ, Erik,
 *                          team workstations). cwd-under-HOME boundary
 *                          and audit log still apply.
 *
 * Mode is persisted in the bridge KV table and chosen during pair.
 * Default is restricted. To go full, the user must opt in explicitly
 * via the pair-UI toggle.
 */
import { kvGet, kvSet } from "../storage/db.ts";

export type AccessMode = "restricted" | "full";

const KEY = "exec.access_mode";

export function getAccessMode(): AccessMode {
  const stored = kvGet(KEY);
  return stored === "full" ? "full" : "restricted";
}

export function setAccessMode(mode: AccessMode): void {
  kvSet(KEY, mode === "full" ? "full" : "restricted");
}
