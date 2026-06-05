/**
 * Forge Remote-Control — ruft das gebündelte `forge-control`-CLI per Subprozess auf:
 *   capture → Screenshot (base64-PNG),  act → Input-Aktion (Maus/Tastatur).
 *
 * BEWUSST OHNE Auth/Policy: diese Schicht sind nur die „Hände". Approval (Ed25519),
 * Consent/Session-Grant, Scope `forge:control` und der Kill-Switch werden vom WS-Handler
 * (sync/ws-client.ts) DAVOR erzwungen — genau wie beim Remote-Exec-Runner.
 *
 * Privacy: das Audit-Log enthält NIE getippten Klartext oder Clipboard-Inhalte — bei
 * `type` nur die Zeichenlänge. Screenshots werden nicht persistiert.
 */
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve as resolvePath } from "node:path";

const AUDIT_PATH = resolvePath(homedir(), ".config/subunit-bridge/forge-audit.jsonl");
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_PNG_BYTES = 12_000_000; // ~12 MB Schutz gegen Riesen-Screenshots.

export type CaptureResult = { ok: true; pngBase64: string } | { ok: false; reason: string };
export type ActResult = { ok: true } | { ok: false; reason: string };

/** Pfad zum forge-control-Binary: Env > neben der Bridge (Sidecar) > Dev-Fallback (cargo target). */
function forgeControlBin(): string {
  const fromEnv = process.env.FORGE_CONTROL_BIN;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const exe = process.platform === "win32" ? "forge-control.exe" : "forge-control";
  const sidecar = join(dirname(process.execPath), exe);
  if (existsSync(sidecar)) return sidecar;
  // Dev-Fallback (lokales Repo) — in Prod liegt das Binary als Sidecar neben der Bridge.
  return resolvePath(homedir(), "subunit/unitone/workspace/projects/forge-control/target/release/forge-control");
}

function writeAudit(entry: Record<string, unknown>): void {
  try {
    mkdirSync(dirname(AUDIT_PATH), { recursive: true });
    appendFileSync(AUDIT_PATH, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
  } catch (err) {
    console.warn("[forge] audit write failed:", err);
  }
}

/** Aktions-Zusammenfassung fürs Audit OHNE sensible Inhalte (kein getippter Text/Clipboard). */
function safeActionSummary(json: string): Record<string, unknown> {
  try {
    const a = JSON.parse(json) as Record<string, unknown>;
    const s: Record<string, unknown> = { type: a.type };
    if (typeof a.x === "number") s.x = a.x;
    if (typeof a.y === "number") s.y = a.y;
    if (typeof a.combo === "string") s.combo = a.combo; // Tastenkombi = kein Inhalt, ok
    if (a.type === "type" && typeof a.text === "string") s.text_len = a.text.length; // NUR Länge
    return s;
  } catch {
    return { type: "unparseable" };
  }
}

// Aktive forge-control-Subprozesse — für den Kill-Switch: Revoke/Logout killt laufende Aktionen.
const activeForgeChildren = new Set<ReturnType<typeof spawn>>();

/** Killt alle laufenden forge-control-Subprozesse (Hard-Stop bei Revoke/Logout). */
export function killActiveForgeChildren(reason = "remote_access_revoked"): void {
  const kids = Array.from(activeForgeChildren);
  for (const child of kids) {
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignored */
    }
  }
  activeForgeChildren.clear();
  if (kids.length > 0) {
    console.warn(`[forge] killed ${kids.length} active forge-control child(ren): ${reason}`);
  }
}

/** Screenshot des primären Monitors als base64-PNG. */
export async function forgeCapture(): Promise<CaptureResult> {
  return new Promise((resolve) => {
    const child = spawn(forgeControlBin(), ["capture"], { stdio: ["ignore", "pipe", "pipe"] });
    activeForgeChildren.add(child);
    let out = "";
    let err = "";
    let tooBig = false;
    const killer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignored */
      }
    }, DEFAULT_TIMEOUT_MS);
    child.stdout.setEncoding("utf-8");
    child.stdout.on("data", (d: string) => {
      out += d;
      if (out.length > MAX_PNG_BYTES) {
        tooBig = true;
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignored */
        }
      }
    });
    child.stderr.setEncoding("utf-8");
    child.stderr.on("data", (d: string) => {
      err += d;
    });
    child.on("error", (e) => {
      clearTimeout(killer);
      activeForgeChildren.delete(child);
      writeAudit({ action: "capture", ok: false, error: String(e) });
      resolve({ ok: false, reason: String(e) });
    });
    child.on("close", (code) => {
      clearTimeout(killer);
      activeForgeChildren.delete(child);
      if (tooBig) {
        writeAudit({ action: "capture", ok: false, reason: "png_too_large" });
        resolve({ ok: false, reason: "screenshot too large" });
        return;
      }
      const ok = code === 0 && out.trim().length > 0;
      writeAudit({ action: "capture", ok, exit: code, bytes: out.length });
      resolve(ok ? { ok: true, pngBase64: out.trim() } : { ok: false, reason: err.trim() || `exit ${code}` });
    });
  });
}

/** Führt eine Input-Aktion aus. `actionJson` = ein Action-Objekt (siehe forge-control). */
export async function forgeAct(actionJson: string): Promise<ActResult> {
  return new Promise((resolve) => {
    const child = spawn(forgeControlBin(), ["act"], { stdio: ["pipe", "pipe", "pipe"] });
    activeForgeChildren.add(child);
    let err = "";
    const killer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignored */
      }
    }, DEFAULT_TIMEOUT_MS);
    child.stderr.setEncoding("utf-8");
    child.stderr.on("data", (d: string) => {
      err += d;
    });
    child.on("error", (e) => {
      clearTimeout(killer);
      activeForgeChildren.delete(child);
      writeAudit({ action: "act", ok: false, error: String(e), request: safeActionSummary(actionJson) });
      resolve({ ok: false, reason: String(e) });
    });
    child.on("close", (code) => {
      clearTimeout(killer);
      activeForgeChildren.delete(child);
      const ok = code === 0;
      writeAudit({ action: "act", ok, exit: code, request: safeActionSummary(actionJson) });
      resolve(ok ? { ok: true } : { ok: false, reason: err.trim() || `exit ${code}` });
    });
    child.stdin.write(actionJson);
    child.stdin.end();
  });
}

export function forgeAuditLogPath(): string {
  return AUDIT_PATH;
}
