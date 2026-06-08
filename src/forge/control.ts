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

// =====================================================================
// Live-Stream (Forge L3) — persistenter forge-control-Prozess, JPEG-Frame-Strom
// =====================================================================

const MAX_STREAM_FRAME_BYTES = 8_000_000; // 8 MB pro Frame (gegen entartete/manipulierte Längen).
const MAX_STREAM_HEADER_BYTES = 4096; // Header-Zeile (JSON) ist winzig; alles darüber = kaputt.

export interface StreamHeader {
  /** ORIGINAL-Capture-Breite/Höhe — Klick-Koordinatenraum (NICHT die skalierte Frame-Größe). */
  w: number;
  h: number;
  fps: number;
  format: string;
}

export interface ForgeStreamHandle {
  /** Beendet den Stream sauber (stdin-EOF → forge-control stoppt) + killt als Fallback. */
  stop: () => void;
}

/**
 * Startet einen Live-Stream: spawnt `forge-control stream` und parst dessen length-prefixed
 * stdout-Protokoll (1 Header-Zeile JSON + '\n', dann je Frame 4 Byte BE-Länge + JPEG-Bytes).
 * `onHeader` feuert einmal, `onFrame` pro Frame (Buffer), `onEnd` genau einmal beim Ende.
 *
 * BEWUSST OHNE Auth/Policy — wie capture/act: Approval/Consent/Kill-Switch erzwingt der
 * WS-Handler DAVOR. Registriert sich im selben `activeForgeChildren`-Set (Revoke killt auch Streams).
 */
export function forgeStream(
  opts: { fps?: number; quality?: number; maxWidth?: number },
  onHeader: (header: StreamHeader) => void,
  onFrame: (jpeg: Buffer) => void,
  onEnd: (reason: string) => void,
): ForgeStreamHandle {
  const args = [
    "stream",
    "--fps",
    String(opts.fps ?? 8),
    "--quality",
    String(opts.quality ?? 55),
    "--max-width",
    String(opts.maxWidth ?? 1280),
  ];
  const child = spawn(forgeControlBin(), args, { stdio: ["pipe", "pipe", "pipe"] });
  activeForgeChildren.add(child);

  let buf: Buffer = Buffer.alloc(0);
  let headerParsed = false;
  let err = "";
  let finished = false;

  function finish(reason: string): void {
    if (finished) return;
    finished = true;
    activeForgeChildren.delete(child);
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignored */
    }
    onEnd(reason);
  }

  child.stdout.on("data", (chunk: Buffer) => {
    if (finished) return;
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    // 1) Header-Zeile bis zum ersten '\n'.
    if (!headerParsed) {
      const nl = buf.indexOf(0x0a);
      if (nl < 0) {
        if (buf.length > MAX_STREAM_HEADER_BYTES) finish("header_too_long");
        return;
      }
      const headerLine = buf.subarray(0, nl).toString("utf-8");
      buf = buf.subarray(nl + 1);
      try {
        const h = JSON.parse(headerLine) as Partial<StreamHeader>;
        if (typeof h.w !== "number" || typeof h.h !== "number") {
          finish("bad_header");
          return;
        }
        onHeader({ w: h.w, h: h.h, fps: Number(h.fps) || 0, format: String(h.format ?? "jpeg") });
        headerParsed = true;
      } catch {
        finish("bad_header");
        return;
      }
    }
    // 2) Frames: [4 Byte BE-Länge][JPEG].
    while (headerParsed && buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (len > MAX_STREAM_FRAME_BYTES) {
        finish("frame_too_large");
        return;
      }
      if (buf.length < 4 + len) break; // Rest des Frames noch nicht angekommen.
      const jpeg = Buffer.from(buf.subarray(4, 4 + len)); // kopieren → Restpuffer kann GC
      buf = buf.subarray(4 + len);
      onFrame(jpeg);
    }
  });
  child.stderr.setEncoding("utf-8");
  child.stderr.on("data", (d: string) => {
    err += d;
    if (err.length > 8192) err = err.slice(-8192);
  });
  child.on("error", (e) => {
    writeAudit({ action: "stream", ok: false, error: String(e) });
    finish(String(e));
  });
  child.on("close", (code) => {
    writeAudit({ action: "stream", ok: code === 0, exit: code });
    finish(err.trim() || `exit ${code}`);
  });

  return {
    stop: () => {
      // Sauberer Stop: stdin schließen → forge-control beendet bei EOF; finish killt als Fallback.
      try {
        child.stdin.end();
      } catch {
        /* ignored */
      }
      finish("stopped");
    },
  };
}

export function forgeAuditLogPath(): string {
  return AUDIT_PATH;
}
