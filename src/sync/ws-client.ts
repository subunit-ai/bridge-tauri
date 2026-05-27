/**
 * WebSocket Client — connects Bridge to api.subunit.ai/ws.
 *
 * Subscribes to workspace-scoped events from the server (decision.created,
 * task.updated, etc) and updates local SQLite cache so subsequent HTTP reads
 * from local apps return fresh data.
 *
 * Connection lifecycle:
 *   - Wait for paired tokens (poll every 2s if not paired)
 *   - Connect to wss://api.subunit.ai/ws?client_id=bridge-daemon with Authorization
 *   - On open: send hello and start ping interval (30s)
 *   - On message: dispatch to local handlers
 *   - On close: exponential backoff reconnect (1s..60s)
 *   - On token refresh: reconnect with new token
 */
import { db } from "../storage/db.ts";
import { createHash, verify } from "node:crypto";
import { ensureFreshAccessToken } from "./auth-client.ts";
import { loadTokens } from "../storage/tokens.ts";
import { config } from "../config.ts";
import {
  createVerifiedApprovalProof,
  killActiveRemoteExecChildren,
  runRemoteExec,
  type VerifiedApprovalProof,
} from "../exec/runner.ts";
import {
  awaitConsent,
  consumeAllowedConsent,
  createConsentReservation,
  decide,
  expireOpenConsentRequests,
  hasMatchingSessionGrant,
  isRemoteAccessRevoked,
  markConsentRevoked,
  type ConsumedConsentProof,
} from "../exec/consent.ts";

const PING_INTERVAL_MS = 30_000;
const SERVER_SILENCE_TIMEOUT_MS = 90_000; // 3 missed pings → force reconnect
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 60_000;
const RECONNECT_JITTER_MS = 500;
const EXEC_APPROVAL_MAX_FUTURE_MS = 5 * 60_000;
const EXEC_SEEN_RETENTION_MS = 10 * 60_000;
const MAX_EXEC_ARG_LENGTH = 2048;
const MAX_EXEC_ARGS = 64;

interface ServerEvent {
  kind: string;
  workspace_id: string;
  payload: Record<string, unknown>;
  ts: number;
}

// Module-level handle so logout-handlers in other modules can close the
// active WebSocket immediately without waiting for the next ping.
let activeSocket: WebSocket | null = null;
const seenExecRequestIds = new Map<string, number>();
const seenExecNonces = new Map<string, number>();

export function disconnectWsClient(reason = "logout"): void {
  if (reason === "logout" || reason === "remote_access_revoked") {
    killActiveRemoteExecChildren(reason);
  }
  if (activeSocket) {
    try { activeSocket.close(4001, reason); } catch { /* ignored */ }
    activeSocket = null;
  }
}

function wsUrlFromHttp(httpUrl: string): string {
  return httpUrl.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://");
}

export function startWsClient(): { stop(): void } {
  let stopped = false;
  let ws: WebSocket | null = null;
  let reconnectAttempts = 0;
  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  async function connectLoop(): Promise<void> {
    while (!stopped) {
      if (isRemoteAccessRevoked()) {
        await sleep(2_000);
        continue;
      }
      const tokens = await ensureFreshAccessToken();
      if (!tokens) {
        // Not paired yet — wait + retry. Sleep a few seconds, then re-check.
        await sleep(2_000);
        continue;
      }
      if (isRemoteAccessRevoked()) {
        await sleep(2_000);
        continue;
      }

      const url = `${wsUrlFromHttp(config.apiBaseUrl)}/ws?client_id=${encodeURIComponent(config.clientId)}`;
      console.log(`[ws-client] connecting...`);
      try {
        await new Promise<void>((resolve) => {
          ws = new WebSocket(url, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
          activeSocket = ws;

          let lastServerMessageAt = Date.now();

          ws.addEventListener("open", () => {
            console.log("[ws-client] connected");
            reconnectAttempts = 0;
            lastServerMessageAt = Date.now();
            if (pingTimer) clearInterval(pingTimer);
            pingTimer = setInterval(() => {
              // Belt-and-braces: if the user logged out, ensureFreshAccessToken
              // would already have purged tokens. Verify here so even if a
              // sibling module called clearTokens() without invoking
              // disconnectWsClient(), we self-close.
              if (!loadTokens()) {
                console.log("[ws-client] tokens gone — closing");
                try { ws?.close(4001, "logout"); } catch { /* ignored */ }
                return;
              }
              if (isRemoteAccessRevoked()) {
                console.log("[ws-client] remote access revoked — closing");
                killActiveRemoteExecChildren("remote_access_revoked");
                try { ws?.close(4003, "remote_access_revoked"); } catch { /* ignored */ }
                return;
              }
              // Death detection: on laptop sleep/wake (Win11 esp.) the TCP
              // socket can enter a zombie state where send() silently succeeds
              // but no server frames arrive. Without this, the close event
              // doesn't fire until OS-level TCP keep-alive expires (default
              // 2h on Windows). Force-close after 90s of server silence so
              // the outer reconnect loop kicks in.
              if (Date.now() - lastServerMessageAt > SERVER_SILENCE_TIMEOUT_MS) {
                console.warn("[ws-client] no server frame in 90s — forcing reconnect");
                try { ws?.close(4002, "server_silence"); } catch { /* ignored */ }
                return;
              }
              try {
                ws?.send(JSON.stringify({ kind: "ping" }));
              } catch { /* ignored — close handler will fire */ }
            }, PING_INTERVAL_MS);
          });

          ws.addEventListener("message", (evt) => {
            lastServerMessageAt = Date.now();
            handleMessage(evt.data as string);
          });

          ws.addEventListener("error", (evt) => {
            console.warn("[ws-client] error", (evt as { message?: string }).message ?? evt);
          });

          ws.addEventListener("close", (evt) => {
            console.log(`[ws-client] closed (code=${evt.code}, reason=${evt.reason || "—"})`);
            if (evt.reason === "logout" || evt.reason === "remote_access_revoked") {
              killActiveRemoteExecChildren(evt.reason);
            }
            expireOpenConsentRequests(`ws_closed:${evt.reason || evt.code}`);
            if (pingTimer) {
              clearInterval(pingTimer);
              pingTimer = null;
            }
            activeSocket = null;
            resolve();
          });
        });
      } catch (err) {
        console.warn("[ws-client] connect threw:", err);
      }

      if (stopped) break;
      if (isRemoteAccessRevoked()) {
        console.log("[ws-client] remote access revoked — reconnect paused");
        await sleep(2_000);
        continue;
      }
      // If we're now un-paired (user logged out), don't burn cycles
      // reconnecting — the outer loop's ensureFreshAccessToken() will park
      // us in the 2s wait branch until the next pair.
      const backoff = loadTokens() ? backoffMs(reconnectAttempts++) : 2_000;
      console.log(`[ws-client] reconnecting in ${backoff}ms`);
      await sleep(backoff);
    }
  }

  void connectLoop();

  return {
    stop() {
      stopped = true;
      if (pingTimer) clearInterval(pingTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      try { ws?.close(); } catch { /* ignored */ }
    },
  };
}

function backoffMs(attempts: number): number {
  const base = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * Math.pow(2, Math.min(attempts, 10)));
  const jitter = Math.floor(Math.random() * RECONNECT_JITTER_MS);
  return base + jitter;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeId(value: unknown, min: number, max: number): value is string {
  return typeof value === "string" && value.length >= min && value.length <= max && /^[A-Za-z0-9._:-]+$/.test(value);
}

function isSafeNonce(value: unknown): value is string {
  return typeof value === "string" && value.length >= 16 && value.length <= 160 && /^[A-Za-z0-9._~-]+$/.test(value);
}

function isSafeOperatorId(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 200 && !/[\0\x01-\x08\x0e-\x1f\x7f<>]/.test(value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

function sha256Json(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function decodeSignature(signature: string): Buffer {
  return Buffer.from(signature, "base64url");
}

function verifyApprovalSignature(payload: Record<string, unknown>, signature: string): boolean {
  if (!config.execApprovalPublicKey) return false;
  try {
    return verify(null, Buffer.from(canonicalJson(payload)), config.execApprovalPublicKey, decodeSignature(signature));
  } catch (err) {
    console.warn("[ws-client] exec approval signature verification failed:", err instanceof Error ? err.message : String(err));
    return false;
  }
}

function pruneSeenExec(now: number): void {
  for (const [id, expiresAt] of seenExecRequestIds) {
    if (expiresAt <= now) seenExecRequestIds.delete(id);
  }
  for (const [nonce, expiresAt] of seenExecNonces) {
    if (expiresAt <= now) seenExecNonces.delete(nonce);
  }
}

interface ParsedExecRequest {
  workspaceId: string;
  requestId: string;
  cmd: string[];
  cwd?: string;
  timeoutMs?: number;
  operatorId: string;
  nonce: string;
  scope: string;
  approvalExpiresAt: number;
  cmdSha256: string;
  cwdSha256: string;
  seenUntil: number;
  verifiedApproval: VerifiedApprovalProof;
}

type ExecParseResult =
  | { ok: true; request: ParsedExecRequest }
  | { ok: false; requestId: string; reason: string };

function parseExecRequest(evt: ServerEvent): ExecParseResult {
  const p = evt.payload;
  const requestId = isSafeId(p.request_id, 1, 128) ? p.request_id : "";
  if (!requestId) return { ok: false, requestId: "", reason: "malformed exec.request" };
  if (!isSafeId(evt.workspace_id, 1, 128)) return { ok: false, requestId, reason: "invalid workspace scope" };
  if (!Array.isArray(p.cmd) || p.cmd.length < 1 || p.cmd.length > MAX_EXEC_ARGS) {
    return { ok: false, requestId, reason: "invalid command" };
  }
  const cmd: string[] = [];
  for (const arg of p.cmd) {
    if (typeof arg !== "string" || arg.length < 1 || arg.length > MAX_EXEC_ARG_LENGTH || /[\0\x01-\x08\x0e-\x1f\x7f]/.test(arg)) {
      return { ok: false, requestId, reason: "invalid command arg" };
    }
    cmd.push(arg);
  }
  if (typeof p.cwd === "string" && p.cwd.length > 0 && p.cwd.trim().length === 0) {
    return { ok: false, requestId, reason: "invalid cwd: whitespace-only" };
  }
  const cwd = typeof p.cwd === "string" && p.cwd.length > 0 && p.cwd.length <= 512 && !/[\0\x01-\x08\x0e-\x1f\x7f]/.test(p.cwd)
    ? p.cwd
    : undefined;
  if (p.cwd !== undefined && cwd === undefined) return { ok: false, requestId, reason: "invalid cwd" };
  const timeoutMs = typeof p.timeout_ms === "number" && Number.isInteger(p.timeout_ms) && p.timeout_ms >= 1_000 && p.timeout_ms <= 300_000
    ? p.timeout_ms
    : undefined;
  if (p.timeout_ms !== undefined && timeoutMs === undefined) return { ok: false, requestId, reason: "invalid timeout" };
  const tokens = loadTokens();
  if (!tokens?.active_workspace_id || tokens.active_workspace_id !== evt.workspace_id) {
    return { ok: false, requestId, reason: "workspace scope denied" };
  }

  const approval = isRecord(p.approval) ? p.approval : null;
  if (!approval || approval.alg !== "Ed25519" || typeof approval.signature !== "string" || !isRecord(approval.payload)) {
    return { ok: false, requestId, reason: "missing exec approval" };
  }
  const claims = approval.payload;
  if (claims.approved !== true) return { ok: false, requestId, reason: "exec not approved" };
  if (!isSafeId(claims.id, 1, 128) || claims.request_id !== requestId || claims.workspace_id !== evt.workspace_id) {
    return { ok: false, requestId, reason: "approval scope mismatch" };
  }
  const scope = claims.scope;
  if (scope !== "exec:run") return { ok: false, requestId, reason: "approval scope denied" };
  if (!isSafeOperatorId(claims.operator_id)) return { ok: false, requestId, reason: "missing signed operator_id" };
  if (!isSafeNonce(claims.nonce)) return { ok: false, requestId, reason: "invalid approval nonce" };
  const cmdSha256 = sha256Json(cmd);
  const cwdSha256 = sha256Text(cwd ?? "");
  if (claims.cmd_sha256 !== cmdSha256) return { ok: false, requestId, reason: "approval command mismatch" };
  if (claims.cwd_sha256 !== cwdSha256) return { ok: false, requestId, reason: "approval cwd mismatch" };
  if (claims.timeout_ms !== (timeoutMs ?? null)) return { ok: false, requestId, reason: "approval timeout mismatch" };
  if (typeof claims.expires_at !== "number" || !Number.isFinite(claims.expires_at)) {
    return { ok: false, requestId, reason: "invalid approval expiry" };
  }

  const now = Date.now();
  const expiresAt = claims.expires_at > 1_000_000_000_000 ? claims.expires_at : claims.expires_at * 1000;
  if (expiresAt <= now) return { ok: false, requestId, reason: "approval expired" };
  if (expiresAt > now + EXEC_APPROVAL_MAX_FUTURE_MS) return { ok: false, requestId, reason: "approval expiry too far" };
  if (!verifyApprovalSignature(claims, approval.signature)) return { ok: false, requestId, reason: "invalid approval signature" };

  return {
    ok: true,
    request: {
      workspaceId: evt.workspace_id,
      requestId,
      cmd,
      cwd,
      timeoutMs,
      operatorId: claims.operator_id,
      nonce: claims.nonce,
      scope,
      approvalExpiresAt: expiresAt,
      cmdSha256,
      cwdSha256,
      seenUntil: Math.max(expiresAt, now + EXEC_SEEN_RETENTION_MS),
      verifiedApproval: createVerifiedApprovalProof({
        requestId,
        workspaceId: evt.workspace_id,
        operatorId: claims.operator_id,
        nonce: claims.nonce,
        scope,
        cmdSha256,
        cwdSha256,
        expiresAt,
      }),
    },
  };
}

function handleMessage(raw: string): void {
  let evt: ServerEvent;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed) || typeof parsed.kind !== "string" || !isRecord(parsed.payload)) {
      console.warn("[ws-client] malformed message");
      return;
    }
    evt = {
      kind: parsed.kind,
      workspace_id: typeof parsed.workspace_id === "string" ? parsed.workspace_id : "",
      payload: parsed.payload,
      ts: typeof parsed.ts === "number" ? parsed.ts : 0,
    };
  } catch {
    console.warn("[ws-client] non-JSON message");
    return;
  }
  switch (evt.kind) {
    case "hello":
      console.log(`[ws-client] hello received (subscriber_id=${evt.payload.subscriber_id})`);
      return;
    case "ping":
      // server pong — ignore
      return;
    case "decision.created":
    case "decision.approved":
    case "decision.rejected":
      handleDecisionEvent(evt);
      return;
    case "task.created":
    case "task.updated":
      handleTaskEvent(evt);
      return;
    case "memory.ingested":
      // Not stored locally yet — Phase 2.
      console.log(`[ws-client] memory.ingested received (id=${evt.payload.id})`);
      return;
    case "exec.request":
      // Remote-Exec: operator (or self) is asking the bridge to run a
      // whitelisted command and stream output back. Fire-and-forget
      // here — the runner will push exec.chunk / exec.done frames
      // back through activeSocket as it goes.
      void handleExecRequest(evt);
      return;
    default:
      console.log(`[ws-client] unknown event kind: ${evt.kind}`);
  }
}

async function handleExecRequest(evt: ServerEvent): Promise<void> {
  const parsed = parseExecRequest(evt);
  if (!parsed.ok) {
    sendExecFrame({
      kind: "exec.done",
      request_id: parsed.requestId,
      ok: false,
      reason: parsed.reason,
    });
    return;
  }
  const {
    workspaceId,
    requestId,
    cmd,
    cwd,
    timeoutMs,
    operatorId,
    nonce,
    scope,
    approvalExpiresAt,
    cmdSha256,
    cwdSha256,
    seenUntil,
    verifiedApproval,
  } = parsed.request;
  const reservation = createConsentReservation({
    requestId,
    nonce,
    workspaceId,
    operatorId,
    cmd,
    cwd,
    cmdSha256,
    cwdSha256,
    scope,
    approvalExpiresAt,
  });
  if (!reservation.ok) {
    sendExecFrame({
      kind: "exec.done",
      request_id: requestId,
      ok: false,
      reason: reservation.status === "duplicate" ? "duplicate exec request" : `consent ${reservation.reason}`,
    });
    return;
  }

  pruneSeenExec(Date.now());
  seenExecRequestIds.set(requestId, seenUntil);
  seenExecNonces.set(nonce, seenUntil);

  const consentId = reservation.id;
  const consentCtx = {
    workspaceId,
    requestId,
    nonce,
    operatorId,
    cmdSha256,
    cwdSha256,
    scope,
    approvalExpiresAt,
  };

  if (isRemoteAccessRevoked()) {
    markConsentRevoked(consentId);
    sendExecFrame({
      kind: "exec.done",
      request_id: requestId,
      ok: false,
      reason: "remote access revoked",
    });
    return;
  }

  if (hasMatchingSessionGrant(consentCtx)) {
    const decision = decide(consentId, "allowed", "session_grant");
    if (!decision.ok) {
      sendExecFrame({ kind: "exec.done", request_id: requestId, ok: false, reason: `consent ${decision.reason ?? decision.status}` });
      return;
    }
    const consumed = consumeAllowedConsent(consentId, consentCtx);
    if (!consumed.ok) {
      sendExecFrame({ kind: "exec.done", request_id: requestId, ok: false, reason: consumed.reason });
      return;
    }
    startRemoteExec({ workspaceId, requestId, cmd, cwd, timeoutMs, operatorId, verifiedApproval, consumedConsent: consumed.proof });
    return;
  }

  sendExecFrame({
    kind: "exec.pending",
    request_id: requestId,
    consent_id: consentId,
    operator_id: operatorId,
    cmd_sha256: cmdSha256,
    cwd_sha256: cwdSha256,
    scope,
    expires_at: approvalExpiresAt,
  });

  const consent = await awaitConsent(consentId, Math.min(60_000, Math.max(0, approvalExpiresAt - Date.now())));
  if (consent.status !== "allowed") {
    sendExecFrame({
      kind: "exec.done",
      request_id: requestId,
      ok: false,
      reason: `consent ${consent.reason}`,
    });
    return;
  }

  const consumed = consumeAllowedConsent(consentId, consentCtx);
  if (!consumed.ok) {
    sendExecFrame({
      kind: "exec.done",
      request_id: requestId,
      ok: false,
      reason: consumed.reason,
    });
    return;
  }
  startRemoteExec({ workspaceId, requestId, cmd, cwd, timeoutMs, operatorId, verifiedApproval, consumedConsent: consumed.proof });
}

function startRemoteExec(req: {
  workspaceId: string;
  requestId: string;
  cmd: string[];
  cwd?: string;
  timeoutMs?: number;
  operatorId: string;
  verifiedApproval: VerifiedApprovalProof;
  consumedConsent: ConsumedConsentProof;
}): void {
  void runRemoteExec(
    {
      cmd: req.cmd,
      cwd: req.cwd,
      timeoutMs: req.timeoutMs,
      requestId: req.requestId,
      workspaceId: req.workspaceId,
      operatorId: req.operatorId,
    },
    {
      verifiedApproval: req.verifiedApproval,
      consumedConsent: req.consumedConsent,
    },
    (stream, data) => {
      sendExecFrame({
        kind: "exec.chunk",
        request_id: req.requestId,
        stream,
        data,
      });
    },
  ).then((result) => {
    sendExecFrame({
      kind: "exec.done",
      request_id: req.requestId,
      ok: result.ok,
      exit_code: result.exitCode,
      wall_time_ms: result.wallTimeMs,
      stdout_bytes: result.stdoutBytes,
      stderr_bytes: result.stderrBytes,
      truncated: result.truncated,
      reason: result.reason ?? null,
    });
  }).catch((err) => {
    sendExecFrame({
      kind: "exec.done",
      request_id: req.requestId,
      ok: false,
      reason: `runner threw: ${err}`,
    });
  });
}

function sendExecFrame(frame: Record<string, unknown>): void {
  if (!activeSocket || activeSocket.readyState !== WebSocket.OPEN) {
    // Socket dropped mid-exec — drop the frame. Audit log still has
    // the full record on disk.
    return;
  }
  try {
    activeSocket.send(JSON.stringify(frame));
  } catch (err) {
    console.warn("[ws-client] exec frame send failed:", err);
  }
}

function handleDecisionEvent(evt: ServerEvent): void {
  const id = evt.payload.id as string | undefined;
  if (!id) return;

  if (evt.kind === "decision.created") {
    // If the event carries a bridge_local_id and we already have that row,
    // this is the echo of our own outbox push. Mark it synced (no insert).
    const bridgeLocalId = evt.payload.bridge_local_id as string | null | undefined;
    if (bridgeLocalId) {
      const own = db
        .query<{ id: string }, [string]>("SELECT id FROM decisions WHERE id = ?")
        .get(bridgeLocalId);
      if (own) {
        db.run("UPDATE decisions SET synced_at = unixepoch() WHERE id = ?", [bridgeLocalId]);
        return;
      }
    }
    // Skip if already present by server id (shouldn't happen but be defensive)
    const existing = db.query<{ id: string }, [string]>("SELECT id FROM decisions WHERE id = ?").get(id);
    if (existing) return;
    const title = (evt.payload.title as string | undefined) ?? "(no title)";
    const source = (evt.payload.source as string | null | undefined) ?? null;
    db.run(
      "INSERT OR IGNORE INTO decisions (id, workspace_id, status, payload, source, synced_at) VALUES (?, ?, 'pending', ?, ?, unixepoch())",
      [id, evt.workspace_id, JSON.stringify({ title, body: null, metadata: { server_pushed: true } }), source],
    );
    console.log(`[ws-client] decision created locally: ${id}`);
  } else {
    const status = evt.kind === "decision.approved" ? "approved" : "rejected";
    db.run("UPDATE decisions SET status = ?, resolved_at = unixepoch(), synced_at = unixepoch() WHERE id = ?", [status, id]);
    console.log(`[ws-client] decision ${status}: ${id}`);
  }
}

function handleTaskEvent(evt: ServerEvent): void {
  const id = evt.payload.id as string | undefined;
  if (!id) return;
  if (evt.kind === "task.created") {
    const bridgeLocalId = evt.payload.bridge_local_id as string | null | undefined;
    if (bridgeLocalId) {
      const own = db.query<{ id: string }, [string]>("SELECT id FROM tasks WHERE id = ?").get(bridgeLocalId);
      if (own) {
        db.run("UPDATE tasks SET synced_at = unixepoch() WHERE id = ?", [bridgeLocalId]);
        return;
      }
    }
    const existing = db.query<{ id: string }, [string]>("SELECT id FROM tasks WHERE id = ?").get(id);
    if (existing) return;
    const title = (evt.payload.title as string | undefined) ?? "(no title)";
    const priority = evt.payload.priority as string | null | undefined;
    db.run(
      "INSERT OR IGNORE INTO tasks (id, workspace_id, title, status, payload, synced_at) VALUES (?, ?, ?, 'pending', ?, unixepoch())",
      [id, evt.workspace_id, title, JSON.stringify({ priority: priority ?? null, server_pushed: true })],
    );
    console.log(`[ws-client] task created locally: ${id}`);
  } else {
    const status = (evt.payload.status as string | undefined) ?? "pending";
    db.run("UPDATE tasks SET status = ?, updated_at = unixepoch(), synced_at = unixepoch() WHERE id = ?", [status, id]);
    console.log(`[ws-client] task updated: ${id} → ${status}`);
  }
}
