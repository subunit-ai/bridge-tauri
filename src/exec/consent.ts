import { createHash, randomUUID } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve as resolvePath } from "node:path";

import { db, kvDel, kvGet, kvSet } from "../storage/db.ts";
import { getAccessMode, type AccessMode } from "./access-mode.ts";

export type RemoteAccessState = "active" | "revoked";
export type ConsentStatus = "pending" | "allowed" | "denied" | "expired" | "consumed" | "revoked" | "rate_limited";
export type ConsentAwaitStatus = "allowed" | "denied" | "expired";

const REMOTE_ACCESS_KEY = "consent.remote_access";
const SESSION_GRANT_KEY = "consent.session_grant";
const EXEC_LAST_ACTIVE_KEY = "exec.last_active_at";
const CONSENT_AUDIT_PATH = resolvePath(homedir(), ".config/subunit-bridge/consent-audit.jsonl");
const MAX_PENDING_PER_WORKSPACE_OPERATOR = 5;
const MAX_PENDING_PER_WORKSPACE = 20;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_PER_WINDOW = 20;
const MAX_REMEMBER_SECONDS = 30 * 60;

const CONSUMED_CONSENT_BRAND = Symbol.for("subunit.consent.consumed");

interface ConsentRow {
  id: string;
  request_id: string;
  nonce: string;
  workspace_id: string;
  operator_id: string;
  cmd: string;
  cwd: string | null;
  cmd_sha256: string;
  cwd_sha256: string;
  scope: string;
  status: ConsentStatus;
  created_at: number;
  decided_at: number | null;
  consumed_at: number | null;
  expires_at: number;
}

export interface SessionGrant {
  workspace_id: string;
  operator_id: string;
  access_mode: AccessMode;
  cmd_sha256: string;
  cwd_sha256: string;
  scope: string;
  source_consent_id: string;
  created_at: number;
  expires_at: number;
}

interface Awaiter {
  timer: ReturnType<typeof setTimeout>;
  resolve: (result: ConsentAwaitResult) => void;
}

export interface ConsentRequestView {
  id: string;
  request_id: string;
  workspace_id: string;
  operator_id: string;
  cmd: string[];
  cwd: string | null;
  cmd_sha256: string;
  cwd_sha256: string;
  scope: string;
  status: ConsentStatus;
  created_at: number;
  decided_at: number | null;
  consumed_at: number | null;
  expires_at: number;
}

export interface CreateConsentReservationInput {
  requestId: string;
  nonce: string;
  workspaceId: string;
  operatorId: string;
  cmd: string[];
  cwd?: string;
  cmdSha256: string;
  cwdSha256: string;
  scope: string;
  approvalExpiresAt: number;
}

export type CreateConsentReservationResult =
  | { ok: true; id: string; status: "pending" }
  | { ok: false; id?: string; status: "rate_limited"; reason: string }
  | { ok: false; status: "duplicate"; reason: string };

export interface ConsentAwaitResult {
  status: ConsentAwaitStatus;
  reason: string;
}

export interface DecideResult {
  ok: boolean;
  status: ConsentStatus | "not_found";
  reason?: string;
}

export interface ConsentConsumeContext {
  workspaceId: string;
  requestId: string;
  nonce: string;
  operatorId: string;
  cmdSha256: string;
  cwdSha256: string;
  scope: string;
  approvalExpiresAt: number;
}

export interface ConsumedConsentProof {
  readonly [CONSUMED_CONSENT_BRAND]: true;
  internalId: string;
  requestId: string;
  workspaceId: string;
  operatorId: string;
  cmdSha256: string;
  cwdSha256: string;
  scope: string;
  consumedAt: number;
}

export type ConsumeAllowedConsentResult =
  | { ok: true; proof: ConsumedConsentProof }
  | { ok: false; reason: string };

export type RemoteAccessHardStopHook = (reason: string) => void;

let memorySessionGrant: SessionGrant | null = null;
const awaiters = new Map<string, Set<Awaiter>>();
const remoteAccessHardStopHooks = new Set<RemoteAccessHardStopHook>();

function nowMs(): number {
  return Date.now();
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function writeConsentAudit(entry: Record<string, unknown>): void {
  try {
    mkdirSync(dirname(CONSENT_AUDIT_PATH), { recursive: true });
    appendFileSync(CONSENT_AUDIT_PATH, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
  } catch (err) {
    console.warn("[consent] audit write failed:", err);
  }
}

function auditInput(input: CreateConsentReservationInput, status: ConsentStatus | "duplicate", reason: string): void {
  writeConsentAudit({
    request_id: input.requestId,
    nonce_sha256: sha256Text(input.nonce),
    operator_id: input.operatorId,
    workspace_id: input.workspaceId,
    cmd_sha256: input.cmdSha256,
    status,
    reason,
  });
}

function auditRow(row: ConsentRow, status: ConsentStatus, reason: string): void {
  writeConsentAudit({
    request_id: row.request_id,
    nonce_sha256: sha256Text(row.nonce),
    operator_id: row.operator_id,
    workspace_id: row.workspace_id,
    cmd_sha256: row.cmd_sha256,
    status,
    reason,
  });
}

function readConsentRow(internalId: string): ConsentRow | null {
  return db.query<ConsentRow, [string]>("SELECT * FROM consent_requests WHERE id = ?").get(internalId) ?? null;
}

function activeWorkspaceId(): string | null {
  const row = db
    .query<{ active_workspace_id: string | null }, []>("SELECT active_workspace_id FROM tokens ORDER BY id DESC LIMIT 1")
    .get();
  return row?.active_workspace_id ?? null;
}

function parseCmdJson(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) return [];
    return parsed;
  } catch {
    return [];
  }
}

function rowToView(row: ConsentRow): ConsentRequestView {
  return {
    id: row.id,
    request_id: row.request_id,
    workspace_id: row.workspace_id,
    operator_id: row.operator_id,
    cmd: parseCmdJson(row.cmd),
    cwd: row.cwd,
    cmd_sha256: row.cmd_sha256,
    cwd_sha256: row.cwd_sha256,
    scope: row.scope,
    status: row.status,
    created_at: row.created_at,
    decided_at: row.decided_at,
    consumed_at: row.consumed_at,
    expires_at: row.expires_at,
  };
}

function awaitResultForRow(row: ConsentRow | null): ConsentAwaitResult {
  if (!row) return { status: "denied", reason: "not_found" };
  if (row.status === "allowed") return { status: "allowed", reason: "local_allowed" };
  if (row.status === "expired") return { status: "expired", reason: "expired" };
  if (row.status === "pending") return { status: "expired", reason: "expired" };
  if (row.status === "consumed") return { status: "expired", reason: "already_consumed" };
  return { status: "denied", reason: row.status };
}

function isTerminalForAwait(row: ConsentRow | null): boolean {
  return !row || row.status !== "pending";
}

function notifyAwaiters(internalId: string, result: ConsentAwaitResult): void {
  const entries = awaiters.get(internalId);
  if (!entries) return;
  awaiters.delete(internalId);
  for (const entry of entries) {
    clearTimeout(entry.timer);
    entry.resolve(result);
  }
}

export function registerRemoteAccessHardStopHook(hook: RemoteAccessHardStopHook): () => void {
  remoteAccessHardStopHooks.add(hook);
  return () => {
    remoteAccessHardStopHooks.delete(hook);
  };
}

function runRemoteAccessHardStopHooks(reason: string): void {
  for (const hook of Array.from(remoteAccessHardStopHooks)) {
    try {
      hook(reason);
    } catch (err) {
      console.warn("[consent] remote access hard-stop hook failed:", err);
    }
  }
}

function isUniqueConstraintError(err: unknown): boolean {
  return err instanceof Error && /UNIQUE constraint failed/i.test(err.message);
}

function expireDueConsents(reason: string): void {
  const now = nowMs();
  const rows = db
    .query<ConsentRow, [number]>(
      "SELECT * FROM consent_requests WHERE status IN ('pending', 'allowed') AND consumed_at IS NULL AND expires_at <= ?",
    )
    .all(now);
  if (rows.length === 0) return;
  db.run(
    "UPDATE consent_requests SET status = 'expired', decided_at = COALESCE(decided_at, ?) WHERE status IN ('pending', 'allowed') AND consumed_at IS NULL AND expires_at <= ?",
    [now, now],
  );
  for (const row of rows) {
    auditRow(row, "expired", reason);
    notifyAwaiters(row.id, { status: "expired", reason });
  }
}

function loadSessionGrant(): SessionGrant | null {
  if (memorySessionGrant) return memorySessionGrant;
  const raw = kvGet(SESSION_GRANT_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as SessionGrant;
    memorySessionGrant = parsed;
    return parsed;
  } catch {
    kvDel(SESSION_GRANT_KEY);
    return null;
  }
}

function clearSessionGrant(): void {
  memorySessionGrant = null;
  kvDel(SESSION_GRANT_KEY);
}

export function isConsumedConsentProof(value: unknown): value is ConsumedConsentProof {
  return typeof value === "object" && value !== null && (value as { [CONSUMED_CONSENT_BRAND]?: unknown })[CONSUMED_CONSENT_BRAND] === true;
}

export function getRemoteAccessState(): RemoteAccessState {
  return kvGet(REMOTE_ACCESS_KEY) === "revoked" ? "revoked" : "active";
}

export function isRemoteAccessRevoked(): boolean {
  return getRemoteAccessState() === "revoked";
}

export function setRemoteAccess(state: RemoteAccessState): void {
  const revokedRows: ConsentRow[] = [];
  const now = nowMs();
  db.transaction(() => {
    kvSet(REMOTE_ACCESS_KEY, state);
    if (state === "revoked") {
      revokedRows.push(
        ...db
          .query<ConsentRow, []>(
            "SELECT * FROM consent_requests WHERE status IN ('pending', 'allowed') AND consumed_at IS NULL",
          )
          .all(),
      );
      db.run(
        "UPDATE consent_requests SET status = 'revoked', decided_at = ? WHERE status IN ('pending', 'allowed') AND consumed_at IS NULL",
        [now],
      );
      clearSessionGrant();
    }
  })();

  for (const row of revokedRows) {
    auditRow(row, "revoked", "remote_access_revoked");
    notifyAwaiters(row.id, { status: "denied", reason: "remote_access_revoked" });
  }
  if (state === "revoked") runRemoteAccessHardStopHooks("remote_access_revoked");
}

export function expireOpenConsentRequests(reason: string): void {
  const rows = db.query<ConsentRow, []>("SELECT * FROM consent_requests WHERE status = 'pending'").all();
  if (rows.length === 0) return;
  const now = nowMs();
  db.run("UPDATE consent_requests SET status = 'expired', decided_at = ? WHERE status = 'pending'", [now]);
  for (const row of rows) {
    auditRow(row, "expired", reason);
    notifyAwaiters(row.id, { status: "expired", reason });
  }
}

export function initConsentOnStartup(): void {
  const staleRows = db
    .query<ConsentRow, []>("SELECT * FROM consent_requests WHERE status IN ('pending', 'allowed') AND consumed_at IS NULL")
    .all();
  const now = nowMs();
  db.transaction(() => {
    if (!kvGet(REMOTE_ACCESS_KEY)) kvSet(REMOTE_ACCESS_KEY, "active");
    clearSessionGrant();
    db.run(
      "UPDATE consent_requests SET status = 'expired', decided_at = COALESCE(decided_at, ?) WHERE status IN ('pending', 'allowed') AND consumed_at IS NULL",
      [now],
    );
  })();
  for (const row of staleRows) {
    auditRow(row, "expired", "startup_restart");
  }
}

export function createConsentReservation(input: CreateConsentReservationInput): CreateConsentReservationResult {
  expireDueConsents("ttl");
  const now = nowMs();
  const workspacePendingCount = db
    .query<{ count: number }, [string]>(
      "SELECT COUNT(*) AS count FROM consent_requests WHERE workspace_id = ? AND status = 'pending'",
    )
    .get(input.workspaceId)?.count ?? 0;
  const pendingCount = db
    .query<{ count: number }, [string, string]>(
      "SELECT COUNT(*) AS count FROM consent_requests WHERE workspace_id = ? AND operator_id = ? AND status = 'pending'",
    )
    .get(input.workspaceId, input.operatorId)?.count ?? 0;
  const recentCount = db
    .query<{ count: number }, [string, string, number]>(
      "SELECT COUNT(*) AS count FROM consent_requests WHERE workspace_id = ? AND operator_id = ? AND created_at >= ?",
    )
    .get(input.workspaceId, input.operatorId, now - RATE_LIMIT_WINDOW_MS)?.count ?? 0;

  const id = randomUUID();
  let status: ConsentStatus = "pending";
  let reason = "created";
  if (workspacePendingCount >= MAX_PENDING_PER_WORKSPACE) {
    status = "rate_limited";
    reason = "workspace_pending_cap";
  } else if (pendingCount >= MAX_PENDING_PER_WORKSPACE_OPERATOR) {
    status = "rate_limited";
    reason = "pending_cap";
  } else if (recentCount >= RATE_LIMIT_MAX_PER_WINDOW) {
    status = "rate_limited";
    reason = "rate_limit";
  }

  try {
    db.run(
      `INSERT INTO consent_requests
        (id, request_id, nonce, workspace_id, operator_id, cmd, cwd, cmd_sha256, cwd_sha256, scope, status, created_at, decided_at, consumed_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
      [
        id,
        input.requestId,
        input.nonce,
        input.workspaceId,
        input.operatorId,
        JSON.stringify(input.cmd),
        input.cwd ?? null,
        input.cmdSha256,
        input.cwdSha256,
        input.scope,
        status,
        now,
        status === "pending" ? null : now,
        input.approvalExpiresAt,
      ],
    );
  } catch (err) {
    if (isUniqueConstraintError(err)) {
      auditInput(input, "duplicate", "duplicate_request_or_nonce");
      return { ok: false, status: "duplicate", reason: "duplicate_request_or_nonce" };
    }
    throw err;
  }

  auditInput(input, status, reason);
  if (status === "rate_limited") return { ok: false, id, status, reason };
  return { ok: true, id, status: "pending" };
}

export async function awaitConsent(internalId: string, timeoutMs: number): Promise<ConsentAwaitResult> {
  expireDueConsents("ttl");
  const first = readConsentRow(internalId);
  if (isTerminalForAwait(first)) return awaitResultForRow(first);

  let entry: Awaiter | null = null;
  try {
    return await new Promise<ConsentAwaitResult>((resolve) => {
      const row = first!;
      const deadline = Math.min(nowMs() + Math.max(0, timeoutMs), row.expires_at);
      const delay = Math.max(0, deadline - nowMs());
      entry = {
        resolve,
        timer: setTimeout(() => {
          const current = readConsentRow(internalId);
          if (current?.status === "pending") {
            db.run("UPDATE consent_requests SET status = 'expired', decided_at = ? WHERE id = ? AND status = 'pending'", [nowMs(), internalId]);
            auditRow(current, "expired", "await_timeout");
          }
          notifyAwaiters(internalId, { status: "expired", reason: "await_timeout" });
        }, delay),
      };

      const set = awaiters.get(internalId) ?? new Set<Awaiter>();
      set.add(entry);
      awaiters.set(internalId, set);

      expireDueConsents("ttl");
      const second = readConsentRow(internalId);
      if (isTerminalForAwait(second)) {
        notifyAwaiters(internalId, awaitResultForRow(second));
      }
    });
  } finally {
    const cleanupEntry = entry as Awaiter | null;
    if (cleanupEntry) {
      clearTimeout(cleanupEntry.timer);
      const set = awaiters.get(internalId);
      if (set) {
        set.delete(cleanupEntry);
        if (set.size === 0) awaiters.delete(internalId);
      }
    }
  }
}

export function decide(internalId: string, decision: "allowed" | "denied", reason = "local_decision"): DecideResult {
  expireDueConsents("ttl");
  const now = nowMs();
  const nextStatus: ConsentStatus = decision;
  const before = readConsentRow(internalId);
  if (!before) return { ok: false, status: "not_found", reason: "not_found" };
  const result = db.run(
    "UPDATE consent_requests SET status = ?, decided_at = ? WHERE id = ? AND status = 'pending' AND expires_at > ?",
    [nextStatus, now, internalId, now],
  );
  if (result.changes !== 1) {
    const after = readConsentRow(internalId);
    return { ok: false, status: after?.status ?? "not_found", reason: "not_pending" };
  }
  auditRow(before, nextStatus, reason);
  notifyAwaiters(internalId, awaitResultForRow({ ...before, status: nextStatus, decided_at: now }));
  return { ok: true, status: nextStatus };
}

export function markConsentRevoked(internalId: string, reason = "remote_access_revoked"): void {
  const now = nowMs();
  const before = readConsentRow(internalId);
  if (!before) return;
  const result = db.run(
    "UPDATE consent_requests SET status = 'revoked', decided_at = ? WHERE id = ? AND status = 'pending'",
    [now, internalId],
  );
  if (result.changes === 1) {
    auditRow(before, "revoked", reason);
    notifyAwaiters(internalId, { status: "denied", reason });
  }
}

export function consumeAllowedConsent(internalId: string, ctx: ConsentConsumeContext): ConsumeAllowedConsentResult {
  let proof: ConsumedConsentProof | null = null;
  let failure = "consent_not_consumed";
  const now = nowMs();

  db.transaction(() => {
    if (getRemoteAccessState() !== "active") {
      failure = "remote_access_revoked";
      db.run(
        "UPDATE consent_requests SET status = 'revoked', decided_at = COALESCE(decided_at, ?) WHERE id = ? AND status = 'allowed' AND consumed_at IS NULL",
        [now, internalId],
      );
      return;
    }
    if (activeWorkspaceId() !== ctx.workspaceId) {
      failure = "workspace_scope_changed";
      db.run(
        "UPDATE consent_requests SET status = 'expired', decided_at = COALESCE(decided_at, ?) WHERE id = ? AND status = 'allowed' AND consumed_at IS NULL",
        [now, internalId],
      );
      return;
    }
    if (ctx.approvalExpiresAt <= now) {
      failure = "approval_expired";
      db.run(
        "UPDATE consent_requests SET status = 'expired', decided_at = COALESCE(decided_at, ?) WHERE id = ? AND status = 'allowed' AND consumed_at IS NULL",
        [now, internalId],
      );
      return;
    }

    const result = db.run(
      `UPDATE consent_requests
       SET status = 'consumed', consumed_at = ?
       WHERE id = ?
         AND workspace_id = ?
         AND request_id = ?
         AND nonce = ?
         AND operator_id = ?
         AND cmd_sha256 = ?
         AND cwd_sha256 = ?
         AND scope = ?
         AND status = 'allowed'
         AND consumed_at IS NULL
         AND expires_at > ?`,
      [
        now,
        internalId,
        ctx.workspaceId,
        ctx.requestId,
        ctx.nonce,
        ctx.operatorId,
        ctx.cmdSha256,
        ctx.cwdSha256,
        ctx.scope,
        now,
      ],
    );
    if (result.changes !== 1) {
      const row = readConsentRow(internalId);
      if (row?.status === "allowed" && row.expires_at <= now) {
        failure = "consent_expired";
        db.run(
          "UPDATE consent_requests SET status = 'expired', decided_at = COALESCE(decided_at, ?) WHERE id = ? AND status = 'allowed' AND consumed_at IS NULL",
          [now, internalId],
        );
      } else {
        failure = row ? `consent_${row.status}` : "consent_not_found";
      }
      return;
    }

    proof = Object.freeze({
      [CONSUMED_CONSENT_BRAND]: true as const,
      internalId,
      requestId: ctx.requestId,
      workspaceId: ctx.workspaceId,
      operatorId: ctx.operatorId,
      cmdSha256: ctx.cmdSha256,
      cwdSha256: ctx.cwdSha256,
      scope: ctx.scope,
      consumedAt: now,
    });
  })();

  const row = readConsentRow(internalId);
  if (proof && row) {
    auditRow(row, "consumed", "atomic_consume");
    return { ok: true, proof };
  }
  if (row && (row.status === "expired" || row.status === "revoked")) auditRow(row, row.status, failure);
  return { ok: false, reason: failure };
}

export function hasMatchingSessionGrant(ctx: ConsentConsumeContext): boolean {
  const grant = getSessionGrant();
  if (!grant) return false;
  const mode = getAccessMode();
  return (
    grant.workspace_id === ctx.workspaceId &&
    grant.operator_id === ctx.operatorId &&
    grant.access_mode === mode &&
    grant.cmd_sha256 === ctx.cmdSha256 &&
    grant.cwd_sha256 === ctx.cwdSha256 &&
    grant.scope === ctx.scope
  );
}

export function setSessionGrantForConsent(internalId: string, rememberForSeconds: number): SessionGrant | null {
  const seconds = Math.max(0, Math.min(MAX_REMEMBER_SECONDS, Math.floor(rememberForSeconds)));
  if (seconds <= 0 || getRemoteAccessState() !== "active") return null;
  const row = readConsentRow(internalId);
  if (!row || row.status !== "allowed") return null;
  const now = nowMs();
  const grant: SessionGrant = {
    workspace_id: row.workspace_id,
    operator_id: row.operator_id,
    access_mode: getAccessMode(),
    cmd_sha256: row.cmd_sha256,
    cwd_sha256: row.cwd_sha256,
    scope: row.scope,
    source_consent_id: row.id,
    created_at: now,
    expires_at: now + seconds * 1000,
  };
  memorySessionGrant = grant;
  kvSet(SESSION_GRANT_KEY, JSON.stringify(grant));
  return grant;
}

export function getSessionGrant(): SessionGrant | null {
  const grant = loadSessionGrant();
  if (!grant) return null;
  if (grant.expires_at <= nowMs()) {
    clearSessionGrant();
    return null;
  }
  return grant;
}

export function listPendingConsentRequests(workspaceId: string): ConsentRequestView[] {
  expireDueConsents("ttl");
  return db
    .query<ConsentRow, [string, number]>(
      "SELECT * FROM consent_requests WHERE workspace_id = ? AND status = 'pending' AND expires_at > ? ORDER BY created_at DESC LIMIT 200",
    )
    .all(workspaceId, nowMs())
    .map(rowToView);
}

export function getConsentRequest(internalId: string, workspaceId?: string): ConsentRequestView | null {
  expireDueConsents("ttl");
  const row = workspaceId
    ? db.query<ConsentRow, [string, string]>("SELECT * FROM consent_requests WHERE id = ? AND workspace_id = ?").get(internalId, workspaceId)
    : readConsentRow(internalId);
  return row ? rowToView(row) : null;
}

export function pendingConsentCount(workspaceId: string): number {
  expireDueConsents("ttl");
  return db
    .query<{ count: number }, [string, number]>(
      "SELECT COUNT(*) AS count FROM consent_requests WHERE workspace_id = ? AND status = 'pending' AND expires_at > ?",
    )
    .get(workspaceId, nowMs())?.count ?? 0;
}

export function lastExecActiveAt(): number | null {
  const raw = kvGet(EXEC_LAST_ACTIVE_KEY);
  if (!raw) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
}
