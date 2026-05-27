/**
 * Remote-Exec runner — receives exec requests (locally or from
 * api.subunit.ai via WebSocket), runs them against the whitelist,
 * streams stdout/stderr back, and writes an audit-log entry for
 * every attempted command.
 *
 * Security invariants:
 *   - Whitelist enforced at the binary level (basename of argv[0]).
 *     Whitelisted binaries are the read-ish dev tools the operator
 *     uses for diagnosis: `claude-code`, `git`, `ls`, `cat`, `head`,
 *     `tail`, `grep`, `find`, `python`, `python3`, `node`, `npm`,
 *     `bun`. NOT `rm`, NOT `sudo`, NOT shell.
 *   - cwd must resolve under the user's home directory. No escaping
 *     into `/etc` etc.
 *   - Execution timeout (default 60s, max 300s) so a runaway command
 *     can't hold the WebSocket subscriber forever.
 *   - Every exec attempt is logged BEFORE the spawn — even if the
 *     whitelist rejects it.
 *
 * Stream protocol:
 *   - Caller passes an `onChunk(stream, data)` callback. `stream` is
 *     "stdout" or "stderr", `data` is a UTF-8 string slice.
 *   - On completion the resolved promise carries `{ ok, exitCode,
 *     wallTimeMs, stdoutBytes, stderrBytes }`.
 */
import { spawn, type ChildProcessByStdio } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, appendFileSync, mkdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolve as resolvePath, dirname } from "node:path";
import type { Readable } from "node:stream";
import { kvSet } from "../storage/db.ts";
import { getAccessMode } from "./access-mode.ts";
import { getRemoteAccessState, isConsumedConsentProof, type ConsumedConsentProof } from "./consent.ts";

// Restricted-mode whitelist.
// Strictly read-only diagnostic tools — NO interpreters, NO compilers,
// NO HTTP clients. The whitelist intentionally excludes python, node,
// npm, bun, curl, wget, bash because any of them can call back to the
// local /auth/access endpoint and flip restricted → full from inside
// the sandbox, defeating the safety boundary. claude/claude-code are
// also out for the same reason.
const FILE_READ_COMMANDS: ReadonlySet<string> = new Set([
  "cat", "head", "tail", "ls", "find", "stat", "file", "tree",
  "grep", "rg", "wc", "sort", "uniq", "cut", "du",
]);

const INSPECTION_COMMANDS: ReadonlySet<string> = new Set([
  "ps", "top", "uname", "whoami", "id", "date", "uptime",
  "df", "free", "vmstat", "lsblk", "lsmod", "lsusb", "lspci",
  "journalctl", "dmesg", "ss", "netstat", "ip", "ping",
  "traceroute", "host", "dig", "nslookup", "echo", "pwd", "which",
  "where", "printenv",
]);

const DENIED_RESTRICTED_BINARIES: ReadonlySet<string> = new Set([
  "git", "systemctl", "service", "env", "bash", "sh",
]);

const WHITELIST: ReadonlySet<string> = new Set([
  ...Array.from(FILE_READ_COMMANDS),
  ...Array.from(INSPECTION_COMMANDS),
]);

const HOME = homedir();
const HOME_REAL = realpathSync(HOME);
const AUDIT_PATH = resolvePath(HOME, ".config/subunit-bridge/audit.jsonl");
const EXEC_LAST_ACTIVE_KEY = "exec.last_active_at";
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_TIMEOUT_MS = 300_000;
const MAX_STDOUT_BYTES = 1_000_000; // 1 MB cap so a runaway stream can't OOM the bridge.
const VERIFIED_APPROVAL_BRAND = Symbol.for("subunit.exec.verifiedApproval");
type RemoteChild = ChildProcessByStdio<null, Readable, Readable>;

interface ActiveRemoteChild {
  child: RemoteChild;
  pid: number | null;
  processGroupId: number | null;
}

interface BaseExecRequest {
  cmd: string[];        // argv — first element is the binary
  cwd?: string;         // defaults to user home
  timeoutMs?: number;   // defaults to 60s, capped at 300s
  requestId: string;    // operator-supplied — used in audit log + stream protocol
}

export interface ExecRequest extends BaseExecRequest {
  operator?: string;    // operator identifier (email or sub) for audit
  source: "local";      // local self-test only; WS must use runRemoteExec
}

export interface RemoteExecRequest extends BaseExecRequest {
  workspaceId: string;
  operatorId: string;
}

interface InternalExecRequest extends BaseExecRequest {
  operator?: string;
  source: "ws" | "local";
}

export interface VerifiedApprovalProof {
  readonly [VERIFIED_APPROVAL_BRAND]: true;
  requestId: string;
  workspaceId: string;
  operatorId: string;
  nonce: string;
  scope: string;
  cmdSha256: string;
  cwdSha256: string;
  expiresAt: number;
}

export interface VerifiedApprovalProofInput {
  requestId: string;
  workspaceId: string;
  operatorId: string;
  nonce: string;
  scope: string;
  cmdSha256: string;
  cwdSha256: string;
  expiresAt: number;
}

export interface ExecResult {
  ok: boolean;
  exitCode: number | null;
  wallTimeMs: number;
  stdoutBytes: number;
  stderrBytes: number;
  truncated: boolean;
  reason?: string;      // non-empty when ok=false (whitelist, timeout, etc.)
}

export type StreamHandler = (stream: "stdout" | "stderr", data: string) => void;

const activeRemoteChildren = new Map<RemoteChild, ActiveRemoteChild>();

function writeAudit(entry: Record<string, unknown>): void {
  try {
    mkdirSync(dirname(AUDIT_PATH), { recursive: true });
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + "\n");
  } catch (err) {
    console.warn("[exec] audit write failed:", err);
  }
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

function isVerifiedApprovalProof(value: unknown): value is VerifiedApprovalProof {
  return typeof value === "object" && value !== null && (value as { [VERIFIED_APPROVAL_BRAND]?: unknown })[VERIFIED_APPROVAL_BRAND] === true;
}

export function createVerifiedApprovalProof(input: VerifiedApprovalProofInput): VerifiedApprovalProof {
  return Object.freeze({
    [VERIFIED_APPROVAL_BRAND]: true as const,
    requestId: input.requestId,
    workspaceId: input.workspaceId,
    operatorId: input.operatorId,
    nonce: input.nonce,
    scope: input.scope,
    cmdSha256: input.cmdSha256,
    cwdSha256: input.cwdSha256,
    expiresAt: input.expiresAt,
  });
}

function registerActiveRemoteChild(child: RemoteChild): void {
  const pid = typeof child.pid === "number" ? child.pid : null;
  activeRemoteChildren.set(child, {
    child,
    pid,
    processGroupId: process.platform === "win32" ? null : pid,
  });
}

function killWindowsProcessTree(entry: ActiveRemoteChild): void {
  if (entry.pid === null) {
    try { entry.child.kill("SIGKILL"); } catch { /* ignored */ }
    return;
  }
  try {
    const killer = spawn("taskkill", ["/PID", String(entry.pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
    });
    killer.on("error", () => { /* ignored */ });
    killer.unref();
  } catch {
    try { entry.child.kill("SIGKILL"); } catch { /* ignored */ }
  }
}

function killPosixProcessGroup(entry: ActiveRemoteChild): void {
  if (entry.processGroupId !== null) {
    try {
      process.kill(-entry.processGroupId, "SIGKILL");
      return;
    } catch {
      // Fall through to direct child kill if the process group is already gone.
    }
  }
  try { entry.child.kill("SIGKILL"); } catch { /* ignored */ }
}

export function killActiveRemoteExecChildren(reason = "remote_access_revoked"): void {
  const entries = Array.from(activeRemoteChildren.values());
  for (const entry of entries) {
    if (process.platform === "win32") {
      killWindowsProcessTree(entry);
    } else {
      killPosixProcessGroup(entry);
    }
  }
  if (entries.length > 0) {
    console.warn(`[exec] killed active remote child process groups: ${reason}`);
  }
}

function safeBasename(p: string): string {
  // Strip directory + optional .exe suffix so the whitelist works
  // identically across Unix + Windows installs.
  const parts = p.replace(/\\/g, "/").split("/");
  const tail = parts[parts.length - 1] ?? p;
  return tail.replace(/\.exe$/i, "");
}

function pathUnderApprovedRoot(path: string): boolean {
  const normalized = path.replace(/\\/g, "/");
  const root = HOME_REAL.replace(/\\/g, "/");
  return normalized === root || normalized.startsWith(`${root}/`);
}

function nearestExistingRealpath(path: string): string | null {
  let cur = path;
  while (true) {
    if (existsSync(cur)) return realpathSync(cur);
    const parent = dirname(cur);
    if (parent === cur) return existsSync(parent) ? realpathSync(parent) : null;
    cur = parent;
  }
}

function isSafePathArg(cwd: string, arg: string): boolean {
  const resolved = resolvePath(cwd, arg);
  const real = nearestExistingRealpath(resolved);
  return !!real && pathUnderApprovedRoot(real);
}

function hasParentSegment(arg: string): boolean {
  return arg.replace(/\\/g, "/").split("/").includes("..");
}

function isAbsoluteOrParentPath(arg: string): boolean {
  return arg.startsWith("/") || /^[A-Za-z]:[\\/]/.test(arg) || arg.startsWith("\\\\") || arg.startsWith("~") || hasParentSegment(arg);
}

function isCwdSafe(cwd: string): boolean {
  // Resolve symbolic links + .. tokens so a request can't punch out
  // of $HOME with a relative `../../etc/passwd`.
  const real = realpathSync(cwd);
  return pathUnderApprovedRoot(real);
}

function validateCommonArgs(cmd: string[]): string | null {
  if (cmd.length > 64) return "too many args";
  for (const arg of cmd) {
    if (typeof arg !== "string" || arg.length === 0) return "invalid arg";
    if (arg.length > 2048) return "arg too long";
    if (/[\0\x01-\x08\x0e-\x1f\x7f]/.test(arg)) return "arg contains control characters";
  }
  return null;
}

function collectPathOperands(args: string[], valueOptions: ReadonlySet<string> = new Set()): string[] {
  const paths: string[] = [];
  let afterDoubleDash = false;
  let skipNext = false;
  for (const arg of args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (!afterDoubleDash && arg === "--") {
      afterDoubleDash = true;
      continue;
    }
    if (!afterDoubleDash && valueOptions.has(arg)) {
      skipNext = true;
      continue;
    }
    if (!afterDoubleDash && arg.startsWith("-")) continue;
    paths.push(arg);
  }
  return paths;
}

function validatePathOperands(cwd: string, args: string[]): string | null {
  for (const arg of args) {
    if (!isSafePathArg(cwd, arg)) return `path outside approved root: ${arg}`;
  }
  return null;
}

function validateAbsoluteAndParentArgs(cwd: string, args: string[]): string | null {
  for (const arg of args) {
    if (isAbsoluteOrParentPath(arg) && !isSafePathArg(cwd, arg)) return `path outside approved root: ${arg}`;
  }
  return null;
}

function validateFindArgs(cwd: string, args: string[]): string | null {
  const denied = new Set(["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls", "-fprint", "-fprintf"]);
  for (const arg of args) {
    if (denied.has(arg)) return `find option denied: ${arg}`;
  }
  const absoluteError = validateAbsoluteAndParentArgs(cwd, args);
  if (absoluteError) return absoluteError;
  const paths: string[] = [];
  for (const arg of args) {
    if (arg === "!" || arg === "(" || arg === ")" || arg.startsWith("-")) break;
    paths.push(arg);
  }
  return validatePathOperands(cwd, paths);
}

function validateGrepArgs(cwd: string, args: string[]): string | null {
  const absoluteError = validateAbsoluteAndParentArgs(cwd, args);
  if (absoluteError) return absoluteError;
  const paths: string[] = [];
  let afterDoubleDash = false;
  let patternSeen = false;
  let skipNext = false;
  for (const arg of args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (!afterDoubleDash && arg === "--") {
      afterDoubleDash = true;
      continue;
    }
    if (!afterDoubleDash && (arg === "-e" || arg === "--regexp")) {
      skipNext = true;
      patternSeen = true;
      continue;
    }
    if (!afterDoubleDash && (arg === "-f" || arg === "--file")) {
      skipNext = true;
      continue;
    }
    if (!afterDoubleDash && arg.startsWith("-")) continue;
    if (!patternSeen) {
      patternSeen = true;
      continue;
    }
    paths.push(arg);
  }
  return validatePathOperands(cwd, paths);
}

function validateRgArgs(cwd: string, args: string[]): string | null {
  const denied = new Set(["--pre", "--pre-glob", "--files-from", "--search-zip", "-z"]);
  for (const arg of args) {
    if (denied.has(arg) || arg.startsWith("--pre=") || arg.startsWith("--files-from=")) return `rg option denied: ${arg}`;
  }
  return validateGrepArgs(cwd, args);
}

function validateRestrictedArgs(bin: string, args: string[], cwd: string): string | null {
  if (DENIED_RESTRICTED_BINARIES.has(bin)) return `binary denied in restricted mode: ${bin}`;
  const commonError = validateCommonArgs([bin, ...args]);
  if (commonError) return commonError;
  if (bin === "find") return validateFindArgs(cwd, args);
  if (bin === "grep") return validateGrepArgs(cwd, args);
  if (bin === "rg") return validateRgArgs(cwd, args);
  if (FILE_READ_COMMANDS.has(bin)) {
    const absoluteError = validateAbsoluteAndParentArgs(cwd, args);
    if (absoluteError) return absoluteError;
    if (bin === "sort" && (args.includes("-o") || args.some((arg) => arg.startsWith("--output")))) return "sort output option denied";
    return validatePathOperands(cwd, collectPathOperands(args, new Set(["-n", "-c", "--lines", "--bytes", "-m", "-s", "-t", "-k"])));
  }
  if (INSPECTION_COMMANDS.has(bin)) return validateAbsoluteAndParentArgs(cwd, args);
  return `no restricted argument rule for: ${bin}`;
}

export async function runExec(req: ExecRequest, onChunk: StreamHandler): Promise<ExecResult> {
  return runExecInternal(req, onChunk);
}

export async function runRemoteExec(
  req: RemoteExecRequest,
  proofs: { verifiedApproval: VerifiedApprovalProof; consumedConsent: ConsumedConsentProof },
  onChunk: StreamHandler,
): Promise<ExecResult> {
  if (req.cwd !== undefined && req.cwd.trim().length === 0) {
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: "invalid cwd: whitespace-only" };
  }
  const cmdSha256 = sha256Json(req.cmd);
  const cwdSha256 = sha256Text(req.cwd ?? "");
  if (!isVerifiedApprovalProof(proofs.verifiedApproval)) {
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: "missing verified approval proof" };
  }
  if (!isConsumedConsentProof(proofs.consumedConsent)) {
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: "missing consumed consent proof" };
  }
  if (
    proofs.verifiedApproval.requestId !== req.requestId ||
    proofs.verifiedApproval.workspaceId !== req.workspaceId ||
    proofs.verifiedApproval.operatorId !== req.operatorId ||
    proofs.verifiedApproval.scope !== "exec:run" ||
    proofs.verifiedApproval.cmdSha256 !== cmdSha256 ||
    proofs.verifiedApproval.cwdSha256 !== cwdSha256 ||
    proofs.consumedConsent.requestId !== req.requestId ||
    proofs.consumedConsent.workspaceId !== req.workspaceId ||
    proofs.consumedConsent.operatorId !== req.operatorId ||
    proofs.consumedConsent.cmdSha256 !== cmdSha256 ||
    proofs.consumedConsent.cwdSha256 !== cwdSha256 ||
    proofs.consumedConsent.scope !== proofs.verifiedApproval.scope
  ) {
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: "remote proof scope mismatch" };
  }
  if (proofs.verifiedApproval.expiresAt <= Date.now()) {
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: "approval expired" };
  }

  return runExecInternal(
    {
      cmd: req.cmd,
      cwd: req.cwd,
      timeoutMs: req.timeoutMs,
      requestId: req.requestId,
      operator: req.operatorId,
      source: "ws",
    },
    onChunk,
  );
}

async function runExecInternal(
  req: InternalExecRequest,
  onChunk: StreamHandler,
): Promise<ExecResult> {
  const startedAt = Date.now();
  kvSet(EXEC_LAST_ACTIVE_KEY, String(startedAt));
  const cwd = req.cwd && req.cwd.trim() ? req.cwd : HOME;
  const mode = getAccessMode();
  const audit: Record<string, unknown> = {
    ts: new Date().toISOString(),
    request_id: req.requestId,
    operator: req.operator ?? "unknown",
    source: req.source,
    cmd: req.cmd,
    cwd,
    mode,
  };

  // Whitelist + sanity check BEFORE spawn so even a rejected request
  // shows up in the audit log.
  if (!Array.isArray(req.cmd) || req.cmd.length === 0) {
    audit.outcome = "rejected:empty_cmd";
    writeAudit(audit);
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: "empty cmd" };
  }
  const commonArgError = validateCommonArgs(req.cmd);
  if (commonArgError) {
    audit.outcome = `rejected:${commonArgError}`;
    writeAudit(audit);
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: commonArgError };
  }
  const bin = safeBasename(req.cmd[0]!);
  if (mode === "restricted" && !WHITELIST.has(bin)) {
    audit.outcome = `rejected:not_in_whitelist:${bin}`;
    writeAudit(audit);
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: `binary not in whitelist: ${bin}` };
  }
  if (!existsSync(cwd)) {
    audit.outcome = "rejected:cwd_missing";
    writeAudit(audit);
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: `cwd does not exist: ${cwd}` };
  }
  if (!isCwdSafe(cwd)) {
    audit.outcome = "rejected:cwd_outside_home";
    writeAudit(audit);
    return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: `cwd not under $HOME: ${cwd}` };
  }
  if (mode === "restricted") {
    const argError = validateRestrictedArgs(bin, req.cmd.slice(1), cwd);
    if (argError) {
      audit.outcome = `rejected:arg_policy:${argError}`;
      writeAudit(audit);
      return { ok: false, exitCode: null, wallTimeMs: 0, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: argError };
    }
  }

  const timeoutMs = Math.min(MAX_TIMEOUT_MS, Math.max(1_000, req.timeoutMs ?? DEFAULT_TIMEOUT_MS));
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let truncated = false;

  return new Promise<ExecResult>((resolve) => {
    if (req.source === "ws" && getRemoteAccessState() !== "active") {
      const wallTimeMs = Date.now() - startedAt;
      writeAudit({ ...audit, outcome: "rejected:remote_access_revoked", wall_time_ms: wallTimeMs });
      resolve({ ok: false, exitCode: null, wallTimeMs, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: "remote access revoked" });
      return;
    }

    audit.outcome = "started";
    writeAudit(audit);

    let child: RemoteChild;
    try {
      child = spawn(req.cmd[0]!, req.cmd.slice(1), {
        cwd,
        env: process.env,
        stdio: ["ignore", "pipe", "pipe"],
        detached: req.source === "ws" && process.platform !== "win32",
      });
    } catch (err) {
      const wallTimeMs = Date.now() - startedAt;
      writeAudit({ ...audit, outcome: "spawn_failed", error: String(err), wall_time_ms: wallTimeMs });
      resolve({ ok: false, exitCode: null, wallTimeMs, stdoutBytes: 0, stderrBytes: 0, truncated: false, reason: `spawn failed: ${err}` });
      return;
    }

    if (req.source === "ws") registerActiveRemoteChild(child);

    const killTimer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch { /* ignored */ }
    }, timeoutMs);

    child.stdout?.setEncoding("utf-8");
    child.stderr?.setEncoding("utf-8");

    child.stdout?.on("data", (chunk: string) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        if (!truncated) {
          truncated = true;
          onChunk("stderr", "\n[exec] output truncated at 1 MB cap\n");
          try { child.kill("SIGTERM"); } catch { /* ignored */ }
        }
        return;
      }
      onChunk("stdout", chunk);
    });
    child.stderr?.on("data", (chunk: string) => {
      stderrBytes += chunk.length;
      onChunk("stderr", chunk);
    });

    child.on("error", (err) => {
      clearTimeout(killTimer);
      if (req.source === "ws") activeRemoteChildren.delete(child);
      const wallTimeMs = Date.now() - startedAt;
      writeAudit({ ...audit, outcome: "child_error", error: String(err), wall_time_ms: wallTimeMs });
      resolve({ ok: false, exitCode: null, wallTimeMs, stdoutBytes, stderrBytes, truncated, reason: String(err) });
    });

    child.on("close", (exitCode) => {
      clearTimeout(killTimer);
      if (req.source === "ws") activeRemoteChildren.delete(child);
      const wallTimeMs = Date.now() - startedAt;
      writeAudit({ ...audit, outcome: "completed", exit_code: exitCode, wall_time_ms: wallTimeMs, stdout_bytes: stdoutBytes, stderr_bytes: stderrBytes, truncated });
      resolve({ ok: exitCode === 0, exitCode, wallTimeMs, stdoutBytes, stderrBytes, truncated });
    });
  });
}

export function whitelist(): string[] {
  return Array.from(WHITELIST).sort();
}

export function auditLogPath(): string {
  return AUDIT_PATH;
}
