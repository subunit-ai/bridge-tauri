/**
 * /exec routes — local self-test surface for the Remote-Exec runner.
 *
 * - GET  /exec/status — whitelist + audit-log path + is-ws-connected
 * - POST /exec/local — synchronously run a whitelisted command and
 *   return the full stdout/stderr/exit. Local-only auth (Bearer that
 *   matches the bridge's local API token). Useful so the CLI can
 *   verify a command works before triggering it remotely.
 *
 * Remote exec from api.subunit.ai arrives over the WebSocket, NOT
 * this HTTP route — see sync/ws-client.ts.
 */
import { Hono } from "hono";
import { z } from "zod";

import { auditLogPath, runExec, whitelist } from "../exec/runner.ts";

export const execRoutes = new Hono();

const LocalExecSchema = z.object({
  cmd: z.array(z.string().min(1)).min(1).max(64),
  cwd: z.string().max(512).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
});

execRoutes.get("/status", (c) => {
  return c.json({
    whitelist: whitelist(),
    audit_log: auditLogPath(),
  });
});

execRoutes.post("/local", async (c) => {
  // Local-token-gated self-test only. Remote WS exec cannot enter here
  // and must pass Ed25519 approval plus local consent in ws-client.ts.
  const body = LocalExecSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) {
    return c.json({ error: "invalid_request", issues: body.error.issues }, 400);
  }
  const requestId = `local-${Date.now()}`;
  let stdout = "";
  let stderr = "";
  const result = await runExec(
    {
      cmd: body.data.cmd,
      cwd: body.data.cwd,
      timeoutMs: body.data.timeout_ms,
      requestId,
      operator: "local-self-test",
      source: "local",
    },
    (stream, data) => {
      if (stream === "stdout") stdout += data;
      else stderr += data;
    },
  );
  return c.json({
    request_id: requestId,
    ok: result.ok,
    exit_code: result.exitCode,
    wall_time_ms: result.wallTimeMs,
    stdout,
    stderr,
    truncated: result.truncated,
    reason: result.reason ?? null,
  });
});
