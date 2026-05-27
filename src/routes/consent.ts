import { Hono } from "hono";
import { z } from "zod";

import {
  decide,
  getConsentRequest,
  getRemoteAccessState,
  getSessionGrant,
  lastExecActiveAt,
  listPendingConsentRequests,
  pendingConsentCount,
  setRemoteAccess,
  setSessionGrantForConsent,
} from "../exec/consent.ts";
import { killActiveRemoteExecChildren } from "../exec/runner.ts";
import { ensureFreshAccessToken } from "../sync/auth-client.ts";
import { disconnectWsClient } from "../sync/ws-client.ts";

export const consentRoutes = new Hono();

const AllowSchema = z.object({
  remember_for_seconds: z.number().int().min(1).max(30 * 60).optional(),
});

async function activeWorkspace(): Promise<{ ok: true; workspaceId: string } | { ok: false; status: 400 | 401; body: Record<string, unknown> }> {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return { ok: false, status: 401, body: { error: "not_paired" } };
  if (!tokens.active_workspace_id) return { ok: false, status: 400, body: { error: "no_active_workspace" } };
  return { ok: true, workspaceId: tokens.active_workspace_id };
}

consentRoutes.get("/pending", async (c) => {
  const ws = await activeWorkspace();
  if (!ws.ok) return c.json(ws.body, ws.status);
  return c.json({ pending: listPendingConsentRequests(ws.workspaceId) });
});

consentRoutes.post("/:id/allow", async (c) => {
  const ws = await activeWorkspace();
  if (!ws.ok) return c.json(ws.body, ws.status);
  const id = c.req.param("id");
  const body = AllowSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request", issues: body.error.issues }, 400);

  const row = getConsentRequest(id, ws.workspaceId);
  if (!row) return c.json({ error: "not_found" }, 404);
  const result = decide(id, "allowed", "local_allow");
  if (!result.ok) return c.json({ error: "not_pending", status: result.status, reason: result.reason ?? null }, 409);

  const grant = body.data.remember_for_seconds
    ? setSessionGrantForConsent(id, body.data.remember_for_seconds)
    : null;
  return c.json({ ok: true, session_grant: grant });
});

consentRoutes.post("/:id/deny", async (c) => {
  const ws = await activeWorkspace();
  if (!ws.ok) return c.json(ws.body, ws.status);
  const id = c.req.param("id");
  const row = getConsentRequest(id, ws.workspaceId);
  if (!row) return c.json({ error: "not_found" }, 404);
  const result = decide(id, "denied", "local_deny");
  if (!result.ok) return c.json({ error: "not_pending", status: result.status, reason: result.reason ?? null }, 409);
  return c.json({ ok: true });
});

consentRoutes.post("/revoke", (c) => {
  setRemoteAccess("revoked");
  disconnectWsClient("remote_access_revoked");
  killActiveRemoteExecChildren("remote_access_revoked");
  return c.json({ ok: true, remote_access: getRemoteAccessState() });
});

consentRoutes.post("/resume", (c) => {
  setRemoteAccess("active");
  return c.json({ ok: true, remote_access: getRemoteAccessState() });
});

consentRoutes.get("/state", async (c) => {
  const ws = await activeWorkspace();
  if (!ws.ok) return c.json(ws.body, ws.status);
  return c.json({
    remote_access: getRemoteAccessState(),
    session_grant: getSessionGrant(),
    pending_count: pendingConsentCount(ws.workspaceId),
    last_session_active_at: lastExecActiveAt(),
  });
});
