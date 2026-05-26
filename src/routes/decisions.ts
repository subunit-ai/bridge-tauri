import { Hono } from "hono";
import { z } from "zod";
import { db } from "../storage/db.ts";
import { randomUUID } from "node:crypto";
import { ensureFreshAccessToken } from "../sync/auth-client.ts";

export const decisionRoutes = new Hono();

interface DecisionRow {
  id: string;
  workspace_id: string;
  status: string;
  payload: string;
  source: string | null;
  created_at: number;
  resolved_at: number | null;
  synced_at: number | null;
}

decisionRoutes.get("/pending", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ decisions: [] });
  const rows = db
    .query<DecisionRow, [string]>(
      "SELECT * FROM decisions WHERE workspace_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 200",
    )
    .all(ws);
  return c.json({
    decisions: rows.map((r) => ({
      id: r.id,
      workspace_id: r.workspace_id,
      status: r.status,
      source: r.source,
      created_at: r.created_at,
      synced_at: r.synced_at,
      payload: JSON.parse(r.payload),
    })),
  });
});

const CreateSchema = z.object({
  title: z.string().min(1).max(500),
  body: z.string().max(8000).optional(),
  source: z.string().max(60).optional(),
  metadata: z.record(z.unknown()).optional(),
});

decisionRoutes.post("/", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ error: "no_active_workspace" }, 400);
  const body = CreateSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request", details: body.error.flatten() }, 400);

  const id = randomUUID();
  const payload = JSON.stringify({
    title: body.data.title,
    body: body.data.body ?? null,
    metadata: body.data.metadata ?? {},
  });
  db.run(
    "INSERT INTO decisions (id, workspace_id, status, payload, source) VALUES (?, ?, 'pending', ?, ?)",
    [id, ws, payload, body.data.source ?? null],
  );
  // Queue for server sync
  db.run(
    "INSERT INTO outbox (kind, payload) VALUES ('decision.create', ?)",
    [JSON.stringify({ local_id: id, workspace_id: ws, payload: JSON.parse(payload), source: body.data.source ?? null })],
  );
  return c.json({ ok: true, id });
});

const ApproveSchema = z.object({
  note: z.string().max(2000).optional(),
});

decisionRoutes.post("/:id/approve", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ error: "no_active_workspace" }, 400);
  const id = c.req.param("id");
  const body = ApproveSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request" }, 400);

  const row = db.query<DecisionRow, [string, string]>("SELECT * FROM decisions WHERE id = ? AND workspace_id = ?").get(id, ws);
  if (!row) return c.json({ error: "not_found" }, 404);
  db.run("UPDATE decisions SET status = 'approved', resolved_at = unixepoch() WHERE id = ? AND workspace_id = ?", [id, ws]);
  db.run(
    "INSERT INTO outbox (kind, payload) VALUES ('decision.approve', ?)",
    [JSON.stringify({ local_id: id, workspace_id: ws, note: body.data.note ?? null })],
  );
  return c.json({ ok: true });
});

decisionRoutes.post("/:id/reject", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ error: "no_active_workspace" }, 400);
  const id = c.req.param("id");
  const row = db.query<DecisionRow, [string, string]>("SELECT * FROM decisions WHERE id = ? AND workspace_id = ?").get(id, ws);
  if (!row) return c.json({ error: "not_found" }, 404);
  db.run("UPDATE decisions SET status = 'rejected', resolved_at = unixepoch() WHERE id = ? AND workspace_id = ?", [id, ws]);
  db.run(
    "INSERT INTO outbox (kind, payload) VALUES ('decision.reject', ?)",
    [JSON.stringify({ local_id: id, workspace_id: ws })],
  );
  return c.json({ ok: true });
});
