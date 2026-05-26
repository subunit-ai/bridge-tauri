import { Hono } from "hono";
import { z } from "zod";
import { db } from "../storage/db.ts";
import { randomUUID } from "node:crypto";
import { ensureFreshAccessToken } from "../sync/auth-client.ts";

export const taskRoutes = new Hono();

interface TaskRow {
  id: string;
  workspace_id: string;
  title: string;
  status: string;
  payload: string | null;
  created_at: number;
  updated_at: number;
  synced_at: number | null;
}

taskRoutes.get("/", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ tasks: [] });
  const status = c.req.query("status") ?? "pending";
  const rows = db
    .query<TaskRow, [string, string]>(
      "SELECT * FROM tasks WHERE workspace_id = ? AND status = ? ORDER BY created_at DESC LIMIT 500",
    )
    .all(ws, status);
  return c.json({
    tasks: rows.map((r) => ({
      id: r.id,
      title: r.title,
      status: r.status,
      created_at: r.created_at,
      updated_at: r.updated_at,
      synced_at: r.synced_at,
      payload: r.payload ? JSON.parse(r.payload) : null,
    })),
  });
});

const CreateSchema = z.object({
  title: z.string().min(1).max(500),
  metadata: z.record(z.unknown()).optional(),
});

taskRoutes.post("/", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ error: "no_active_workspace" }, 400);
  const body = CreateSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request", details: body.error.flatten() }, 400);

  const id = randomUUID();
  const payload = body.data.metadata ? JSON.stringify(body.data.metadata) : null;
  db.run("INSERT INTO tasks (id, workspace_id, title, payload) VALUES (?, ?, ?, ?)", [id, ws, body.data.title, payload]);
  db.run(
    "INSERT INTO outbox (kind, payload) VALUES ('task.create', ?)",
    [JSON.stringify({ local_id: id, workspace_id: ws, title: body.data.title, metadata: body.data.metadata ?? {} })],
  );
  return c.json({ ok: true, id });
});

const StatusSchema = z.object({
  status: z.enum(["pending", "in_progress", "completed", "cancelled"]),
});

taskRoutes.patch("/:id/status", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ error: "no_active_workspace" }, 400);
  const id = c.req.param("id");
  const body = StatusSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request" }, 400);
  const row = db.query<TaskRow, [string, string]>("SELECT * FROM tasks WHERE id = ? AND workspace_id = ?").get(id, ws);
  if (!row) return c.json({ error: "not_found" }, 404);
  db.run("UPDATE tasks SET status = ?, updated_at = unixepoch() WHERE id = ? AND workspace_id = ?", [body.data.status, id, ws]);
  db.run(
    "INSERT INTO outbox (kind, payload) VALUES ('task.update', ?)",
    [JSON.stringify({ local_id: id, workspace_id: ws, status: body.data.status })],
  );
  return c.json({ ok: true });
});
