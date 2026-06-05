import { Hono } from "hono";
import { z } from "zod";
import { db } from "../storage/db.ts";
import { ensureFreshAccessToken } from "../sync/auth-client.ts";

export const activityRoutes = new Hono();

// Trace-/Process-Mining-Batch (Outbox-Kind `activity.batch`). Vertrag:
// trace-tauri/docs/MINING-PIPELINE.md Abschnitt 5. Der Batch wird von der Trace-Engine
// in sonar-tauri erzeugt und ist BEREITS redacted (Masking lokal, vor Persistenz).
// Hier nur die Hülle validieren + als Outbox-Eintrag weiterreichen — die tiefe
// Event-Validierung passiert serverseitig (subunit-api, P3).
const BatchSchema = z.object({
  batch_local_id: z.string().min(1),
  device_id: z.string().min(1),
  os: z.string().min(1),
  schema_version: z.number().int(),
  sessions: z.array(z.unknown()).max(1000),
  events: z.array(z.unknown()).max(10000),
});

activityRoutes.post("/", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const ws = tokens.active_workspace_id;
  if (!ws) return c.json({ error: "no_active_workspace" }, 400);

  const body = BatchSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) {
    return c.json({ error: "invalid_request", details: body.error.flatten() }, 400);
  }

  // Leere Batches gar nicht erst einreihen.
  if (body.data.events.length === 0) return c.json({ ok: true, enqueued: 0 });

  db.run("INSERT INTO outbox (kind, payload) VALUES ('activity.batch', ?)", [
    JSON.stringify({ workspace_id: ws, ...body.data }),
  ]);
  return c.json({ ok: true, enqueued: body.data.events.length });
});
