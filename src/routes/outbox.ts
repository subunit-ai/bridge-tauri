import { Hono } from "hono";
import { db } from "../storage/db.ts";

export const outboxRoutes = new Hono();

interface OutboxRow {
  id: number;
  kind: string;
  payload: string;
  attempts: number;
  next_attempt_at: number;
  created_at: number;
  delivered_at: number | null;
}

outboxRoutes.get("/", (c) => {
  const rawLimit = c.req.query("limit") ?? "100";
  if (!/^\d+$/.test(rawLimit)) return c.json({ error: "invalid_request" }, 400);
  const limit = Number(rawLimit);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) return c.json({ error: "invalid_request" }, 400);
  const status = c.req.query("status") ?? "pending";
  if (status !== "pending" && status !== "delivered") return c.json({ error: "invalid_request" }, 400);
  const where = status === "delivered" ? "delivered_at IS NOT NULL" : "delivered_at IS NULL";
  const rows = db
    .query<OutboxRow, [number]>(`SELECT * FROM outbox WHERE ${where} ORDER BY created_at DESC LIMIT ?`)
    .all(limit);
  return c.json({
    outbox: rows.map((r) => ({
      id: r.id,
      kind: r.kind,
      attempts: r.attempts,
      created_at: r.created_at,
      delivered_at: r.delivered_at,
      next_attempt_at: r.next_attempt_at,
      payload: JSON.parse(r.payload),
    })),
  });
});

outboxRoutes.get("/stats", (c) => {
  const pending = db.query<{ n: number }, []>(
    "SELECT COUNT(*) AS n FROM outbox WHERE delivered_at IS NULL",
  ).get();
  const delivered = db.query<{ n: number }, []>(
    "SELECT COUNT(*) AS n FROM outbox WHERE delivered_at IS NOT NULL",
  ).get();
  return c.json({
    pending: pending?.n ?? 0,
    delivered: delivered?.n ?? 0,
  });
});
