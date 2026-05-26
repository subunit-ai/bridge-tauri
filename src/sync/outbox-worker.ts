/**
 * Outbox Worker
 *
 * Background interval that picks up pending outbox entries and pushes them to
 * api.subunit.ai/sync/outbox. Marks delivered_at on success. Retries with
 * exponential backoff on failure (max 1h between attempts).
 */
import { db } from "../storage/db.ts";
import { ensureFreshAccessToken } from "./auth-client.ts";
import { config } from "../config.ts";

const POLL_INTERVAL_MS = 15_000;
const BATCH_SIZE = 50;
const MAX_BACKOFF_SECONDS = 3600;

interface OutboxRow {
  id: number;
  kind: string;
  payload: string;
  attempts: number;
  next_attempt_at: number;
  created_at: number;
  delivered_at: number | null;
}

interface DispatchResult {
  outbox_id: number;
  status: "ok" | "duplicate" | "error";
  server_id?: string;
  error?: string;
}

interface OutboxWorkerHandle {
  stop(): void;
  trigger(): Promise<void>; // immediate one-shot for tests
}

export function startOutboxWorker(): OutboxWorkerHandle {
  let running = true;
  let inFlight = false;

  async function tick(): Promise<void> {
    if (!running || inFlight) return;
    inFlight = true;
    try {
      await pushBatch();
    } catch (err) {
      console.error("[outbox-worker] tick failed:", err);
    } finally {
      inFlight = false;
    }
  }

  const handle: OutboxWorkerHandle = {
    stop() {
      running = false;
      clearInterval(timer);
    },
    async trigger() {
      await tick();
    },
  };

  // First tick after a short delay (let main HTTP server come up first).
  setTimeout(() => { void tick(); }, 1000);
  const timer = setInterval(() => { void tick(); }, POLL_INTERVAL_MS);

  console.log(`[outbox-worker] started, polling every ${POLL_INTERVAL_MS / 1000}s, batch=${BATCH_SIZE}`);
  return handle;
}

async function pushBatch(): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const rows = db
    .query<OutboxRow, [number, number]>(
      "SELECT * FROM outbox WHERE delivered_at IS NULL AND next_attempt_at <= ? ORDER BY id LIMIT ?",
    )
    .all(now, BATCH_SIZE);

  if (rows.length === 0) return;

  const tokens = await ensureFreshAccessToken();
  if (!tokens) {
    // No paired user — keep entries queued without bumping attempts.
    console.log(`[outbox-worker] ${rows.length} entries waiting but daemon not paired`);
    return;
  }

  console.log(`[outbox-worker] pushing ${rows.length} entries`);

  const entries = rows.map((r) => ({
    id: r.id,
    kind: r.kind,
    payload: JSON.parse(r.payload),
    attempts: r.attempts,
  }));

  let response: Response;
  try {
    response = await fetch(`${config.apiBaseUrl}/sync/outbox`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({ client_id: config.clientId, entries }),
    });
  } catch (err) {
    // Network-level failure — backoff entire batch, do not increment attempts past first
    backoffAll(rows, `network: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  if (!response.ok) {
    const text = await response.text().catch(() => "<no body>");
    backoffAll(rows, `http ${response.status}: ${text.slice(0, 200)}`);
    return;
  }

  const result = (await response.json().catch(() => null)) as { results?: DispatchResult[] } | null;
  if (!result?.results) {
    backoffAll(rows, "malformed response");
    return;
  }

  const resultById = new Map(result.results.map((r) => [r.outbox_id, r]));

  const markDelivered = db.transaction((ids: number[]) => {
    for (const id of ids) {
      db.run("UPDATE outbox SET delivered_at = unixepoch() WHERE id = ?", [id]);
    }
  });
  const markFailure = db.transaction((failures: Array<{ id: number; attempts: number; nextAt: number }>) => {
    for (const f of failures) {
      db.run(
        "UPDATE outbox SET attempts = ?, next_attempt_at = ? WHERE id = ?",
        [f.attempts, f.nextAt, f.id],
      );
    }
  });

  const delivered: number[] = [];
  const failed: Array<{ id: number; attempts: number; nextAt: number }> = [];

  for (const row of rows) {
    const r = resultById.get(row.id);
    if (!r) {
      // Server didn't include this id — treat as failure
      const attempts = row.attempts + 1;
      failed.push({ id: row.id, attempts, nextAt: backoffSeconds(attempts) + Math.floor(Date.now() / 1000) });
      continue;
    }
    if (r.status === "ok" || r.status === "duplicate") {
      delivered.push(row.id);
    } else {
      const attempts = row.attempts + 1;
      failed.push({ id: row.id, attempts, nextAt: backoffSeconds(attempts) + Math.floor(Date.now() / 1000) });
      console.warn(`[outbox-worker] entry ${row.id} (${row.kind}) failed: ${r.error}`);
    }
  }

  if (delivered.length > 0) markDelivered(delivered);
  if (failed.length > 0) markFailure(failed);

  console.log(`[outbox-worker] delivered=${delivered.length}, failed=${failed.length}`);
}

function backoffSeconds(attempts: number): number {
  // 2^n, capped at MAX_BACKOFF_SECONDS
  const n = Math.min(attempts, 12);
  const base = Math.pow(2, n);
  const jitter = Math.floor(Math.random() * Math.min(30, base / 4));
  return Math.min(MAX_BACKOFF_SECONDS, base + jitter);
}

function backoffAll(rows: OutboxRow[], reason: string): void {
  console.warn(`[outbox-worker] batch failed (${reason}), backing off ${rows.length} entries`);
  const tx = db.transaction((rows: OutboxRow[]) => {
    const now = Math.floor(Date.now() / 1000);
    for (const r of rows) {
      const attempts = r.attempts + 1;
      const nextAt = now + backoffSeconds(attempts);
      db.run(
        "UPDATE outbox SET attempts = ?, next_attempt_at = ? WHERE id = ?",
        [attempts, nextAt, r.id],
      );
    }
  });
  tx(rows);
}
