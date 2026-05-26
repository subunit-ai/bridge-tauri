import { Hono, type Context } from "hono";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { db } from "../storage/db.ts";
import { loginWithPassword, ensureFreshAccessToken, logout, fetchMe } from "../sync/auth-client.ts";
import { disconnectWsClient } from "../sync/ws-client.ts";
import { loadTokens } from "../storage/tokens.ts";
import { getAccessMode, setAccessMode } from "../exec/access-mode.ts";

export const authRoutes = new Hono();

const PAIR_STATE_TTL_SECONDS = 5 * 60;
const PAIR_RATE_LIMIT_WINDOW_SECONDS = 10 * 60;
const PAIR_RATE_LIMIT_MAX = 5;

const PairSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(200),
  device_label: z.string().min(1).max(120).optional(),
  state: z.string().min(32).max(160).optional(),
  pair_state: z.string().min(32).max(160).optional(),
  // Optional: caller opts into full-access exec at pair time. Default
  // is restricted (read-only whitelist). Only flip to "full" on
  // machines you own and trust — typically internal team workstations.
  access_mode: z.enum(["restricted", "full"]).optional(),
}).refine((body) => !!(body.state ?? body.pair_state), {
  path: ["state"],
  message: "pair state required",
});

interface PairAttemptRow {
  state: string;
  code_verifier: string;
  created_at: number;
  consumed_at: number | null;
}

function clientAddress(c: Context): string {
  return c.req.header("x-bridge-remote-addr") ?? "unknown";
}

function digestPart(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 32);
}

function cleanupPairAttempts(): void {
  db.run("DELETE FROM pair_attempts WHERE created_at < unixepoch() - ?", [24 * 60 * 60]);
}

function createPairState(ip: string): { state: string; expiresAt: number } {
  cleanupPairAttempts();
  const state = randomBytes(32).toString("base64url");
  const expiresAt = Math.floor(Date.now() / 1000) + PAIR_STATE_TTL_SECONDS;
  db.run(
    "INSERT INTO pair_attempts (state, code_verifier) VALUES (?, ?)",
    [state, JSON.stringify({ purpose: "pair", ip_hash: digestPart(ip) })],
  );
  return { state, expiresAt };
}

function consumePairState(state: string, ip: string): boolean {
  const row = db.query<PairAttemptRow, [string]>("SELECT * FROM pair_attempts WHERE state = ?").get(state);
  if (!row || row.consumed_at !== null) return false;
  if (row.created_at + PAIR_STATE_TTL_SECONDS < Math.floor(Date.now() / 1000)) return false;
  let meta: { purpose?: string; ip_hash?: string };
  try {
    meta = JSON.parse(row.code_verifier) as { purpose?: string; ip_hash?: string };
  } catch {
    return false;
  }
  if (meta.purpose !== "pair" || meta.ip_hash !== digestPart(ip)) return false;
  db.run("UPDATE pair_attempts SET consumed_at = unixepoch() WHERE state = ? AND consumed_at IS NULL", [state]);
  return true;
}

function pairRatePrefix(ip: string, email: string): string {
  return `rate:${digestPart(ip)}:${digestPart(email.toLowerCase())}:`;
}

function pairRateLimited(ip: string, email: string): boolean {
  const prefix = pairRatePrefix(ip, email);
  const row = db
    .query<{ n: number }, [string, number]>(
      "SELECT COUNT(*) AS n FROM pair_attempts WHERE state LIKE ? AND created_at >= unixepoch() - ?",
    )
    .get(`${prefix}%`, PAIR_RATE_LIMIT_WINDOW_SECONDS);
  return (row?.n ?? 0) >= PAIR_RATE_LIMIT_MAX;
}

function recordPairAttempt(ip: string, email: string): void {
  const state = `${pairRatePrefix(ip, email)}${randomBytes(8).toString("hex")}`;
  db.run("INSERT INTO pair_attempts (state, code_verifier) VALUES (?, ?)", [state, "rate"]);
}

function redactError(err: unknown): string {
  return String(err)
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, "Bearer [redacted]")
    .replace(/(access_token|refresh_token|password)=\S+/g, "$1=[redacted]")
    .slice(0, 500);
}

authRoutes.post("/pair/start", (c) => {
  const { state, expiresAt } = createPairState(clientAddress(c));
  return c.json({ state, expires_at: expiresAt });
});

authRoutes.post("/pair", async (c) => {
  const body = PairSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request" }, 400);
  const ip = clientAddress(c);
  if (pairRateLimited(ip, body.data.email)) return c.json({ error: "rate_limited" }, 429);
  recordPairAttempt(ip, body.data.email);
  const pairState = body.data.state ?? body.data.pair_state ?? "";
  if (!consumePairState(pairState, ip)) return c.json({ error: "invalid_pair_state" }, 400);
  try {
    const tokens = await loginWithPassword(body.data.email, body.data.password, body.data.device_label);
    if (body.data.access_mode) setAccessMode(body.data.access_mode);
    return c.json({
      ok: true,
      paired: true,
      user_id: tokens.user_id,
      email: tokens.email,
      active_workspace_id: tokens.active_workspace_id,
      is_operator: tokens.is_operator,
      access_mode: getAccessMode(),
    });
  } catch (err) {
    console.error("[pair] failed:", redactError(err));
    return c.json({ error: "pair_failed" }, 401);
  }
});

// POST /auth/access — flip access mode without re-pairing. Trusted users
// can do this anytime via the local pair UI; safe-default is restricted.
const AccessSchema = z.object({
  access_mode: z.enum(["restricted", "full"]),
});
authRoutes.post("/access", async (c) => {
  const body = AccessSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request" }, 400);
  setAccessMode(body.data.access_mode);
  return c.json({ ok: true, access_mode: getAccessMode() });
});

authRoutes.post("/logout", async (c) => {
  await logout();
  // Drop the live WebSocket immediately — otherwise the old workspace
  // continues to receive push events until the access token expires.
  disconnectWsClient();
  return c.json({ ok: true });
});

authRoutes.get("/me", async (c) => {
  const fresh = await ensureFreshAccessToken();
  if (!fresh) return c.json({ error: "not_paired" }, 401);
  try {
    const me = await fetchMe(fresh.access_token);
    return c.json(me);
  } catch (err) {
    console.error("[auth/me] upstream failed:", redactError(err));
    return c.json({ error: "upstream_failed" }, 502);
  }
});

authRoutes.get("/status", (c) => {
  const tokens = loadTokens();
  if (!tokens) return c.json({ paired: false, access_mode: getAccessMode() });
  return c.json({
    paired: true,
    user_id: tokens.user_id,
    email: tokens.email,
    active_workspace_id: tokens.active_workspace_id,
    is_operator: tokens.is_operator,
    device_label: tokens.device_label,
    access_expires_at: tokens.access_expires_at,
    access_expires_in_seconds: tokens.access_expires_at - Math.floor(Date.now() / 1000),
    access_mode: getAccessMode(),
  });
});
