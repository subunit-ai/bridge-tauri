import { Hono, type Context } from "hono";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { db } from "../storage/db.ts";
import { loginWithPassword, ensureFreshAccessToken, logout, fetchMe } from "../sync/auth-client.ts";
import { disconnectWsClient } from "../sync/ws-client.ts";
import { loadTokens, saveTokens, setOperatorAttestation, type StoredTokens } from "../storage/tokens.ts";
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
    // JSON-Payloads ("access_token":"…") maskieren — /auth/adopt konsumiert JSON, ein Fehler der
    // den Body stringifiziert würde sonst Tokens im Klartext loggen. Feldliste deckt auch
    // id_token/client_secret ab. (Codex P2-8 / Gemini P2 / ReReview P2)
    .replace(/"(access_token|refresh_token|id_token|client_secret|password)"\s*:\s*"[^"]*"/g, '"$1":"[redacted]"')
    .replace(/(access_token|refresh_token|id_token|client_secret|password)=\S+/g, "$1=[redacted]")
    .slice(0, 500);
}

// Liest den exp-Claim (Sekunden seit Epoch) aus einem JWT. Die Token-Lebensdauer wird IMMER
// hieraus abgeleitet statt aus dem client-gelieferten expires_in — sonst könnte ein lokaler
// Aufrufer mit einem riesigen Wert den proaktiven Refresh unterdrücken (oder mit 0 einen
// Refresh-Loop erzwingen). Gibt 0 zurück, wenn kein dekodierbares exp vorliegt. (Codex P2-7 / Gemini P2)
function accessTokenExpiry(token: string): number {
  try {
    const payload = token.split(".")[1];
    if (!payload) return 0;
    const json = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { exp?: number };
    if (typeof json.exp === "number" && json.exp > 0) return json.exp;
  } catch {
    /* kein dekodierbares JWT → Fallback durch Aufrufer */
  }
  return 0;
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

// POST /auth/adopt — Sonar übergibt sein OAuth-Token (Browser-Login) an die Bridge, damit sie
// pairt + sich mit dem Server verbindet. Token-basierte Alternative zum Passwort-Pairing.
// Lokal-token-gated (globale Middleware). Das Token wird gegen /auth/me VALIDIERT (gefälschte/
// abgelaufene Tokens scheitern), bevor es gespeichert wird — kanonische Claims kommen vom Server.
const AdoptSchema = z.object({
  access_token: z.string().min(10).max(8192),
  refresh_token: z.string().min(10).max(8192),
  // expires_in wird BEWUSST nicht akzeptiert — die Lebensdauer kommt aus dem JWT-exp
  // (accessTokenExpiry), nicht aus dem manipulierbaren Body. Ein evtl. mitgesendetes Feld ignoriert zod.
  active_workspace_id: z.string().max(128).optional(),
  device_label: z.string().max(120).optional(),
});

authRoutes.post("/adopt", async (c) => {
  const body = AdoptSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request" }, 400);
  try {
    const me = await fetchMe(body.data.access_token); // validiert das Token + holt kanonische Claims

    // Identity-Pinning: ist die Bridge bereits an einen User gekoppelt, NICHT stillschweigend auf
    // einen anderen Account umschalten — ein lokaler Token-Halter könnte sonst die Bridge-Identität
    // austauschen (auch auf einen Operator). Account-Wechsel erfordert explizites /auth/logout. (Codex P1-2)
    const existing = loadTokens();
    if (existing && existing.user_id !== me.user.id) {
      return c.json({ error: "identity_mismatch", paired_user: existing.user_id }, 409);
    }

    // active_workspace_id ist client-geliefert → nur übernehmen, wenn der User laut Server (kanonisch)
    // dort Mitglied ist; sonst Server-Default (null). Verhindert lokale Workspace-Poisoning. (Codex P1-4 / Gemini P2)
    const requestedWs = body.data.active_workspace_id ?? null;
    const activeWorkspaceId = requestedWs && me.workspaces.some((w) => w.id === requestedWs) ? requestedWs : null;

    // Lebensdauer aus dem JWT-exp ableiten (nicht aus dem Request-Body); Fallback 1h. (Codex P2-7 / Gemini P2)
    const expFromJwt = accessTokenExpiry(body.data.access_token);
    const accessExpiresAt = expFromJwt > 0 ? expFromJwt : Math.floor(Date.now() / 1000) + 3600;

    const stored: StoredTokens = {
      user_id: me.user.id,
      email: me.user.email,
      access_token: body.data.access_token,
      refresh_token: body.data.refresh_token,
      access_expires_at: accessExpiresAt,
      active_workspace_id: activeWorkspaceId,
      is_operator: me.user.is_operator,
      operator_attested_at: me.user.is_operator ? Math.floor(Date.now() / 1000) : 0,
      device_label: body.data.device_label ?? "sonar",
    };
    saveTokens(stored);
    return c.json({
      ok: true,
      paired: true,
      user_id: stored.user_id,
      email: stored.email,
      is_operator: stored.is_operator,
      active_workspace_id: stored.active_workspace_id,
    });
  } catch (err) {
    console.error("[adopt] failed:", redactError(err));
    return c.json({ error: "adopt_failed" }, 401);
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
    // Server-frischer Operator-Status → persistieren (treibt den Operator-Bypass-Freshness-Check).
    setOperatorAttestation(me.user.is_operator);
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
