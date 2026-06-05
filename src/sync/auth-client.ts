import { config } from "../config.ts";
import { loadTokens, saveTokens, touchAccessExpiry, clearTokens, setOperatorAttestation, type StoredTokens } from "../storage/tokens.ts";

interface LoginResponse {
  ok: true;
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  session_id: string;
  active_workspace_id: string | null;
}

interface RefreshResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
}

interface MeResponse {
  user: {
    id: string;
    email: string;
    display_name: string | null;
    is_operator: boolean;
  };
  workspaces: Array<{ id: string; slug: string; name: string; kind: string; tier: string; role: string }>;
}

function redactForLog(value: string): string {
  return value
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, "Bearer [redacted]")
    .replace(/"(access_token|refresh_token|id_token|client_secret|password)"\s*:\s*"[^"]*"/g, "\"$1\":\"[redacted]\"")
    .slice(0, 500);
}

export async function loginWithPassword(email: string, password: string, deviceLabel?: string): Promise<StoredTokens> {
  const res = await fetch(`${config.authBaseUrl}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-client-id": config.clientId },
    body: JSON.stringify({ email, password, client_id: config.clientId, device_label: deviceLabel ?? null }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    console.error(`[auth-client] login failed status=${res.status} body=${redactForLog(text)}`);
    throw new Error(`auth_login_failed:${res.status}`);
  }
  const data = (await res.json()) as LoginResponse;
  const me = await fetchMe(data.access_token);
  const stored: StoredTokens = {
    user_id: me.user.id,
    email: me.user.email,
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    access_expires_at: Math.floor(Date.now() / 1000) + data.expires_in,
    active_workspace_id: data.active_workspace_id,
    is_operator: me.user.is_operator,
    // is_operator kommt frisch aus /auth/me → jetzt attestiert (saveTokens stempelt identisch).
    operator_attested_at: me.user.is_operator ? Math.floor(Date.now() / 1000) : 0,
    device_label: deviceLabel ?? null,
  };
  saveTokens(stored);
  return stored;
}

// Single-Flight-Lock: parallele Aufrufer (Background-Sync + WS + UI) teilen sich EINEN
// /refresh-Roundtrip. Sonst feuern mehrere gleichzeitig mit demselben refresh_token; nutzt der
// Server Refresh-Token-Rotation, scheitert der zweite mit 401 → clearTokens() → unerwarteter
// Logout. (Gemini-Review P1)
let inflightRefresh: Promise<StoredTokens | null> | null = null;

export function refreshTokens(): Promise<StoredTokens | null> {
  if (inflightRefresh) return inflightRefresh;
  inflightRefresh = doRefresh().finally(() => {
    inflightRefresh = null;
  });
  return inflightRefresh;
}

async function doRefresh(): Promise<StoredTokens | null> {
  const cur = loadTokens();
  if (!cur) return null;
  const res = await fetch(`${config.authBaseUrl}/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: cur.refresh_token }),
  });
  if (!res.ok) {
    if (res.status === 401) {
      clearTokens();
      return null;
    }
    throw new Error(`auth_refresh_failed: ${res.status}`);
  }
  const data = (await res.json()) as RefreshResponse;

  // Identität des erneuerten Tokens server-frisch bestätigen — fail-CLOSED: ergibt der (ggf. via
  // /adopt client-gelieferte) refresh_token einen ANDEREN User als den gespeicherten, liegt eine
  // Token-Family-Confusion vor (access≠refresh aus verschiedenen Accounts) → hart abmelden.
  // (Codex P1-3 / Gemini P3)
  const me = await fetchMe(data.access_token).catch((e: unknown) => {
    // /me nicht erreichbar → Identität NICHT prüfbar. Den erneuerten Token NICHT committen (kein
    // ungeprüfter/fremder Token unter alter Identität), aber auch NICHT ausloggen (kein clearTokens
    // → kein spontaner Logout bei transientem /me-Ausfall). Der nächste Versuch prüft erneut. (Codex-ReReview P1)
    console.error(`[auth-client] refresh /me check failed → renewed token NOT committed: ${redactForLog(String(e))}`);
    return null;
  });
  if (me === null) return cur;
  if (me.user.id !== cur.user_id) {
    console.error("[auth-client] refresh identity mismatch (token-family confusion) → clearing tokens");
    clearTokens();
    return null;
  }

  // TOCTOU: Während der Netzwerk-Roundtrips kann ein paralleles Logout/Adopt den lokalen Token-Zustand
  // geändert haben — den erneuerten Token NICHT blind über die (evtl. neue/gelöschte) Zeile schreiben.
  // loadTokens→touchAccessExpiry läuft synchron (kein await dazwischen) → atomar in JS' Single-Thread. (Codex-ReReview P1)
  const now = loadTokens();
  if (!now || now.user_id !== cur.user_id || now.access_token !== cur.access_token) {
    return now;
  }
  const newExpiresAt = Math.floor(Date.now() / 1000) + data.expires_in;
  setOperatorAttestation(me.user.is_operator);
  touchAccessExpiry(data.access_token, newExpiresAt);
  return {
    ...now,
    access_token: data.access_token,
    access_expires_at: newExpiresAt,
    is_operator: me.user.is_operator,
    operator_attested_at: me.user.is_operator ? Math.floor(Date.now() / 1000) : 0,
  };
}

export async function ensureFreshAccessToken(): Promise<StoredTokens | null> {
  let cur = loadTokens();
  if (!cur) return null;
  const skew = 30;
  const now = Math.floor(Date.now() / 1000);
  if (cur.access_expires_at - skew > now) return cur;
  return await refreshTokens();
}

export async function fetchMe(accessToken: string): Promise<MeResponse> {
  const res = await fetch(`${config.authBaseUrl}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`auth_me_failed: ${res.status}`);
  return (await res.json()) as MeResponse;
}

export async function logout(): Promise<void> {
  const cur = loadTokens();
  if (!cur) return;
  try {
    await fetch(`${config.authBaseUrl}/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: cur.refresh_token }),
    });
  } catch { /* network errors ignored — we still drop local state */ }
  clearTokens();
}
