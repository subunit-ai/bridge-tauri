import { config } from "../config.ts";
import { loadTokens, saveTokens, touchAccessExpiry, clearTokens, type StoredTokens } from "../storage/tokens.ts";

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
    .replace(/"(access_token|refresh_token|password)"\s*:\s*"[^"]*"/g, "\"$1\":\"[redacted]\"")
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
    device_label: deviceLabel ?? null,
  };
  saveTokens(stored);
  return stored;
}

export async function refreshTokens(): Promise<StoredTokens | null> {
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
  const newExpiresAt = Math.floor(Date.now() / 1000) + data.expires_in;
  touchAccessExpiry(data.access_token, newExpiresAt);
  return { ...cur, access_token: data.access_token, access_expires_at: newExpiresAt };
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
