import { db } from "./db.ts";
import { encrypt, decryptWithMetadata } from "./secrets.ts";

export interface StoredTokens {
  user_id: string;
  email: string;
  access_token: string;
  refresh_token: string;
  access_expires_at: number;
  active_workspace_id: string | null;
  is_operator: boolean;
  /** Unix-Sekunden der letzten server-frischen Operator-Attestierung (/auth/me). 0 = nie. */
  operator_attested_at: number;
  device_label: string | null;
}

interface Row {
  id: number;
  user_id: string;
  email: string;
  access_token: string;
  refresh_token: string;
  access_expires_at: number;
  active_workspace_id: string | null;
  is_operator: number;
  operator_attested_at: number;
  device_label: string | null;
}

export function saveTokens(t: StoredTokens): void {
  // Single-user-per-daemon model: replace any existing row.
  db.transaction(() => {
    db.run("DELETE FROM tokens");
    db.run(
      `INSERT INTO tokens (user_id, email, access_token, refresh_token, access_expires_at, active_workspace_id, is_operator, operator_attested_at, device_label)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        t.user_id,
        t.email,
        encrypt(t.access_token),
        encrypt(t.refresh_token),
        t.access_expires_at,
        t.active_workspace_id,
        t.is_operator ? 1 : 0,
        // is_operator kommt hier frisch aus /auth/me (Login/Pairing) → jetzt attestiert.
        t.is_operator ? Math.floor(Date.now() / 1000) : 0,
        t.device_label,
      ],
    );
  })();
}

export function loadTokens(): StoredTokens | null {
  const row = db.query<Row, []>("SELECT * FROM tokens ORDER BY id DESC LIMIT 1").get();
  if (!row) return null;
  const access = decryptWithMetadata(row.access_token);
  const refresh = decryptWithMetadata(row.refresh_token);
  if (access.needsReencrypt || refresh.needsReencrypt) {
    db.run(
      "UPDATE tokens SET access_token = ?, refresh_token = ? WHERE id = ?",
      [encrypt(access.plain), encrypt(refresh.plain), row.id],
    );
  }
  return {
    user_id: row.user_id,
    email: row.email,
    access_token: access.plain,
    refresh_token: refresh.plain,
    access_expires_at: row.access_expires_at,
    active_workspace_id: row.active_workspace_id,
    is_operator: row.is_operator === 1,
    operator_attested_at: row.operator_attested_at,
    device_label: row.device_label,
  };
}

export function clearTokens(): void {
  db.run("DELETE FROM tokens");
}

/**
 * Setzt den Operator-Status aus einer SERVER-frischen /auth/me-Antwort und stempelt
 * die Attestierungszeit. is_operator=true → operator_attested_at=jetzt; is_operator=false
 * → 0 (sofortiger Entzug, fail-closed). Treibt den Freshness-Check des Operator-Bypass.
 */
export function setOperatorAttestation(isOperator: boolean): void {
  db.run(
    "UPDATE tokens SET is_operator = ?, operator_attested_at = ?",
    [isOperator ? 1 : 0, isOperator ? Math.floor(Date.now() / 1000) : 0],
  );
}

export function touchAccessExpiry(newAccess: string, newExpiresAt: number): void {
  const enc = encrypt(newAccess);
  db.run(
    "UPDATE tokens SET access_token = ?, access_expires_at = ?, last_refresh_at = unixepoch()",
    [enc, newExpiresAt],
  );
}
