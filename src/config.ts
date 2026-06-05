import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

function envOr(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function corsOriginsEnv(): string {
  return process.env.LOCAL_CORS_ORIGINS ?? process.env.CORS_ORIGINS ?? "loopback";
}

function resolveStateDir(): string {
  const explicit = process.env.STATE_DIR;
  if (explicit) return explicit;
  const xdg = process.env.XDG_DATA_HOME;
  const base = xdg ?? join(homedir(), ".local", "share");
  return join(base, "subunit-bridge");
}

const stateDir = resolveStateDir();
if (!existsSync(stateDir)) {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
}

export const config = {
  port: Number(envOr("PORT", "7842")),
  host: envOr("HOST", "127.0.0.1"),
  authBaseUrl: envOr("AUTH_BASE_URL", "https://auth.subunit.ai"),
  apiBaseUrl: envOr("API_BASE_URL", "https://api.subunit.ai"),
  wsBaseUrl: envOr("WS_BASE_URL", "wss://ws.subunit.ai"),
  clientId: envOr("CLIENT_ID", "bridge-daemon"),
  localCorsOrigins: corsOriginsEnv(),
  execApprovalPublicKey: (process.env.EXEC_APPROVAL_PUBLIC_KEY ?? "").replace(/\\n/g, "\n"),
  stateDir,
  dbPath: join(stateDir, "bridge.sqlite"),
  version: "0.4.1", // IM EINKLANG MIT DEM git-Tag halten (bridge-tauri vX.Y.Z) — sonst zeigt der Installer eine falsche Version
};

export function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().replace(/^\[(.*)\]$/, "$1").toLowerCase();
  return normalized === "localhost" || normalized === "::1" || /^127\./.test(normalized);
}

export function assertBindableHost(host: string, strongLocalApiAuth: boolean): void {
  if (!isLoopbackHost(host) && !strongLocalApiAuth) {
    throw new Error("refusing non-loopback HOST without strong local API auth");
  }
}
