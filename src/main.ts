import { Hono } from "hono";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { assertBindableHost, config, isLoopbackHost } from "./config.ts";
import { healthRoutes } from "./routes/health.ts";
import { authRoutes } from "./routes/auth.ts";
import { decisionRoutes } from "./routes/decisions.ts";
import { taskRoutes } from "./routes/tasks.ts";
import { outboxRoutes } from "./routes/outbox.ts";
import { execRoutes } from "./routes/exec.ts";
import { consentRoutes } from "./routes/consent.ts";
import { initConsentOnStartup, registerRemoteAccessHardStopHook } from "./exec/consent.ts";
import { startOutboxWorker } from "./sync/outbox-worker.ts";
import { disconnectWsClient, startWsClient } from "./sync/ws-client.ts";

const LOCAL_API_TOKEN_PATH = join(config.stateDir, "local-api-token");

function loadOrCreateLocalApiToken(): string {
  if (existsSync(LOCAL_API_TOKEN_PATH)) {
    chmodSync(LOCAL_API_TOKEN_PATH, 0o600);
    const token = readFileSync(LOCAL_API_TOKEN_PATH, "utf8").trim();
    if (token.length < 32) throw new Error("local API token is missing or too short");
    return token;
  }
  const token = randomBytes(32).toString("base64url");
  writeFileSync(LOCAL_API_TOKEN_PATH, `${token}\n`, { mode: 0o600 });
  chmodSync(LOCAL_API_TOKEN_PATH, 0o600);
  return token;
}

const localApiToken = loadOrCreateLocalApiToken();
const localApiTokenDigest = createHash("sha256").update(localApiToken).digest();
assertBindableHost(config.host, localApiToken.length >= 32);

const app = new Hono();

function configuredCorsOrigins(): string[] {
  return config.localCorsOrigins.split(",").map((origin) => origin.trim()).filter(Boolean);
}

const corsOrigins = configuredCorsOrigins();

function isAllowedCorsOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    if (
      corsOrigins.includes("loopback") &&
      (url.protocol === "http:" || url.protocol === "https:") &&
      isLoopbackHost(url.hostname)
    ) {
      return true;
    }
    return corsOrigins.includes(origin);
  } catch {
    return false;
  }
}

function hostnameFromHostHeader(host: string): string | null {
  try {
    return new URL(`http://${host}`).hostname;
  } catch {
    const trimmed = host.trim();
    if (trimmed.startsWith("[") && trimmed.includes("]")) return trimmed.slice(1, trimmed.indexOf("]"));
    return trimmed.split(":")[0] ?? null;
  }
}

function isAllowedRequestHost(hostHeader: string | undefined): boolean {
  if (!hostHeader) return false;
  const hostname = hostnameFromHostHeader(hostHeader);
  return !!hostname && isLoopbackHost(hostname);
}

function hasValidBearer(authHeader: string | undefined): boolean {
  const prefix = "Bearer ";
  if (!authHeader?.startsWith(prefix)) return false;
  const supplied = authHeader.slice(prefix.length).trim();
  const suppliedDigest = createHash("sha256").update(supplied).digest();
  return timingSafeEqual(localApiTokenDigest, suppliedDigest);
}

function isPublicRoute(method: string, path: string): boolean {
  return method === "GET" && (path === "/" || path === "/health");
}

// CORS for local apps. Defaults to loopback origins only; set
// LOCAL_CORS_ORIGINS to a comma-separated exact-origin allowlist.
app.use("*", async (c, next) => {
  const origin = c.req.header("Origin");
  if (origin && isAllowedCorsOrigin(origin)) {
    c.header("Access-Control-Allow-Origin", origin);
    c.header("Vary", "Origin");
    c.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
    c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (c.req.method === "OPTIONS") return c.body(null, origin && isAllowedCorsOrigin(origin) ? 204 : 403);
  await next();
});

app.use("*", async (c, next) => {
  if (isPublicRoute(c.req.method, c.req.path)) {
    await next();
    return;
  }
  if (!isAllowedRequestHost(c.req.header("Host"))) {
    return c.json({ error: "forbidden" }, 403);
  }
  const origin = c.req.header("Origin");
  if (origin && !isAllowedCorsOrigin(origin)) {
    return c.json({ error: "forbidden" }, 403);
  }
  if (!hasValidBearer(c.req.header("Authorization"))) {
    c.header("WWW-Authenticate", "Bearer");
    return c.json({ error: "unauthorized" }, 401);
  }
  await next();
});

app.route("/", healthRoutes);
app.route("/auth", authRoutes);
app.route("/decisions", decisionRoutes);
app.route("/tasks", taskRoutes);
app.route("/outbox", outboxRoutes);
app.route("/exec", execRoutes);
app.route("/consent", consentRoutes);

app.notFound((c) => c.json({ error: "not_found" }, 404));
app.onError((err, c) => {
  console.error("[bridge:error]", err);
  return c.json({ error: "internal_error" }, 500);
});

initConsentOnStartup();
registerRemoteAccessHardStopHook(disconnectWsClient);

const server = Bun.serve({
  port: config.port,
  hostname: config.host,
  fetch(req, server) {
    const remote = server.requestIP(req);
    if (!remote?.address) return app.fetch(req);
    const headers = new Headers(req.headers);
    headers.set("x-bridge-remote-addr", remote.address);
    return app.fetch(new Request(req, { headers }));
  },
});

console.log(`[subunit-bridge] listening on http://${config.host}:${server.port}`);
console.log(`[subunit-bridge] state_dir: ${config.stateDir}`);
console.log(`[subunit-bridge] local_api_token: ${LOCAL_API_TOKEN_PATH}`);
console.log(`[subunit-bridge] auth:      ${config.authBaseUrl}`);
console.log(`[subunit-bridge] api:       ${config.apiBaseUrl}`);

// Start background outbox sync worker.
startOutboxWorker();

// Start WebSocket client (waits for pairing).
startWsClient();
