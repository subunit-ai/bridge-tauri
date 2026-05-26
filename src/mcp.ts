#!/usr/bin/env bun
/**
 * Subunit Bridge MCP Server (stdio transport)
 *
 * Spawned by u1, Claude Desktop, or other MCP clients to expose the locally
 * running Bridge Daemon (http://127.0.0.1:7842) as a set of MCP tools.
 *
 * This module is intentionally thin — it proxies all calls to the Bridge HTTP API
 * so there is exactly one source of truth (the daemon).
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const BRIDGE_BASE = process.env.BRIDGE_BASE_URL ?? "http://127.0.0.1:7842";

// Local API token: the hardened Bridge requires `Authorization: Bearer <token>`
// on every route except public GET / and /health. Read from the Bridge state dir
// (same resolution as the daemon's config.ts). Graceful if absent.
function bridgeStateDir(): string {
  return process.env.STATE_DIR
    ?? join(process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share"), "subunit-bridge");
}
let cachedToken: string | null | undefined;
function localToken(): string | null {
  if (cachedToken !== undefined) return cachedToken;
  const fromEnv = process.env.BRIDGE_LOCAL_TOKEN?.trim();
  if (fromEnv) return (cachedToken = fromEnv);
  try {
    cachedToken = readFileSync(join(bridgeStateDir(), "local-api-token"), "utf8").trim() || null;
  } catch {
    cachedToken = null;
  }
  return cachedToken;
}

interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

async function bridgeFetch(method: string, path: string, body?: unknown): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const tok = localToken();
  if (tok) headers["Authorization"] = `Bearer ${tok}`;
  const res = await fetch(`${BRIDGE_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  if (!res.ok) {
    throw new Error(`bridge_http_${res.status}: ${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }
  return parsed;
}

const TOOLS: ToolDef[] = [
  {
    name: "bridge_health",
    description: "Liveness probe for the local Subunit Bridge Daemon. Returns ok-flag, paired state, version, upstream auth URL.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => bridgeFetch("GET", "/health"),
  },
  {
    name: "bridge_auth_status",
    description: "Returns whether the Bridge is paired with a Subunit account, plus active workspace and token expiry. Use this before calling tools that require pairing.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => bridgeFetch("GET", "/auth/status"),
  },
  {
    name: "bridge_me",
    description: "Fetches the paired user's profile and workspace list from auth.subunit.ai via the Bridge (handles token refresh automatically).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => bridgeFetch("GET", "/auth/me"),
  },
  {
    name: "bridge_list_decisions",
    description: "Lists pending decisions in the active workspace. Decisions are pieces of state that need a yes/no answer (e.g. 'should u1 commit this code?', 'approve outbound email?').",
    inputSchema: { type: "object", properties: {} },
    handler: async () => bridgeFetch("GET", "/decisions/pending"),
  },
  {
    name: "bridge_create_decision",
    description: "Creates a new pending decision in the active workspace. Use when something needs explicit user approval before continuing.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Short question / title" },
        body: { type: "string", description: "Optional longer context" },
        source: { type: "string", description: "Source identifier, e.g. 'u1', 'sonar', 'bridge-mcp'" },
        metadata: { type: "object", description: "Arbitrary metadata to attach" },
      },
      required: ["title"],
    },
    handler: async (args) => bridgeFetch("POST", "/decisions", args),
  },
  {
    name: "bridge_approve_decision",
    description: "Approves a pending decision by id.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Decision UUID from bridge_list_decisions" },
        note: { type: "string", description: "Optional note explaining approval" },
      },
      required: ["id"],
    },
    handler: async (args) => bridgeFetch("POST", `/decisions/${(args as { id: string }).id}/approve`, { note: (args as { note?: string }).note }),
  },
  {
    name: "bridge_reject_decision",
    description: "Rejects a pending decision by id.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Decision UUID from bridge_list_decisions" },
      },
      required: ["id"],
    },
    handler: async (args) => bridgeFetch("POST", `/decisions/${(args as { id: string }).id}/reject`),
  },
  {
    name: "bridge_list_tasks",
    description: "Lists tasks in the active workspace. Optional status filter (pending, in_progress, completed, cancelled).",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["pending", "in_progress", "completed", "cancelled"] },
      },
    },
    handler: async (args) => {
      const status = (args as { status?: string }).status ?? "pending";
      return bridgeFetch("GET", `/tasks?status=${encodeURIComponent(status)}`);
    },
  },
  {
    name: "bridge_create_task",
    description: "Creates a new task in the active workspace.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Task title" },
        metadata: { type: "object", description: "Arbitrary metadata (priority, owner, due_date, ...)" },
      },
      required: ["title"],
    },
    handler: async (args) => bridgeFetch("POST", "/tasks", args),
  },
  {
    name: "bridge_update_task_status",
    description: "Updates a task's status.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Task UUID" },
        status: { type: "string", enum: ["pending", "in_progress", "completed", "cancelled"] },
      },
      required: ["id", "status"],
    },
    handler: async (args) => {
      const { id, status } = args as { id: string; status: string };
      return bridgeFetch("PATCH", `/tasks/${id}/status`, { status });
    },
  },
  {
    name: "bridge_outbox_stats",
    description: "Returns counts of pending vs delivered outbox entries (queued events waiting for server sync).",
    inputSchema: { type: "object", properties: {} },
    handler: async () => bridgeFetch("GET", "/outbox/stats"),
  },
  {
    name: "bridge_outbox_list",
    description: "Lists outbox entries (queued sync events). Use to debug what's stuck.",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["pending", "delivered"] },
        limit: { type: "number", minimum: 1, maximum: 500 },
      },
    },
    handler: async (args) => {
      const q = new URLSearchParams();
      const { status, limit } = args as { status?: string; limit?: number };
      if (status) q.set("status", status);
      if (limit) q.set("limit", String(limit));
      const suffix = q.toString();
      return bridgeFetch("GET", `/outbox${suffix ? `?${suffix}` : ""}`);
    },
  },
];

const TOOL_MAP = new Map(TOOLS.map((t) => [t.name, t]));

async function main() {
  const server = new Server(
    {
      name: "subunit-bridge",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const tool = TOOL_MAP.get(req.params.name);
    if (!tool) {
      return {
        content: [{ type: "text", text: `unknown_tool: ${req.params.name}` }],
        isError: true,
      };
    }
    try {
      const result = await tool.handler((req.params.arguments ?? {}) as Record<string, unknown>);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `error: ${err instanceof Error ? err.message : String(err)}` }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[subunit-bridge-mcp] connected via stdio, proxying to ${BRIDGE_BASE}`);
}

main().catch((err) => {
  console.error("[subunit-bridge-mcp] fatal:", err);
  process.exit(1);
});
