import { Database } from "bun:sqlite";
import { config } from "../config.ts";

export const db = new Database(config.dbPath, { create: true });
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA foreign_keys = ON");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  -- Stored encrypted via OS keychain layer (see secret_storage)
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  access_expires_at INTEGER NOT NULL,
  active_workspace_id TEXT,
  is_operator INTEGER NOT NULL DEFAULT 0,
  device_label TEXT,
  issued_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_refresh_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  tier TEXT NOT NULL,
  role TEXT NOT NULL,
  retention_days INTEGER NOT NULL,
  cached_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  payload TEXT NOT NULL,                 -- JSON
  source TEXT,                            -- "u1", "sonar", etc
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  resolved_at INTEGER,
  synced_at INTEGER                       -- last sync to server
);

CREATE INDEX IF NOT EXISTS idx_decisions_workspace ON decisions(workspace_id, status);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  payload TEXT,                           -- JSON
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  synced_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_tasks_workspace ON tasks(workspace_id, status);

CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                     -- "decision.approve", "task.create", "memory.ingest"
  payload TEXT NOT NULL,                  -- JSON
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT (unixepoch()),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  delivered_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(delivered_at, next_attempt_at);

CREATE TABLE IF NOT EXISTS memory_index (
  id TEXT PRIMARY KEY,
  content TEXT NOT NULL,
  category TEXT,
  source TEXT,
  metadata TEXT,                          -- JSON
  embedded_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_memory_category ON memory_index(category);

CREATE TABLE IF NOT EXISTS pair_attempts (
  state TEXT PRIMARY KEY,
  code_verifier TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_pair_attempts_created ON pair_attempts(created_at);
`;

db.exec(SCHEMA);

export function kvGet(key: string): string | null {
  const row = db.query<{ value: string }, [string]>("SELECT value FROM kv WHERE key = ?").get(key);
  return row?.value ?? null;
}

export function kvSet(key: string, value: string): void {
  db.run(
    "INSERT INTO kv (key, value, updated_at) VALUES (?, ?, unixepoch()) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = unixepoch()",
    [key, value],
  );
}

export function kvDel(key: string): void {
  db.run("DELETE FROM kv WHERE key = ?", [key]);
}
