# Subunit Bridge Daemon

**Status:** Scaffolding 2026-05-13 22:48 CEST
**Phase:** 1.2 (Master-Plan §6 Phase 1)
**Owner:** u1
**Greenlight:** TJ 2026-05-13 22:34

---

## Was das ist

Lokaler Background-Service der auf der User-Maschine laeuft und alle Subunit-Produkte verklebt.

**Analogie:** Dropbox-Daemon — aber fuer Subunit-Ecosystem.

**Wer redet mit dem Bridge-Daemon:**
- Sonar Desktop (lokales Whisper-Diktat → Bridge → Cloud-Cleanup oder lokal)
- Synapse Desktop (Drag-Drop-Files → Bridge → Synapse-Ingest)
- Subunit App / Sonar Mobile (via Lokales Netz wenn auf gleichem WLAN)
- Subunit CLI (lokales Tool, ruft Bridge)
- Browser-Extension (talk via localhost ws:// von Tab aus)
- u1 (Server-MCP koennte Bridge als Tool aufrufen fuer client-side Actions)

## Server-MCP vs Bridge-Daemon — Klare Trennung

| Ebene | Server-MCP (`u1-bridge`) | Bridge-Daemon (lokal) |
|-------|--------------------------|------------------------|
| Wo | Server (subunit.ai) | User-Maschine |
| Was | Memory/Status/Triggers/Tool-Exec im Server-Kontext | Lokale Datei-Sync, Token-Storage, OS-Notifications, App-Cross-Talk |
| Wer ruft | u1-Agent (Claude Code via MCP) | Sonar Desktop / Subunit App / CLI / Browser-Ext / etc |
| Lifetime | Always-on (Server) | Always-on auf User-Maschine (System-Tray) |

Beide kommunizieren via Cloud (Bridge → Server-API), aber haben getrennte Domaenen.

## Tech-Stack

| Komponente | Wahl | Begruendung |
|------------|------|-------------|
| Runtime | **Bun** | Single-binary kompilierbar (`bun build --compile`), startet < 50ms, nativer TS |
| HTTP/WS Server | **Hono** | localhost:78XX HTTP API + WebSocket fuer Push |
| MCP Server | Custom (Pattern aus `codeaashu-claude-code`) | Konsistenz mit u1-bridge MCP |
| OS Integration | **Bun FFI** + Platform-specific | Tray-Icon, Notifications, Hotkeys, Autostart |
| Storage | **SQLite** (via `bun:sqlite`) | local-only DB fuer Cache + ChromaDB-Replica + Token-Index |
| Secret-Storage | **Keychain (Mac) / Credential Manager (Win) / Secret Service (Linux)** | OS-Native, kein Keystore-File |
| Sync-Transport | **WebSocket** zum Server | Server pusht Decisions/Tasks/Updates |
| Vector-Storage (Offline) | **ChromaDB lokal** oder **lancedb** | Memory-Sync fuer Offline-Suche |

## Architektur

```
┌─────────────── User-Maschine ─────────────────┐
│                                                │
│  Sonar Desktop   Subunit App   CLI   Browser  │
│       ▼              ▼          ▼      ▼      │
│  ┌─────────────────────────────────────────┐  │
│  │  Bridge Daemon (localhost:7842)         │  │
│  │                                         │  │
│  │  • HTTP API (REST)                      │  │
│  │  • MCP Server (stdio + HTTP)            │  │
│  │  • WebSocket Server (Push to apps)      │  │
│  │  • Tray-Icon (System-Tray)              │  │
│  │  • Auto-Updater                         │  │
│  │  • OS-Notifications                     │  │
│  │                                         │  │
│  │  ┌───────────────────────────────────┐  │  │
│  │  │  SQLite (local-only)              │  │  │
│  │  │  - tokens (encrypted via OS)      │  │  │
│  │  │  - workspaces (cache)             │  │  │
│  │  │  - decisions (offline-queue)      │  │  │
│  │  │  - tasks (offline-queue)          │  │  │
│  │  │  - memory_index (vector cache)    │  │  │
│  │  └───────────────────────────────────┘  │  │
│  └─────────────────────────────────────────┘  │
│                     │                          │
└─────────────────────┼──────────────────────────┘
                      │ WSS (push from server)
                      │ HTTPS (REST to API)
                      ▼
              ┌────────────────────┐
              │  api.subunit.ai    │
              │  auth.subunit.ai   │
              │  ws.subunit.ai     │
              └────────────────────┘
```

## Endpoints (Phase 1)

### HTTP API (localhost:7842)

| Method | Path | Purpose |
|--------|------|---------|
| GET | /health | Liveness probe |
| GET | /me | Current user + active workspace (cached) |
| POST | /pair | Browser-pairing Initiation |
| POST | /pair/callback | Browser-pairing Callback |
| POST | /logout | Remove tokens |
| GET | /tokens/refresh | Force refresh (debug) |
| GET | /workspaces | List user workspaces (cached) |
| POST | /workspaces/active | Switch active |
| GET | /decisions/pending | Offline-queue + cached server-state |
| POST | /decisions/:id/approve | Approve a decision (offline-queue if no net) |
| POST | /tasks | Create task (offline-queue if no net) |
| GET | /tasks | List tasks (cached) |
| POST | /memory/search | Local vector search (or proxy to server) |
| POST | /memory/ingest | Local ingest + sync to server |
| POST | /notify | OS-native notification |
| GET | /status | Bridge-Daemon status (last sync, queue size, etc) |

### WebSocket (localhost:7842/ws)

Apps subscribe via WS → Bridge pusht Server-Events lokal.
Events: `decision.new`, `task.new`, `task.update`, `memory.update`, `workspace.switch`

### MCP Server (stdio)

Stdio-MCP fuer u1-Agent oder Claude-Desktop:
- Tools: `bridge_search_memory`, `bridge_list_decisions`, `bridge_approve_decision`, `bridge_create_task`, etc

## Auto-Start

- **macOS:** LaunchAgent in `~/Library/LaunchAgents/ai.subunit.bridge.plist`
- **Linux:** systemd-user unit `~/.config/systemd/user/subunit-bridge.service`
- **Windows:** Task Scheduler "On user logon"

## Update-Mechanismus

Selbe Mechanik wie Sonar Desktop (GitHub-Release + Signature-Check). Daemon updated sich selbst beim Start wenn neue Version verfuegbar.

## Wer bundelt den Daemon

- Sonar Desktop Installer pruft beim Install ob Bridge bereits installiert → wenn nicht, installiert
- Synapse Desktop Installer dito
- Subunit CLI `subunit init` installiert Bridge wenn fehlt
- Single-Daemon-Lock (keine 2 parallel)

## Referenzen

- `~/subunit/unitone/workspace/codeaashu-claude-code/` — Claude Code Source als Pattern-Referenz (Tool/Command/MCP-Layering)
- `~/subunit/unitone/workspace/projects/subunit-ecosystem/MASTER-PLAN.md` §B2 (Bridge Daemon)
- MCP Spec: https://spec.modelcontextprotocol.io/

## Naechste Schritte

1. `package.json` + Bun-Setup
2. Hono-Server mit `/health` als erste Endpoint
3. SQLite-Schema + Migrations-Runner
4. Token-Storage-Layer (OS-Keychain Abstraktion)
5. Auth-Bridge-Integration (Pair-Flow gegen auth.subunit.ai)
6. WebSocket-Client (zum Server) + Server-WS-Endpoint reden
7. Erste MCP-Tools (memory_search, decisions_list)
8. Tray-Icon-Integration (Mac zuerst, dann Win, dann Linux)
9. Auto-Start-Skripte fuer alle 3 Plattformen
10. Single-Binary-Build via `bun build --compile`
