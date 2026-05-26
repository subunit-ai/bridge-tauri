# Pattern Notes — Claude Code Leaked Source Analyse

**Source:** `~/subunit/unitone/workspace/codeaashu-claude-code/`
**Why:** Bridge-Daemon braucht ein robustes Tool/Command/MCP-Layering. Claude Code hat das bereits sauber durchdesigned — wir uebernehmen Patterns, nicht Code.

**Status:** TODO — Source noch zu studieren. Diese Datei ist Platzhalter mit den Fragen die wir beantworten wollen.

## Was wir aus dem Source lernen wollen

1. **Tool-System** — wie sind Tools deklariert, geladen, aufgerufen? (siehe `src/tools/`)
2. **Command-System** — wie funktioniert das Slash-Command-Dispatch? (siehe `src/commands/`)
3. **MCP-Layer** — wie ist die MCP-Server-Implementierung strukturiert? (siehe `mcp-server/`)
4. **Service-Layer** — wo lebt Background-Logik (file-watcher, hooks, etc)?
5. **Auth-Token-Storage** — wie wird Cred-Storage abstrahiert?
6. **IPC-Pattern** — wie reden Sub-Prozesse miteinander?
7. **Update-Mechanik** — wie macht Claude Code Self-Update?
8. **OS-Integration** — Tray? Notifications? Autostart?

## Konkrete Files die ich anschauen werde

- `package.json` (Stack-Confirmation)
- `bunfig.toml` (Bun-Configuration)
- `src/index.ts` (Entry-Point)
- `src/tools/` (Tool-Registry-Pattern)
- `src/commands/` (Command-Dispatch)
- `mcp-server/` (MCP-Implementation)
- `src/services/` (Background-Services)
- `docs/` (eventuell Architektur-Docs)

## Was wir NICHT uebernehmen

- React+Ink fuer UI — Bridge ist headless, optional Tray-Icon native
- CLI-Argv-Parsing — Bridge ist Daemon, kein REPL
- Spezifische Claude/Anthropic-API-Calls

## Naechste Steps

1. `tree` ueber `codeaashu-claude-code/src/` und `mcp-server/` machen, Struktur dokumentieren
2. Tool-Registry-Code lesen, Pattern in `src/tools.ts` (Bridge) anwenden
3. MCP-Server-Code lesen, Pattern in `src/mcp/` (Bridge) anwenden
4. Service-Pattern fuer Sync-Engine adaptieren
