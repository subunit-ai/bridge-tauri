# Subunit Bridge — Remote-Exec Endpoint Plan
**Erstellt:** 2026-05-18 | **Trigger:** TJ-Voice „wenn das geht mit Realtime Remote, das wäre anders krass"
**Status:** Plan v1, awaiting greenlight

## Was wir bauen
Erweiterung des bestehenden Subunit Bridge Daemons (localhost:7842) um einen authentifizierten Remote-Exec-Endpoint. Damit kann ich (Claude im Server) auf Erik's Surface (oder TJ's Laptop, oder später bei Kunden) Befehle triggern — ohne SSH, ohne Port-Forward, ohne IP.

## Architektur

```
   ┌──────────────────────┐         ┌──────────────────────────┐
   │  Claude (u1, server) │ POST    │  api.subunit.ai/         │
   │  via Telegram /      │ ─────▶  │  v1/bridge/exec          │
   │  CLI                 │         │  (with subunit JWT)      │
   └──────────────────────┘         └──────────┬───────────────┘
                                               │ WebSocket push
                                               ▼ (held-open
                                                 from bridge)
                                    ┌──────────────────────────┐
                                    │ subunit-bridge daemon    │
                                    │ (Erik's Surface, :7842)  │
                                    │                          │
                                    │  /exec endpoint:         │
                                    │   - whitelist check      │
                                    │   - audit log            │
                                    │   - execute via spawn    │
                                    │   - stream stdout back   │
                                    └──────────────────────────┘
```

## Wie der Flow läuft

1. **Setup (einmalig):** Erik auf seinem Tablet → `claude-code subunit pair` → Browser-Login → Bridge erhält Bearer-Token, paired mit Subunit-User-ID „erik.becker@subunit.ai"
2. **Bridge `subscribe` an api.subunit.ai:** Bridge öffnet WebSocket zu `wss://api.subunit.ai/v1/bridge/subscribe` mit Bearer. Server hält die Verbindung offen, weiß: „Erik's Tablet ist erreichbar"
3. **Trigger (von mir aus):** Telegram-User TJ sagt „yo schau mal was auf Erik's tablet abgeht". Ich (Claude) führe aus:
   ```
   bash ~/subunit/unitone/workspace/scripts/bridge-remote-exec.sh \
     --user erik.becker@subunit.ai \
     --cmd "claude-code 'lies sonar logs der letzten 30min'"
   ```
4. **Server-Side:** api.subunit.ai validiert mein Operator-Token, findet Erik's offene WS, sendet Exec-Request: `{cmd, cwd, timeout, request_id}`
5. **Bridge:** prüft Whitelist (z.B. nur `claude-code`, `git`, `cat`, `ls`, `python`, NICHT `rm -rf`, NICHT `sudo`). Logged jeden Request in `audit.jsonl` mit Timestamp + Operator + Command.
6. **Bridge spawnt** Process, streamt stdout/stderr zurück an api.subunit.ai über WS → an mich
7. **Ich seh die Live-Ausgabe**, kann iterativ debuggen.

## Security-Modell

| Layer | Schutz |
|-------|--------|
| WS-Auth | Bearer-JWT (sonar-desktop scope reicht NICHT — neuer `bridge:exec` scope) |
| Server-Auth | Nur Operator-Tokens (TJ + ich) dürfen `POST /v1/bridge/exec` für FREMDE User |
| Self-Exec | User darf seinen eigenen Bridge triggern ohne Operator-Scope (TJ → TJ Bridge ok) |
| Whitelist | Hardcoded in Bridge: `claude-code`, `git`, `ls`, `cat`, `head`, `tail`, `grep`, `find`, `python`, `npm`, `bun`, `node` (read-only-ish + dev-tools). Schreibt-System-Sachen verboten. |
| Audit-Log | Jeder Exec geht in `~/.config/subunit/bridge/audit.jsonl` mit Operator-ID, Cmd, Exit, Timestamp |
| User-Konsent | Bridge zeigt Win-Tray-Notification „TJ executed: `claude-code lies logs`" bei jedem Exec → User kann sehen wer was triggert |
| Kill-Switch | Bridge-Daemon-Tray hat „Disable Remote Exec" Button → kappt WS sofort |

## Bridge-Endpoints (neu)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET    | /exec/status | Bearer | Zeigt Whitelist + ob WS connected ist |
| WS     | /exec/stream | Bearer (internal, lokal-only) | Server pusht Exec-Requests, Bridge streamt zurück |
| POST   | /exec/local | Bearer (lokal-only) | Direkter Lokal-Exec (für CLI-Selftest, nicht für Remote) |

## API-Server-Endpoints (neu, in subunit-api)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | /v1/bridge/exec | Operator OR Self | Triggert Exec auf User's Bridge, returnt stream-handle |
| GET  | /v1/bridge/status | Operator OR Self | Listet welche Bridges grad connected sind |
| POST | /v1/bridge/exec/:request_id/kill | Operator | Aborts ein laufendes Exec |

## Implementation-Phasen

### Phase 1: Bridge-Side (3-4h)
- Whitelist + Audit-Log in subunit-bridge
- WS-Subscribe-Loop zu api.subunit.ai
- Exec-Handler mit stdout-stream
- Tray-Notification bei jedem Trigger

### Phase 2: API-Server-Side (2-3h)
- `/v1/bridge/subscribe` WS-Endpoint (hält Verbindungen pro User)
- `/v1/bridge/exec` POST-Endpoint (forwarded an User's Bridge)
- Operator-Scope-Check (nur TJ + u1 dürfen fremde Bridges triggern)
- WebSocket-Multiplexing (mehrere parallele Exec-Streams pro Bridge)

### Phase 3: Trigger-CLI (1h)
- `bridge-remote-exec.sh` Wrapper im scripts/
- Telegram-Skill für mich: „/bridge erik 'claude-code ...'"
- Output kommt in mein Chat-Stream

### Phase 4: Erik-Setup (~30min)
- `bridge-daemon` Setup-Anleitung schreiben
- Browser-Pair-Flow auf Erik's Surface durchspielen
- Smoke-Test: ich triggere `ls C:\Users\erik\AppData\Local\synapse-voice\logs` → seh die Datei

## Gesamt-Aufwand

~7-9h fokussierte Arbeit. Kann ich als eigenen Sprint nach den Sonar-Hotfixes machen. Kein Sonar-Code wird angefasst — alles in subunit-bridge + subunit-api.

## Was es uns gibt

- **Erik-Debug:** wenn er sagt „Sonar is langsam", führe ich `cProfile`, schaue Logs, fixe Code, commit + push direkt von seinem Tablet aus
- **TJ-Debug:** dieselbe Hebelwirkung auf deinem Laptop — wir können gemeinsam an Codebase live arbeiten
- **Kunden-Support:** „Premium-Tier: 24/7 Subunit-Operator-Access für Diagnostik". Echter Mehrwert für €500+/mo Tier.
- **Self-Service-Automation:** TJ kann von seinem Phone „/bridge laptop 'cd projects/xxx && pnpm test'" sagen.

## Risks

| Risk | Mitigation |
|------|------------|
| RCE-Sicherheitsproblem | Whitelist + Audit + Tray-Notification + User-Kill-Switch |
| User vergisst Bridge läuft → DSGVO-Bedenken | Bridge-Tray-Icon dauerhaft sichtbar, Tooltip „Sub-Operator-Access ENABLED" |
| WS-Disconnect bei Network-Drops | Bridge reconnectet alle 30s, exponential backoff |
| Operator-Token-Leak → totaler Zugriff | Operator-Tokens kurzlebig (15min), separate Token-Rotation, MFA-Required für Issue |
| User auf Tablet schläft → Bridge offline → Exec failed | Server returnt 503 mit „Bridge nicht erreichbar — last seen X min ago" |

## Next Step

TJ-Greenlight → ich starte Phase 1 in subunit-bridge Repo, am besten parallel zur Erik-Sonar-Testing-Phase damit wir nichts dryckdyncken.
