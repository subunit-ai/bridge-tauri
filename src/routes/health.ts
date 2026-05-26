import { Hono } from "hono";
import { config } from "../config.ts";
import { loadTokens } from "../storage/tokens.ts";
import { getAccessMode } from "../exec/access-mode.ts";

export const healthRoutes = new Hono();

healthRoutes.get("/health", (c) => {
  const tokens = loadTokens();
  return c.json({
    ok: true,
    version: config.version,
    paired: !!tokens,
    active_workspace_id: tokens?.active_workspace_id ?? null,
    auth_base_url: config.authBaseUrl,
  });
});

// GET / — Browser-friendly landing.
//   - When unpaired: render a minimal HTML pair form so a customer can
//     finish setup without using a terminal.
//   - When paired: show a status card.
// Both pages call back to /auth/pair and /auth/logout via fetch().
healthRoutes.get("/", (c) => {
  const tokens = loadTokens();
  const mode = getAccessMode();
  const accepts = c.req.header("accept") ?? "";
  if (accepts.includes("application/json") && !accepts.includes("text/html")) {
    return c.json({
      service: "subunit-bridge",
      version: config.version,
      state_dir: config.stateDir,
      paired: !!tokens,
      access_mode: mode,
    });
  }
  c.header("Content-Type", "text/html; charset=utf-8");
  return c.body(renderLanding(tokens, mode));
});

function renderLanding(tokens: ReturnType<typeof loadTokens>, mode: "restricted" | "full"): string {
  const paired = !!tokens;
  const safeEmail = (tokens?.email ?? "").replace(/[<>]/g, "");
  const safeDevice = (tokens?.device_label ?? "").replace(/[<>]/g, "");
  const safeWorkspace = (tokens?.active_workspace_id ?? "").replace(/[<>]/g, "");
  const operatorBadge = tokens?.is_operator ? `<span class="badge op">operator</span>` : "";
  const modeBadge = mode === "full"
    ? `<span class="badge danger">full access</span>`
    : `<span class="badge">read-only</span>`;
  const card = paired
    ? `
      <h1>Subunit Bridge — paired</h1>
      <div class="status ok">
        <div class="row"><span class="k">Account</span><span class="v">${safeEmail} ${operatorBadge}</span></div>
        <div class="row"><span class="k">Device</span><span class="v">${safeDevice || "—"}</span></div>
        <div class="row"><span class="k">Workspace</span><span class="v">${safeWorkspace || "—"}</span></div>
        <div class="row"><span class="k">Access mode</span><span class="v">${modeBadge}</span></div>
        <div class="row"><span class="k">Bridge version</span><span class="v">${config.version}</span></div>
      </div>
      <p class="hint">Diese Maschine ist mit Subunit verbunden. Operator-Befehle koennen
      live ausgefuehrt werden. Audit-Log: <code>~/.config/subunit-bridge/audit.jsonl</code></p>
      <div class="access-toggle">
        <button type="button" class="btn-secondary" id="toggle-mode" data-mode="${mode}">
          ${mode === "full" ? "Auf Read-only zurueckschalten" : "Full-Access aktivieren (Achtung)"}
        </button>
        <div id="toggle-msg" class="msg"></div>
      </div>
      <button id="logout" class="btn-secondary" style="margin-top:18px;">Pairing aufheben</button>
      <div id="logout-msg" class="msg"></div>
      `
    : `
      <h1>Subunit Bridge — Pair Device</h1>
      <p class="hint">Logge dich einmal mit deinem Subunit-Konto ein. Die Tokens werden
      verschluesselt auf dieser Maschine gespeichert (AES-256-GCM, Schluessel aus der
      machine-id abgeleitet).</p>
      <form id="pair-form">
        <label>Email
          <input id="email" type="email" autocomplete="username" required autofocus />
        </label>
        <label>Passwort
          <input id="password" type="password" autocomplete="current-password" required />
        </label>
        <label>Geraete-Bezeichnung (optional)
          <input id="device" type="text" placeholder="z.B. Erik-Surface-Pro" />
        </label>
        <label class="check">
          <input id="full-access" type="checkbox" />
          <span>Full-Access aktivieren <strong>(NUR fuer Team-Maschinen)</strong></span>
          <small>Ohne Haken: Operator kann nur eine Read-only-Whitelist ausfuehren. Mit Haken: jeder Befehl, inkl. <code>rm</code>, <code>sudo</code>, etc. — nur fuer Maschinen die DU besitzt.</small>
        </label>
        <button type="submit" class="btn-primary" id="submit">Pair this device</button>
      </form>
      <div id="pair-msg" class="msg"></div>
      `;
  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Subunit Bridge</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; font: 14px/1.5 -apple-system, system-ui, Segoe UI, Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; display: grid; place-items: center; padding: 24px; }
  .card { max-width: 480px; width: 100%; background: #1e293b; border: 1px solid #334155; border-radius: 12px;
    padding: 28px 24px; box-shadow: 0 16px 48px rgba(0,0,0,.35); }
  h1 { margin: 0 0 16px; font-size: 20px; color: #f8fafc; font-weight: 600; }
  .hint { color: #94a3b8; font-size: 13px; margin: 0 0 18px; }
  label { display: block; margin: 12px 0; color: #cbd5e1; font-size: 13px; }
  input { display: block; width: 100%; margin-top: 6px; padding: 10px 12px;
    border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc;
    font: inherit; outline: none; }
  input:focus { border-color: #06b6d4; box-shadow: 0 0 0 3px rgba(6,182,212,.18); }
  button { cursor: pointer; padding: 11px 18px; border-radius: 8px; border: 0; font: inherit; font-weight: 600; }
  .btn-primary { background: #06b6d4; color: #0f172a; width: 100%; margin-top: 12px; }
  .btn-primary:hover { background: #22d3ee; }
  .btn-primary:disabled { opacity: .6; cursor: not-allowed; }
  .btn-secondary { background: #475569; color: #f1f5f9; margin-top: 18px; }
  .btn-secondary:hover { background: #64748b; }
  .msg { margin-top: 14px; padding: 10px 12px; border-radius: 8px; font-size: 13px; display: none; }
  .msg.ok { display: block; background: #064e3b; color: #6ee7b7; border: 1px solid #047857; }
  .msg.err { display: block; background: #4c0519; color: #fda4af; border: 1px solid #9f1239; }
  .status { padding: 4px 0; }
  .row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #334155; }
  .row:last-child { border-bottom: 0; }
  .k { color: #94a3b8; }
  .v { color: #f8fafc; font-weight: 500; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    background: #06b6d4; color: #0f172a; margin-left: 6px; }
  .badge.danger { background: #f43f5e; color: #fff1f2; }
  label.check {
    display: block; margin: 16px 0 12px; padding: 12px 14px;
    background: rgba(244,63,94,0.06); border: 1px solid rgba(244,63,94,0.18);
    border-radius: 8px; cursor: pointer;
  }
  label.check input { margin-right: 8px; vertical-align: middle; transform: scale(1.1); accent-color: #f43f5e; }
  label.check span { color: #f8fafc; font-size: 13px; }
  label.check small { display: block; color: #94a3b8; font-size: 12px; line-height: 1.45; margin-top: 6px; }
  label.check code { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 11.5px; background: #0f172a; padding: 0 4px; border-radius: 3px; color: #fda4af; }
  label.check small strong { color: #fda4af; font-weight: 600; }
  .access-toggle { margin-top: 18px; padding-top: 18px; border-top: 1px solid #334155; }
  code { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    background: #0f172a; padding: 1px 6px; border-radius: 4px; font-size: 12px; color: #cbd5e1; }
</style>
</head>
<body>
<main class="card">${card}</main>
<script>
  const form = document.getElementById("pair-form");
  if (form) {
    const msg = document.getElementById("pair-msg");
    const btn = document.getElementById("submit");
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      msg.className = "msg"; msg.textContent = "";
      btn.disabled = true; btn.textContent = "Paire...";
      try {
        const body = {
          email: document.getElementById("email").value.trim(),
          password: document.getElementById("password").value,
          device_label: document.getElementById("device").value.trim() || undefined,
          access_mode: document.getElementById("full-access")?.checked ? "full" : "restricted",
        };
        const res = await fetch("/auth/pair", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await res.json();
        if (res.ok && data.ok) {
          msg.className = "msg ok";
          msg.innerHTML = "Pairing erfolgreich. Lade neu...";
          setTimeout(() => location.reload(), 800);
        } else {
          msg.className = "msg err";
          msg.textContent = "Pairing fehlgeschlagen: " + (data.message || data.error || res.status);
          btn.disabled = false; btn.textContent = "Pair this device";
        }
      } catch (e) {
        msg.className = "msg err";
        msg.textContent = "Netzwerk-Fehler: " + e;
        btn.disabled = false; btn.textContent = "Pair this device";
      }
    });
  }
  const logout = document.getElementById("logout");
  if (logout) {
    const msg = document.getElementById("logout-msg");
    logout.addEventListener("click", async () => {
      logout.disabled = true; logout.textContent = "Aufheben...";
      try {
        await fetch("/auth/logout", { method: "POST" });
        msg.className = "msg ok";
        msg.innerHTML = "Pairing entfernt. Lade neu...";
        setTimeout(() => location.reload(), 800);
      } catch (e) {
        msg.className = "msg err";
        msg.textContent = "Fehler: " + e;
        logout.disabled = false; logout.textContent = "Pairing aufheben";
      }
    });
  }

  const toggleMode = document.getElementById("toggle-mode");
  if (toggleMode) {
    const tmsg = document.getElementById("toggle-msg");
    toggleMode.addEventListener("click", async () => {
      const current = toggleMode.dataset.mode;
      const next = current === "full" ? "restricted" : "full";
      if (next === "full") {
        const ok = confirm("Full-Access aktivieren?\\n\\nDanach kann Subunit-Operator JEDEN Befehl auf dieser Maschine ausfuehren — inkl. rm, sudo, etc. Nur fuer Maschinen die DU besitzt.\\n\\nFortfahren?");
        if (!ok) return;
      }
      toggleMode.disabled = true; toggleMode.textContent = "Speichere...";
      try {
        const res = await fetch("/auth/access", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ access_mode: next }),
        });
        const data = await res.json();
        if (res.ok && data.ok) {
          tmsg.className = "msg ok";
          tmsg.textContent = "Mode = " + data.access_mode + ". Lade neu...";
          setTimeout(() => location.reload(), 700);
        } else {
          tmsg.className = "msg err"; tmsg.textContent = "Fehler: " + (data.error || res.status);
          toggleMode.disabled = false;
        }
      } catch (e) {
        tmsg.className = "msg err"; tmsg.textContent = "Fehler: " + e;
        toggleMode.disabled = false;
      }
    });
  }
</script>
</body>
</html>`;
}
