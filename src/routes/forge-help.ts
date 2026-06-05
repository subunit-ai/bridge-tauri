import { Hono } from "hono";
import { z } from "zod";
import { config } from "../config.ts";
import { ensureFreshAccessToken } from "../sync/auth-client.ts";

// Forge-Hilfe-Anfrage aus dem Sonar-Forge-Space → DIREKT (nicht über die verzögerte Outbox) an
// subunit-api weiterreichen, das TJ per Telegram benachrichtigt. Authed über das gepairte Token.
export const forgeHelpRoutes = new Hono();

const HelpSchema = z.object({
  message: z.string().max(2000).optional(),
});

forgeHelpRoutes.post("/help-request", async (c) => {
  const tokens = await ensureFreshAccessToken();
  if (!tokens) return c.json({ error: "not_paired" }, 401);
  const body = HelpSchema.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "invalid_request" }, 400);

  try {
    const res = await fetch(`${config.apiBaseUrl}/v1/forge/help-request`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({
        message: body.data.message ?? "",
        device_label: tokens.device_label ?? "sonar",
      }),
    });
    if (!res.ok) {
      console.error(`[forge/help] upstream status=${res.status}`);
      return c.json({ error: "upstream_failed" }, 502);
    }
    return c.json({ ok: true });
  } catch (err) {
    console.error("[forge/help] upstream failed:", String(err).slice(0, 200));
    return c.json({ error: "upstream_failed" }, 502);
  }
});
