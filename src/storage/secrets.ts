// Secret storage abstraction.
//
// Production goal: use OS-native keystores
//   - macOS: Keychain via `security` CLI
//   - Linux: Secret Service via `secret-tool`
//   - Windows: Credential Manager via `cmdkey` / PowerShell
//
// Headless systems fall back to a random file key at `$STATE_DIR/keyring.key`.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { config } from "../config.ts";

const SALT_PATH = join(config.stateDir, "keyring.salt");
const KEY_PATH = join(config.stateDir, "keyring.key");
const KID_PATH = join(config.stateDir, "keyring.kid");
const SERVICE_NAME = "subunit-bridge";
const ACCOUNT_NAME = "token-wrapping-key";
const ENVELOPE_VERSION = 2;
const ENVELOPE_ALG = "A256GCM";

interface KeyMaterial {
  key: Buffer;
  kid: string;
}

interface SecretEnvelope {
  v: number;
  kid: string;
  alg: string;
  iv: string;
  tag: string;
  ct: string;
}

let cachedKey: KeyMaterial | null = null;

function chmodIfExists(path: string): void {
  if (existsSync(path)) chmodSync(path, 0o600);
}

function writeSecure(path: string, value: string | Buffer): void {
  writeFileSync(path, value, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function base64Url(buf: Buffer): string {
  return buf.toString("base64url");
}

function decodeBase64Url(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

function ensureKid(prefix: string): string {
  if (existsSync(KID_PATH)) {
    chmodSync(KID_PATH, 0o600);
    const kid = readFileSync(KID_PATH, "utf8").trim();
    if (kid.length >= 8 && kid.length <= 120) return kid;
  }
  const kid = `${prefix}-${randomBytes(8).toString("base64url")}`;
  writeSecure(KID_PATH, `${kid}\n`);
  return kid;
}

function runSecretCommand(cmd: string, args: string[], input?: string): string | null {
  const result = spawnSync(cmd, args, {
    input,
    encoding: "utf8",
    timeout: 2_000,
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) return null;
  return result.stdout.trim();
}

function osSecretSupported(): boolean {
  if (platform() === "darwin") return true;
  if (platform() === "linux") return !!process.env.DBUS_SESSION_BUS_ADDRESS;
  return false;
}

function readOsKey(): Buffer | null {
  if (!osSecretSupported()) return null;
  const encoded = platform() === "darwin"
    ? runSecretCommand("security", ["find-generic-password", "-s", SERVICE_NAME, "-a", ACCOUNT_NAME, "-w"])
    : runSecretCommand("secret-tool", ["lookup", "service", SERVICE_NAME, "account", ACCOUNT_NAME]);
  if (!encoded) return null;
  const key = decodeBase64Url(encoded);
  return key.length === 32 ? key : null;
}

function writeOsKey(key: Buffer): boolean {
  if (!osSecretSupported()) return false;
  const encoded = base64Url(key);
  if (platform() === "darwin") {
    return runSecretCommand("security", ["add-generic-password", "-U", "-s", SERVICE_NAME, "-a", ACCOUNT_NAME, "-w", encoded]) !== null;
  }
  return runSecretCommand(
    "secret-tool",
    ["store", "--label", "Subunit Bridge wrapping key", "service", SERVICE_NAME, "account", ACCOUNT_NAME],
    encoded,
  ) !== null;
}

function osKeyMaterial(): KeyMaterial | null {
  const existing = readOsKey();
  if (existing) return { key: existing, kid: ensureKid("os") };
  const key = randomBytes(32);
  if (!writeOsKey(key)) return null;
  return { key, kid: ensureKid("os") };
}

function fallbackKeyMaterial(): KeyMaterial {
  chmodIfExists(SALT_PATH);
  if (existsSync(KEY_PATH)) {
    chmodSync(KEY_PATH, 0o600);
    const key = decodeBase64Url(readFileSync(KEY_PATH, "utf8").trim());
    if (key.length !== 32) throw new Error("invalid_fallback_key");
    return { key, kid: ensureKid("file") };
  }
  const key = randomBytes(32);
  writeSecure(KEY_PATH, `${base64Url(key)}\n`);
  return { key, kid: ensureKid("file") };
}

function currentKey(): KeyMaterial {
  if (cachedKey) return cachedKey;
  cachedKey = osKeyMaterial() ?? fallbackKeyMaterial();
  return cachedKey;
}

function deriveLegacyKey(): Buffer {
  if (!existsSync(SALT_PATH)) throw new Error("missing_legacy_salt");
  chmodSync(SALT_PATH, 0o600);
  const salt = readFileSync(SALT_PATH);
  // Mix in the host's machine-id for an additional non-secret factor that ties
  // the key to this machine. If /etc/machine-id is missing we just use the salt.
  let machineId = "";
  try {
    machineId = readFileSync("/etc/machine-id", "utf8").trim();
  } catch { /* ignore */ }
  return createHash("sha256").update(salt).update(machineId).digest();
}

function aadFor(kid: string): Buffer {
  return Buffer.from(`subunit-bridge:v=${ENVELOPE_VERSION}:alg=${ENVELOPE_ALG}:kid=${kid}`, "utf8");
}

function parseEnvelope(payload: string): SecretEnvelope | null {
  if (!payload.trim().startsWith("{")) return null;
  const env = JSON.parse(payload) as Partial<SecretEnvelope>;
  if (
    env.v !== ENVELOPE_VERSION ||
    env.alg !== ENVELOPE_ALG ||
    typeof env.kid !== "string" ||
    typeof env.iv !== "string" ||
    typeof env.tag !== "string" ||
    typeof env.ct !== "string"
  ) {
    throw new Error("invalid_secret_payload");
  }
  return env as SecretEnvelope;
}

export function encrypt(plain: string): string {
  const material = currentKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", material.key, iv);
  cipher.setAAD(aadFor(material.kid));
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: ENVELOPE_VERSION,
    kid: material.kid,
    alg: ENVELOPE_ALG,
    iv: base64Url(iv),
    tag: base64Url(tag),
    ct: base64Url(enc),
  });
}

export function decryptWithMetadata(payload: string): { plain: string; needsReencrypt: boolean } {
  const env = parseEnvelope(payload);
  if (env) {
    const iv = decodeBase64Url(env.iv);
    const tag = decodeBase64Url(env.tag);
    const enc = decodeBase64Url(env.ct);
    if (iv.length !== 12 || tag.length !== 16) throw new Error("invalid_secret_payload");
    const material = currentKey();
    const decipher = createDecipheriv("aes-256-gcm", material.key, iv);
    decipher.setAAD(aadFor(env.kid));
    decipher.setAuthTag(tag);
    return {
      plain: Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8"),
      needsReencrypt: env.kid !== material.kid,
    };
  }

  const parts = payload.split(".");
  if (parts.length !== 3) throw new Error("invalid_secret_payload");
  const [ivB, tagB, encB] = parts as [string, string, string];
  const iv = Buffer.from(ivB, "base64");
  const tag = Buffer.from(tagB, "base64");
  const enc = Buffer.from(encB, "base64");
  if (iv.length !== 12 || tag.length !== 16) throw new Error("invalid_secret_payload");
  const key = deriveLegacyKey();
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return {
    plain: Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8"),
    needsReencrypt: true,
  };
}

export function decrypt(payload: string): string {
  return decryptWithMetadata(payload).plain;
}
