/**
 * Single-admin auth: password hashing (Node's built-in scrypt — no new
 * dependency, per the spec) and signed-cookie session helpers (jose, a
 * small HS256 JWT — chosen over a hand-rolled HMAC cookie only because it's
 * marginally less code to get expiry handling right, and it's already a
 * dependency of claude-skills-security/apps/web so the pattern is familiar).
 *
 * No NextAuth/Clerk/etc — this is a single local admin, not multi-user.
 */
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { SignJWT, jwtVerify } from "jose";
import { getSetting, setSetting } from "./db";

const scrypt = promisify(scryptCb);

export const ADMIN_PASSWORD_HASH_KEY = "ui_admin_password_hash";
export const SESSION_SECRET_KEY = "ui_session_secret";
export const SESSION_COOKIE_NAME = "casky_ui_session";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

const SCRYPT_KEYLEN = 64;

/** Hex-encodes `salt:hash`, both produced by Node's scrypt KDF. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = (await scrypt(password, salt, SCRYPT_KEYLEN)) as Buffer;
  return `${salt.toString("hex")}:${derived.toString("hex")}`;
}

/** Constant-time comparison against a `salt:hash` string from hashPassword(). */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, hashHex] = stored.split(":");
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const derived = (await scrypt(password, salt, SCRYPT_KEYLEN)) as Buffer;
  if (derived.length !== expected.length) return false;
  return timingSafeEqual(derived, expected);
}

const PASSWORD_ALPHABET =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"; // no 0/O/1/l/I ambiguity

/** Generates a random operator-typeable password (not a hex blob). */
export function generatePassword(length = 20): string {
  const bytes = randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += PASSWORD_ALPHABET[bytes[i] % PASSWORD_ALPHABET.length];
  }
  return out;
}

/**
 * Idempotent boot-time setup, called once from instrumentation.ts's
 * register(). Resolves the admin password + session-signing secret and
 * makes sure both are persisted in runtime_settings so a container restart
 * never silently locks the operator out or rotates the session secret
 * (which would just log everyone out, but for no reason).
 *
 * - CASKY_UI_ADMIN_PASSWORD set: that value is (re)hashed and stored every
 *   boot, so the operator can rotate the password by changing the env var
 *   and restarting.
 * - CASKY_UI_ADMIN_PASSWORD unset, no stored hash yet: generate a random
 *   password, print it ONCE (boxed, to stdout — the only place the
 *   operator can learn it), and persist its hash.
 * - CASKY_UI_ADMIN_PASSWORD unset, stored hash already exists: leave it
 *   alone — regenerating here would invalidate the operator's real
 *   password on every restart.
 */
export async function ensureAdminBootstrap(): Promise<void> {
  const envPassword = process.env.CASKY_UI_ADMIN_PASSWORD?.trim();

  if (envPassword) {
    await setSetting(ADMIN_PASSWORD_HASH_KEY, await hashPassword(envPassword));
  } else {
    const existing = await getSetting<string>(ADMIN_PASSWORD_HASH_KEY);
    if (!existing) {
      const generated = generatePassword();
      await setSetting(ADMIN_PASSWORD_HASH_KEY, await hashPassword(generated));
      printGeneratedPasswordBanner(generated);
    }
  }

  const existingSecret = await getSetting<string>(SESSION_SECRET_KEY);
  if (!existingSecret) {
    await setSetting(SESSION_SECRET_KEY, randomBytes(32).toString("hex"));
  }
}

function printGeneratedPasswordBanner(password: string): void {
  const line = `  CASKY-UI ADMIN PASSWORD (generated — save this, it will not be shown again):  `;
  const pwLine = `  ${password}  `;
  const width = Math.max(line.length, pwLine.length);
  const bar = "#".repeat(width);
  // eslint-disable-next-line no-console
  console.log(
    [
      "",
      bar,
      "#" + " ".repeat(width - 2) + "#",
      `#${line.padEnd(width - 2)}#`,
      "#" + " ".repeat(width - 2) + "#",
      `#${pwLine.padEnd(width - 2)}#`,
      "#" + " ".repeat(width - 2) + "#",
      `#  No CASKY_UI_ADMIN_PASSWORD was set, so this was generated for you.` +
        " ".repeat(Math.max(0, width - 74)) + "#",
      `#  It is stored (hashed) in runtime_settings and will NOT change on restart.` +
        " ".repeat(Math.max(0, width - 81)) + "#",
      bar,
      "",
    ].join("\n")
  );
}

// ── Session cookies ──────────────────────────────────────────────────────

let cachedSecret: Promise<Uint8Array> | null = null;

async function getSessionSecretKey(): Promise<Uint8Array> {
  if (!cachedSecret) {
    cachedSecret = (async () => {
      const hex = await getSetting<string>(SESSION_SECRET_KEY);
      if (!hex) {
        throw new Error(
          "ui_session_secret is not set in runtime_settings — has ensureAdminBootstrap() run yet?"
        );
      }
      return new Uint8Array(Buffer.from(hex, "hex"));
    })();
  }
  return cachedSecret;
}

export async function createSessionToken(): Promise<string> {
  const key = await getSessionSecretKey();
  return new SignJWT({ sub: "admin" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(key);
}

export async function verifySessionToken(token: string): Promise<boolean> {
  try {
    const key = await getSessionSecretKey();
    const { payload } = await jwtVerify(token, key);
    return payload.sub === "admin";
  } catch {
    return false;
  }
}

export { SESSION_TTL_SECONDS };
