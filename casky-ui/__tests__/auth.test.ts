import { describe, expect, it } from "vitest";
import { generatePassword, hashPassword, shouldUseSecureCookie, verifyPassword } from "@/lib/auth";

describe("password hashing", () => {
  it("verifies a correct password against its own hash", async () => {
    const hash = await hashPassword("correct horse battery staple");
    await expect(verifyPassword("correct horse battery staple", hash)).resolves.toBe(true);
  });

  it("rejects an incorrect password", async () => {
    const hash = await hashPassword("correct horse battery staple");
    await expect(verifyPassword("wrong password", hash)).resolves.toBe(false);
  });

  it("produces a different salt (and thus hash) on every call", async () => {
    const a = await hashPassword("same-password");
    const b = await hashPassword("same-password");
    expect(a).not.toEqual(b);
    await expect(verifyPassword("same-password", a)).resolves.toBe(true);
    await expect(verifyPassword("same-password", b)).resolves.toBe(true);
  });

  it("rejects a malformed stored hash instead of throwing", async () => {
    await expect(verifyPassword("anything", "not-a-valid-hash")).resolves.toBe(false);
    await expect(verifyPassword("anything", "")).resolves.toBe(false);
  });

  it("generatePassword returns a password of the requested length using an unambiguous alphabet", () => {
    const pw = generatePassword(24);
    expect(pw).toHaveLength(24);
    expect(pw).not.toMatch(/[0O1lI]/);
  });
});

// ── shouldUseSecureCookie ─────────────────────────────────────────────────
//
// Live-caught: every route bounced straight back to /login even after
// successfully logging in — "apparently we are not setting an auth cookie".
// The server WAS calling cookieStore.set(...), but with `secure: NODE_ENV ===
// "production"` — the Dockerfile hardcodes NODE_ENV=production unconditionally,
// while this box's bundled docker-compose stack serves plain HTTP with no TLS
// termination anywhere. So the cookie was always marked Secure with HTTPS
// never actually available to satisfy it, and browsers silently drop a
// Secure cookie set over a non-HTTPS response — indistinguishable, from the
// operator's side, from no cookie ever being set.

describe("shouldUseSecureCookie", () => {
  it("defaults to false when CASKY_UI_FORCE_SECURE_COOKIE is unset", () => {
    expect(shouldUseSecureCookie({})).toBe(false);
  });

  it("stays false even when NODE_ENV is production (the actual regression)", () => {
    expect(shouldUseSecureCookie({ NODE_ENV: "production" })).toBe(false);
  });

  it("is true only when CASKY_UI_FORCE_SECURE_COOKIE is exactly 'true'", () => {
    expect(shouldUseSecureCookie({ CASKY_UI_FORCE_SECURE_COOKIE: "true" })).toBe(true);
    expect(shouldUseSecureCookie({ CASKY_UI_FORCE_SECURE_COOKIE: "1" })).toBe(false);
    expect(shouldUseSecureCookie({ CASKY_UI_FORCE_SECURE_COOKIE: "yes" })).toBe(false);
  });
});
