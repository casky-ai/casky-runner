import { describe, expect, it, vi } from "vitest";

// Deliberately does NOT set DATABASE_URL and does NOT import
// __tests__/db.test.ts's module cache — vitest gives each test file its
// own module graph, so lib/db.ts's lazily-created `pool` singleton starts
// undefined here regardless of what other test files did.
vi.mock("pg", () => ({
  Pool: vi.fn(function Pool() { return { query: vi.fn() }; }),
}));

describe("DatabaseUnavailable when DATABASE_URL is unset", () => {
  it("fails loudly and cleanly instead of connecting with an empty DSN", async () => {
    delete process.env.DATABASE_URL;
    const db = await import("@/lib/db");
    await expect(db.listInvestigations()).rejects.toThrow(/DATABASE_URL is not set/);
    await expect(db.listInvestigations()).rejects.toBeInstanceOf(db.DatabaseUnavailable);
  });
});
