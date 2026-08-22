/**
 * Boundary contract: casky-ui's organizational-memory retrieval must match
 * casky_pipeline/memory.py's find_relevant_memories() / decayed_confidence()
 * exactly — same 90-day half-life, same 0.15 confidence floor, same
 * hard-expiry-overrides-decay rule — since both are independent appliers of
 * one shared design (see lib/memory.ts's header comment), not forks that
 * could silently diverge.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { decayedConfidence, MEMORY_HALF_LIFE_DAYS, MIN_RETRIEVAL_CONFIDENCE } from "@/lib/memory";

describe("decayedConfidence", () => {
  it("returns the original confidence with no elapsed time", () => {
    const now = new Date().toISOString();
    expect(decayedConfidence(0.8, now, null)).toBeCloseTo(0.8, 5);
  });

  it("halves confidence after exactly one half-life", () => {
    const reinforcedAt = new Date(Date.now() - MEMORY_HALF_LIFE_DAYS * 86_400_000).toISOString();
    expect(decayedConfidence(0.8, reinforcedAt, null)).toBeCloseTo(0.4, 2);
  });

  it("returns 0 once past a hard expiry, regardless of decay math", () => {
    const reinforcedAt = new Date().toISOString(); // no decay otherwise
    const expiresAt = new Date(Date.now() - 1000).toISOString(); // 1s in the past
    expect(decayedConfidence(0.9, reinforcedAt, expiresAt)).toBe(0);
  });

  it("ignores a future expiry (not yet hit)", () => {
    const now = new Date().toISOString();
    const future = new Date(Date.now() + 86_400_000).toISOString();
    expect(decayedConfidence(0.8, now, future)).toBeCloseTo(0.8, 5);
  });
});

const queryMock = vi.fn();
vi.mock("pg", () => ({
  Pool: vi.fn(function Pool() {
    return { query: queryMock };
  }),
}));
process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";
const db = await import("@/lib/db");

function rows<T>(data: T[]) {
  return { rows: data };
}

beforeEach(() => {
  queryMock.mockReset();
});

describe("findRelevantMemories", () => {
  it("returns [] without querying when no entities are provided", async () => {
    const result = await db.findRelevantMemories({});
    expect(result).toEqual([]);
    expect(queryMock).not.toHaveBeenCalled();
  });

  it("filters out matches below MIN_RETRIEVAL_CONFIDENCE after decay", async () => {
    const staleReinforcedAt = new Date(Date.now() - 400 * 86_400_000).toISOString(); // long decayed
    queryMock.mockResolvedValueOnce(
      rows([
        {
          id: "mem-1",
          source_investigation_id: "inv-1",
          statement: "stale claim",
          rationale: "r",
          conditions: {},
          applies_to: { technique_ids: ["T1078"] },
          confidence: 0.9,
          escalation_recommended: true,
          created_at: staleReinforcedAt,
          last_reinforced_at: staleReinforcedAt,
          expires_at: null,
          superseded_by: null,
        },
      ])
    );

    const result = await db.findRelevantMemories({ techniqueIds: ["T1078"] });
    expect(result).toEqual([]);
  });

  it("returns a fresh match with effective_confidence attached, sorted by it", async () => {
    const now = new Date().toISOString();
    queryMock.mockResolvedValueOnce(
      rows([
        {
          id: "mem-1",
          source_investigation_id: "inv-1",
          statement: "fresh claim",
          rationale: "r",
          conditions: {},
          applies_to: { cve_ids: ["CVE-2024-1234"] },
          confidence: 0.8,
          escalation_recommended: false,
          created_at: now,
          last_reinforced_at: now,
          expires_at: null,
          superseded_by: null,
        },
      ])
    );

    const result = await db.findRelevantMemories({ cveIds: ["CVE-2024-1234"] });
    expect(result).toHaveLength(1);
    expect(result[0].effective_confidence).toBeCloseTo(0.8, 5);
    expect(result[0].statement).toBe("fresh claim");
  });

  it("queries only superseded_by IS NULL and non-expired rows at the SQL level", async () => {
    queryMock.mockResolvedValueOnce(rows([]));
    await db.findRelevantMemories({ techniqueIds: ["T1078"] });
    const [sql] = queryMock.mock.calls[0];
    expect(sql).toContain("superseded_by IS NULL");
    expect(sql).toContain("expires_at IS NULL OR expires_at > now()");
  });
});

it("MIN_RETRIEVAL_CONFIDENCE matches the Python side's floor", () => {
  expect(MIN_RETRIEVAL_CONFIDENCE).toBe(0.15);
});
