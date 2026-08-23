import { beforeEach, describe, expect, it, vi } from "vitest";

const queryMock = vi.fn();

vi.mock("pg", () => ({
  Pool: vi.fn(function Pool() { return { query: queryMock }; }),
}));

process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";

const db = await import("@/lib/db");

function rows<T>(data: T[]) {
  return { rows: data };
}

beforeEach(() => {
  queryMock.mockReset();
});

describe("getInvestigation", () => {
  it("returns null when the investigation does not exist", async () => {
    queryMock.mockResolvedValueOnce(rows([]));
    const result = await db.getInvestigation("missing-id");
    expect(result).toBeNull();
    expect(queryMock).toHaveBeenCalledWith(
      "SELECT * FROM investigations WHERE id = $1",
      ["missing-id"]
    );
  });

  it("assembles the full nested shape mirroring store.py's get_investigation", async () => {
    queryMock
      .mockResolvedValueOnce(rows([{ id: "inv-1", domain: "example.com" }])) // investigation
      .mockResolvedValueOnce(rows([{ id: "step-1" }])) // steps
      .mockResolvedValueOnce(rows([{ id: "cve-1" }])) // cve_references
      .mockResolvedValueOnce(rows([{ id: "finding-1" }])) // findings
      .mockResolvedValueOnce(rows([{ id: "exec-1" }])) // skill_executions
      .mockResolvedValueOnce(rows([{ id: "report-1" }])); // consolidated_reports

    const result = await db.getInvestigation("inv-1");

    expect(result).toMatchObject({
      id: "inv-1",
      domain: "example.com",
      steps: [{ id: "step-1" }],
      cve_references: [{ id: "cve-1" }],
      findings: [{ id: "finding-1" }],
      skill_executions: [{ id: "exec-1" }],
      consolidated_report: { id: "report-1" },
    });
  });

  it("returns consolidated_report: null when none exists yet", async () => {
    queryMock
      .mockResolvedValueOnce(rows([{ id: "inv-2" }]))
      .mockResolvedValueOnce(rows([]))
      .mockResolvedValueOnce(rows([]))
      .mockResolvedValueOnce(rows([]))
      .mockResolvedValueOnce(rows([]))
      .mockResolvedValueOnce(rows([]));

    const result = await db.getInvestigation("inv-2");
    expect(result?.consolidated_report).toBeNull();
  });
});

describe("listInvestigations", () => {
  it("filters by status when provided", async () => {
    queryMock.mockResolvedValueOnce(rows([{ id: "inv-1" }]));
    await db.listInvestigations({ status: "completed", limit: 10 });
    expect(queryMock).toHaveBeenCalledWith(
      "SELECT * FROM investigations WHERE status = $1 ORDER BY created_at DESC LIMIT $2",
      ["completed", 10]
    );
  });

  it("omits the status filter when not provided, defaulting limit to 50", async () => {
    queryMock.mockResolvedValueOnce(rows([]));
    await db.listInvestigations();
    expect(queryMock).toHaveBeenCalledWith(
      "SELECT * FROM investigations ORDER BY created_at DESC LIMIT $1",
      [50]
    );
  });
});

describe("findRelated", () => {
  it("computes matched_cve_ids / matched_technique_ids / domain_match per result", async () => {
    queryMock
      .mockResolvedValueOnce(
        rows([{ id: "inv-1", domain: "example.com" }, { id: "inv-2", domain: "other.com" }])
      )
      // inv-1 sub-queries
      .mockResolvedValueOnce(rows([{ cve_id: "CVE-2024-1" }]))
      .mockResolvedValueOnce(rows([{ technique_id: "T1595" }]))
      // inv-2 sub-queries
      .mockResolvedValueOnce(rows([]))
      .mockResolvedValueOnce(rows([{ technique_id: "T1595" }]));

    const results = await db.findRelated({
      techniqueIds: ["T1595"],
      cveIds: ["CVE-2024-1"],
      domain: "example.com",
    });

    expect(results).toEqual([
      {
        id: "inv-1",
        domain: "example.com",
        matched_cve_ids: ["CVE-2024-1"],
        matched_technique_ids: ["T1595"],
        domain_match: true,
      },
      {
        id: "inv-2",
        domain: "other.com",
        matched_cve_ids: [],
        matched_technique_ids: ["T1595"],
        domain_match: false,
      },
    ]);
  });

  it("skips the cve/technique sub-queries entirely when both id lists are empty", async () => {
    queryMock.mockResolvedValueOnce(rows([{ id: "inv-1", domain: null }]));
    await db.findRelated({ techniqueIds: [], cveIds: [], domain: null });
    expect(queryMock).toHaveBeenCalledTimes(1);
  });
});

describe("settings", () => {
  it("getSetting returns the fallback when the key is unset", async () => {
    queryMock.mockResolvedValueOnce(rows([]));
    const value = await db.getSetting("missing_key", "fallback");
    expect(value).toBe("fallback");
  });

  it("getSetting returns the stored value when present", async () => {
    queryMock.mockResolvedValueOnce(rows([{ value: "claude" }]));
    const value = await db.getSetting("default_agent", "");
    expect(value).toBe("claude");
  });

  it("setSetting upserts with an explicit jsonb cast", async () => {
    queryMock.mockResolvedValueOnce(rows([]));
    await db.setSetting("default_agent", "claude");
    const [sql, params] = queryMock.mock.calls[0];
    expect(sql).toContain("ON CONFLICT (key) DO UPDATE");
    expect(params).toEqual(["default_agent", JSON.stringify("claude")]);
  });
});

describe("findings", () => {
  it("listFindings combines status and severity filters", async () => {
    queryMock.mockResolvedValueOnce(rows([]));
    await db.listFindings({ status: "open", severity: "critical", limit: 5 });
    const [sql, params] = queryMock.mock.calls[0];
    expect(sql).toContain("status = $1");
    expect(sql).toContain("severity = $2");
    expect(params).toEqual(["open", "critical", 5]);
  });

  it("updateFindingStatus writes the new status by id", async () => {
    queryMock.mockResolvedValueOnce(rows([]));
    await db.updateFindingStatus("finding-1", "resolved");
    expect(queryMock).toHaveBeenCalledWith("UPDATE findings SET status = $1 WHERE id = $2", [
      "resolved",
      "finding-1",
    ]);
  });
});

describe("DatabaseUnavailable", () => {
  it("wraps a failing query in DatabaseUnavailable rather than the raw pg error", async () => {
    queryMock.mockRejectedValueOnce(new Error("connection refused"));
    await expect(db.listInvestigations()).rejects.toBeInstanceOf(db.DatabaseUnavailable);
  });
});
