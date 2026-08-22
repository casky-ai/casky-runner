import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("@/lib/db", () => ({
  getInvestigation: vi.fn(),
  listInvestigations: vi.fn(),
  countInvestigationsByStatus: vi.fn(),
  countOpenFindingsBySeverity: vi.fn(),
  findRelated: vi.fn(),
  findRelevantMemories: vi.fn(),
  listFindings: vi.fn(),
  getFinding: vi.fn(),
  updateFindingStatus: vi.fn(),
  updateFindingRemediation: vi.fn(),
  listReports: vi.fn(),
  getReport: vi.fn(),
  getSetting: vi.fn(),
  setSetting: vi.fn(),
  pingDatabase: vi.fn(),
  DatabaseUnavailable: class DatabaseUnavailable extends Error {},
}));

vi.mock("@/lib/actions", () => ({
  loginAction: vi.fn(),
  logoutAction: vi.fn(),
  updateFindingStatusAction: vi.fn(),
  updateFindingRemediationAction: vi.fn(),
  saveSettingsAction: vi.fn(),
}));

const db = await import("@/lib/db");

const now = new Date().toISOString();

const baseInvestigation = {
  id: "inv-1",
  domain: "example.com",
  evidence_text: "raw evidence",
  status: "completed",
  confidence: 0.8,
  evidence_gaps: ["missing DNS logs"],
  agent_used: "claude",
  model_used: "claude-opus-4-6",
  created_at: now,
  updated_at: now,
  outcome_summary: null,
  confirmed_technique_ids: [],
};

const baseFinding = {
  id: "finding-1",
  investigation_id: "inv-1",
  skill_execution_id: null,
  title: "Exposed admin panel",
  description: "The admin panel is reachable without auth.",
  severity: "high" as const,
  raw_evidence: null,
  mitre_technique_id: "T1595",
  affected_asset: "admin.example.com",
  remediation: "Restrict access via IP allowlist.",
  status: "open" as const,
  created_at: now,
};

beforeEach(() => {
  vi.mocked(db.listInvestigations).mockResolvedValue([baseInvestigation]);
  vi.mocked(db.countInvestigationsByStatus).mockResolvedValue({ completed: 1 });
  vi.mocked(db.countOpenFindingsBySeverity).mockResolvedValue({ high: 1 });
  vi.mocked(db.getInvestigation).mockResolvedValue({
    ...baseInvestigation,
    steps: [],
    cve_references: [],
    findings: [baseFinding],
    skill_executions: [],
    consolidated_report: null,
  });
  vi.mocked(db.findRelated).mockResolvedValue([]);
  vi.mocked(db.findRelevantMemories).mockResolvedValue([]);
  vi.mocked(db.listFindings).mockResolvedValue([baseFinding]);
  vi.mocked(db.listReports).mockResolvedValue([
    {
      id: "report-1",
      investigation_id: "inv-1",
      domain: "example.com",
      generated_at: now,
      summary: "Summary text",
      risk_rating: "high",
      markdown: "# Report",
      report_json: { findings: [{ title: "Exposed admin panel", severity: "high", description: "desc" }] },
    },
  ]);
  vi.mocked(db.getReport).mockResolvedValue({
    id: "report-1",
    investigation_id: "inv-1",
    domain: "example.com",
    generated_at: now,
    summary: "Summary text",
    risk_rating: "high",
    markdown: "# Report\n\nBody",
    report_json: { findings: [{ title: "Exposed admin panel", severity: "high", description: "desc", remediation: "fix it" }] },
  });
  vi.mocked(db.getSetting).mockImplementation(async (key: string, fallback: unknown) =>
    key === "tools" ? [] : (fallback ?? "")
  );
  vi.mocked(db.pingDatabase).mockResolvedValue(true);
});

describe("page smoke tests", () => {
  it("Dashboard renders without crashing", async () => {
    const { default: DashboardPage } = await import("@/app/(app)/page");
    render(await DashboardPage());
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("example.com")).toBeInTheDocument();
  });

  it("Investigations list renders without crashing", async () => {
    const { default: InvestigationsPage } = await import("@/app/(app)/investigations/page");
    render(await InvestigationsPage({ searchParams: Promise.resolve({}) }));
    expect(screen.getByText("Investigations")).toBeInTheDocument();
  });

  it("Investigation detail renders without crashing", async () => {
    const { default: InvestigationDetailPage } = await import(
      "@/app/(app)/investigations/[id]/page"
    );
    render(
      await InvestigationDetailPage({
        params: Promise.resolve({ id: "inv-1" }),
        searchParams: Promise.resolve({}),
      })
    );
    expect(screen.getByText("example.com")).toBeInTheDocument();
  });

  it("Findings list renders without crashing", async () => {
    const { default: FindingsPage } = await import("@/app/(app)/findings/page");
    render(await FindingsPage({ searchParams: Promise.resolve({}) }));
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("Exposed admin panel")).toBeInTheDocument();
  });

  it("Remediation page renders without crashing", async () => {
    vi.mocked(db.listFindings).mockImplementation(async ({ status } = {}) =>
      status === "open" ? [baseFinding] : []
    );
    const { default: RemediationPage } = await import("@/app/(app)/remediation/page");
    render(await RemediationPage());
    expect(screen.getByText("Remediation")).toBeInTheDocument();
  });

  it("Reports list renders without crashing", async () => {
    const { default: ReportsPage } = await import("@/app/(app)/reports/page");
    render(await ReportsPage());
    expect(screen.getByText("Reports")).toBeInTheDocument();
  });

  it("Report detail renders without crashing", async () => {
    const { default: ReportDetailPage } = await import("@/app/(app)/reports/[id]/page");
    render(await ReportDetailPage({ params: Promise.resolve({ id: "report-1" }) }));
    expect(screen.getByText("Summary")).toBeInTheDocument();
  });

  it("Settings page renders without crashing", async () => {
    const { default: SettingsPage } = await import("@/app/(app)/settings/page");
    render(await SettingsPage());
    expect(screen.getByText("Settings")).toBeInTheDocument();
    expect(screen.getByText("connected")).toBeInTheDocument();
  });

  it("Login page renders without crashing", async () => {
    const { default: LoginPage } = await import("@/app/login/page");
    render(await LoginPage({ searchParams: Promise.resolve({}) }));
    expect(screen.getByText("Casky Box")).toBeInTheDocument();
    expect(screen.getByLabelText("Admin password")).toBeInTheDocument();
  });
});
