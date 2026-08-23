import Link from "next/link";
import {
  countInvestigationsByStatus,
  countOpenFindingsBySeverity,
  listInvestigations,
} from "@/lib/db";
import { StatusPill } from "@/components/status-pill";
import { formatDate } from "@/lib/format";
import { SEVERITY_ORDER } from "@casky/ui-kit";

export default async function DashboardPage() {
  const [statusCounts, severityCounts, recent] = await Promise.all([
    countInvestigationsByStatus(),
    countOpenFindingsBySeverity(),
    listInvestigations({ limit: 8 }),
  ]);

  const totalInvestigations = Object.values(statusCounts).reduce((a, b) => a + b, 0);
  const totalOpenFindings = Object.values(severityCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="max-w-5xl space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-[#EAF2FF]">Dashboard</h1>
        <p className="text-sm text-white/45 mt-1">
          {totalInvestigations} investigation{totalInvestigations === 1 ? "" : "s"} ·{" "}
          {totalOpenFindings} open/in-progress finding{totalOpenFindings === 1 ? "" : "s"}
        </p>
      </div>

      <section>
        <h2 className="text-sm font-semibold text-white/60 mb-3">Investigations by status</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Object.entries(statusCounts).length === 0 && (
            <p className="text-sm text-white/35">No investigations yet.</p>
          )}
          {Object.entries(statusCounts).map(([status, count]) => (
            <div
              key={status}
              className="rounded-xl p-4 bg-white/[0.03] border border-white/[0.07]"
            >
              <div className="text-2xl font-semibold text-[#EAF2FF]">{count}</div>
              <div className="mt-1">
                <StatusPill status={status} />
              </div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h2 className="text-sm font-semibold text-white/60 mb-3">
          Open findings by severity
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {SEVERITY_ORDER.map((sev) => (
            <div
              key={sev}
              className="rounded-xl p-4 bg-white/[0.03] border border-white/[0.07]"
            >
              <div className="text-2xl font-semibold text-[#EAF2FF]">
                {severityCounts[sev] ?? 0}
              </div>
              <div className="text-xs text-white/45 mt-1 capitalize">{sev}</div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white/60">Recent investigations</h2>
          <Link href="/investigations" className="text-xs text-white/45 hover:text-white">
            View all →
          </Link>
        </div>
        <div className="rounded-xl border border-white/[0.08] divide-y divide-white/[0.06] overflow-hidden">
          {recent.length === 0 && (
            <p className="text-sm text-white/35 px-4 py-6">
              No investigations yet — run <code className="font-mono">casky harness</code>{" "}
              to create one.
            </p>
          )}
          {recent.map((inv) => (
            <Link
              key={inv.id}
              href={`/investigations/${inv.id}`}
              className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-white/[0.03] transition-colors"
            >
              <div className="min-w-0">
                <div className="text-sm text-[#EAF2FF] truncate">{inv.domain || inv.id}</div>
                <div className="text-xs text-white/35 mt-0.5">{formatDate(inv.created_at)}</div>
              </div>
              <StatusPill status={inv.status} />
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}
