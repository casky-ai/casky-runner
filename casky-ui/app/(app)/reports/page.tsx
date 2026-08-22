import Link from "next/link";
import { listReports } from "@/lib/db";
import { formatDate } from "@/lib/format";

export default async function ReportsPage() {
  const reports = await listReports({ limit: 200 });

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-[#EAF2FF]">Reports</h1>
        <p className="text-sm text-white/45 mt-1">{reports.length} consolidated reports</p>
      </div>

      <div className="rounded-xl border border-white/[0.08] divide-y divide-white/[0.06] overflow-hidden">
        {reports.length === 0 && (
          <p className="text-sm text-white/35 px-4 py-6">
            No consolidated reports yet — these are generated at the end of a{" "}
            <code className="font-mono">casky harness</code> run.
          </p>
        )}
        {reports.map((r) => (
          <Link
            key={r.id}
            href={`/reports/${r.id}`}
            className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-white/[0.03] transition-colors"
          >
            <div className="min-w-0">
              <div className="text-sm text-[#EAF2FF] truncate">{r.domain || r.investigation_id}</div>
              <div className="text-xs text-white/35 mt-0.5">{formatDate(r.generated_at)}</div>
            </div>
            {r.risk_rating && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-white/5 text-white/60 capitalize shrink-0">
                {r.risk_rating}
              </span>
            )}
          </Link>
        ))}
      </div>
    </div>
  );
}
