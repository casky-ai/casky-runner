import Link from "next/link";
import { listInvestigations } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";
import { formatDate } from "@/lib/format";

const STATUS_FILTERS = ["all", "draft", "planned", "running", "completed", "failed"];

export default async function InvestigationsPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string }>;
}) {
  const { status } = await searchParams;
  const activeStatus = status && status !== "all" ? status : undefined;
  const investigations = await listInvestigations({ status: activeStatus, limit: 200 });

  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-[#EAF2FF]">Investigations</h1>
        <p className="text-sm text-white/45 mt-1">{investigations.length} shown</p>
      </div>

      <div className="flex gap-2 flex-wrap">
        {STATUS_FILTERS.map((s) => (
          <Link
            key={s}
            href={s === "all" ? "/investigations" : `/investigations?status=${s}`}
            className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
              (activeStatus ?? "all") === s
                ? "bg-white/10 border-white/20 text-white"
                : "border-white/10 text-white/45 hover:text-white/80"
            }`}
          >
            {s}
          </Link>
        ))}
      </div>

      <div className="rounded-xl border border-white/[0.08] divide-y divide-white/[0.06] overflow-hidden">
        {investigations.length === 0 && (
          <p className="text-sm text-white/35 px-4 py-6">No investigations match this filter.</p>
        )}
        {investigations.map((inv) => (
          <Link
            key={inv.id}
            href={`/investigations/${inv.id}`}
            className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-white/[0.03] transition-colors"
          >
            <div className="min-w-0">
              <div className="text-sm text-[#EAF2FF] truncate">{inv.domain || inv.id}</div>
              <div className="text-xs text-white/35 mt-0.5 font-mono">{inv.id}</div>
            </div>
            <div className="flex items-center gap-4 shrink-0">
              <span className="text-xs text-white/35">{formatDate(inv.created_at)}</span>
              <StatusPill status={inv.status} />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
