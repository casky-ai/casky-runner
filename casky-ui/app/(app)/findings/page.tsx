import Link from "next/link";
import { listFindings } from "@/lib/db";
import { FindingStatusForm, FindingRemediationForm } from "@/components/finding-controls";
import { FindingCard, SEVERITY_ORDER } from "@casky/ui-kit";
import type { FindingStatus } from "@/lib/types";

const STATUSES: FindingStatus[] = ["open", "in_progress", "resolved", "accepted"];

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string; status?: string }>;
}) {
  const { severity, status } = await searchParams;
  const findings = await listFindings({ severity, status, limit: 200 });

  const buildHref = (next: { severity?: string; status?: string }) => {
    const params = new URLSearchParams();
    const sev = next.severity ?? severity;
    const st = next.status ?? status;
    if (sev) params.set("severity", sev);
    if (st) params.set("status", st);
    const qs = params.toString();
    return qs ? `/findings?${qs}` : "/findings";
  };

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-[#EAF2FF]">Findings</h1>
        <p className="text-sm text-white/45 mt-1">{findings.length} shown, across all investigations</p>
      </div>

      <div className="flex flex-wrap gap-4">
        <FilterGroup
          label="Severity"
          current={severity}
          options={SEVERITY_ORDER}
          buildHref={(v) => buildHref({ severity: v })}
          clearHref={buildHref({ severity: undefined })}
        />
        <FilterGroup
          label="Status"
          current={status}
          options={STATUSES}
          buildHref={(v) => buildHref({ status: v })}
          clearHref={buildHref({ status: undefined })}
        />
      </div>

      <div className="space-y-4">
        {findings.length === 0 && <p className="text-sm text-white/35">No findings match this filter.</p>}
        {findings.map((f) => (
          <div key={f.id}>
            <Link
              href={`/investigations/${f.investigation_id}?tab=findings`}
              className="text-xs text-white/35 hover:text-white/70 mb-1 inline-block"
            >
              from investigation {f.investigation_id.slice(0, 8)}…
            </Link>
            <FindingCard
              title={f.title}
              description={f.description}
              severity={f.severity}
              affected_asset={f.affected_asset}
              remediation={f.remediation}
              raw_evidence={f.raw_evidence}
              mitre_technique_id={f.mitre_technique_id}
              status={f.status}
              actions={<FindingStatusForm id={f.id} status={f.status} />}
              footer={<FindingRemediationForm id={f.id} remediation={f.remediation} />}
            />
          </div>
        ))}
      </div>
    </div>
  );
}

function FilterGroup({
  label,
  current,
  options,
  buildHref,
  clearHref,
}: {
  label: string;
  current: string | undefined;
  options: readonly string[];
  buildHref: (value: string) => string;
  clearHref: string;
}) {
  return (
    <div>
      <div className="text-xs text-white/35 mb-1.5">{label}</div>
      <div className="flex gap-1.5 flex-wrap">
        <Link
          href={clearHref}
          className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
            !current
              ? "bg-white/10 border-white/20 text-white"
              : "border-white/10 text-white/45 hover:text-white/80"
          }`}
        >
          all
        </Link>
        {options.map((opt) => (
          <Link
            key={opt}
            href={buildHref(opt)}
            className={`text-xs px-2.5 py-1 rounded-full border transition-colors capitalize ${
              current === opt
                ? "bg-white/10 border-white/20 text-white"
                : "border-white/10 text-white/45 hover:text-white/80"
            }`}
          >
            {opt.replace("_", " ")}
          </Link>
        ))}
      </div>
    </div>
  );
}
