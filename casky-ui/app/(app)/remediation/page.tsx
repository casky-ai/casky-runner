import Link from "next/link";
import { listFindings } from "@/lib/db";
import { FindingRemediationForm, FindingStatusForm } from "@/components/finding-controls";
import { FindingCard, SEVERITY_ORDER } from "@casky/ui-kit";
import type { Finding } from "@/lib/types";

// "Still needing remediation" = open or in_progress, per the spec's default
// scope for this page (distinct from /findings, which shows everything).
export default async function RemediationPage() {
  const [open, inProgress] = await Promise.all([
    listFindings({ status: "open", limit: 200 }),
    listFindings({ status: "in_progress", limit: 200 }),
  ]);

  const bySeverity = (list: Finding[]) =>
    list.slice().sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  const sections: Array<{ label: string; findings: Finding[] }> = [
    { label: "Open", findings: bySeverity(open) },
    { label: "In progress", findings: bySeverity(inProgress) },
  ];

  const total = open.length + inProgress.length;

  return (
    <div className="max-w-4xl space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-[#EAF2FF]">Remediation</h1>
        <p className="text-sm text-white/45 mt-1">
          {total} finding{total === 1 ? "" : "s"} still need remediation
        </p>
      </div>

      {total === 0 && (
        <p className="text-sm text-white/35">Nothing outstanding — every finding is resolved or accepted.</p>
      )}

      {sections.map(
        (section) =>
          section.findings.length > 0 && (
            <div key={section.label}>
              <h2 className="text-sm font-semibold text-white/60 mb-3">
                {section.label} ({section.findings.length})
              </h2>
              <div className="space-y-4">
                {section.findings.map((f) => (
                  <div key={f.id}>
                    <Link
                      href={`/investigations/${f.investigation_id}?tab=remediation`}
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
          )
      )}
    </div>
  );
}
