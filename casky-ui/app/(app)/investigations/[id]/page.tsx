import Link from "next/link";
import { notFound } from "next/navigation";
import { findRelated, findRelevantMemories, getInvestigation } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";
import { formatDate } from "@/lib/format";
import { FindingRemediationForm, FindingStatusForm } from "@/components/finding-controls";
import {
  ConfidenceMeter,
  FindingCard,
  InvestigationStepRow,
  MitreTechniqueChip,
} from "@casky/ui-kit";
import type { StepStatus } from "@/lib/types";

const TABS = [
  "overview",
  "evidence",
  "context",
  "plan",
  "execution",
  "findings",
  "remediation",
  "outcome",
] as const;
type Tab = (typeof TABS)[number];

const TAB_LABELS: Record<Tab, string> = {
  overview: "Overview",
  evidence: "Evidence",
  context: "Context",
  plan: "Plan",
  execution: "Execution",
  findings: "Findings",
  remediation: "Remediation",
  outcome: "Outcome / Memory",
};

const VALID_STEP_STATUSES: StepStatus[] = ["pending", "running", "done", "failed"];
function toStepStatus(status: string | null | undefined): StepStatus {
  return VALID_STEP_STATUSES.includes(status as StepStatus) ? (status as StepStatus) : "pending";
}

export default async function InvestigationDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ tab?: string }>;
}) {
  const { id } = await params;
  const { tab: tabParam } = await searchParams;
  const tab: Tab = (TABS as readonly string[]).includes(tabParam ?? "")
    ? (tabParam as Tab)
    : "overview";

  const investigation = await getInvestigation(id);
  if (!investigation) notFound();

  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <Link href="/investigations" className="text-xs text-white/40 hover:text-white/70">
          ← Investigations
        </Link>
        <div className="flex items-center gap-3 mt-2">
          <h1 className="text-lg font-semibold text-[#EAF2FF]">
            {investigation.domain || investigation.id}
          </h1>
          <StatusPill status={investigation.status} />
        </div>
        <p className="text-xs text-white/35 mt-1 font-mono">{investigation.id}</p>
      </div>

      <div className="flex gap-1 flex-wrap border-b border-white/[0.08]">
        {TABS.map((t) => (
          <Link
            key={t}
            href={`/investigations/${id}?tab=${t}`}
            className={`text-xs px-3 py-2 border-b-2 -mb-px transition-colors ${
              tab === t
                ? "border-emerald-500 text-white"
                : "border-transparent text-white/40 hover:text-white/70"
            }`}
          >
            {TAB_LABELS[t]}
          </Link>
        ))}
      </div>

      {tab === "overview" && (
        <div className="space-y-5">
          <div className="rounded-xl p-5 bg-white/[0.03] border border-white/[0.07] space-y-4">
            <ConfidenceMeter confidence={Number(investigation.confidence ?? 0)} />
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-xs text-white/35 mb-1">Agent used</div>
                <div className="text-[#EAF2FF]">{investigation.agent_used || "—"}</div>
              </div>
              <div>
                <div className="text-xs text-white/35 mb-1">Model used</div>
                <div className="text-[#EAF2FF]">{investigation.model_used || "—"}</div>
              </div>
              <div>
                <div className="text-xs text-white/35 mb-1">Created</div>
                <div className="text-[#EAF2FF]">{formatDate(investigation.created_at)}</div>
              </div>
              <div>
                <div className="text-xs text-white/35 mb-1">Updated</div>
                <div className="text-[#EAF2FF]">{formatDate(investigation.updated_at)}</div>
              </div>
            </div>
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white/60 mb-2">Evidence gaps</h2>
            {investigation.evidence_gaps.length === 0 ? (
              <p className="text-sm text-white/35">None recorded.</p>
            ) : (
              <ul className="list-disc list-inside text-sm text-white/70 space-y-1">
                {investigation.evidence_gaps.map((gap, i) => (
                  <li key={i}>{gap}</li>
                ))}
              </ul>
            )}
          </div>

          {investigation.outcome_summary && (
            <div className="rounded-xl p-5 bg-white/[0.03] border border-white/[0.07] space-y-3">
              <h2 className="text-sm font-semibold text-white/60">Analyst outcome</h2>
              <p className="text-sm text-white/75 whitespace-pre-wrap">
                {investigation.outcome_summary}
              </p>
              {investigation.confirmed_technique_ids.length > 0 && (
                <div>
                  <div className="text-xs text-white/35 mb-1.5">Confirmed techniques</div>
                  <div className="flex gap-1.5 flex-wrap">
                    {investigation.confirmed_technique_ids.map((t) => (
                      <MitreTechniqueChip key={t} techniqueId={t} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {tab === "evidence" && (
        <div className="rounded-xl border border-white/[0.08] p-4">
          {investigation.evidence_text ? (
            <pre className="whitespace-pre-wrap text-sm text-white/75 font-mono">
              {investigation.evidence_text}
            </pre>
          ) : (
            <p className="text-sm text-white/35">No evidence text recorded.</p>
          )}
        </div>
      )}

      {tab === "context" && (
        <div className="space-y-3">
          {investigation.cve_references.length === 0 && (
            <p className="text-sm text-white/35">No CVE references recorded.</p>
          )}
          {investigation.cve_references.map((cve) => (
            <div
              key={cve.id}
              className="rounded-xl p-4 bg-white/[0.03] border border-white/[0.07]"
            >
              <div className="flex items-center gap-2 mb-2">
                <span className="font-mono text-sm text-[#EAF2FF]">{cve.cve_id}</span>
                {cve.cvss_score != null && (
                  <span className="text-xs text-white/45">
                    CVSS {cve.cvss_score} {cve.cvss_severity ? `(${cve.cvss_severity})` : ""}
                  </span>
                )}
                {cve.is_kev && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                    KEV
                  </span>
                )}
              </div>
              {cve.technique_ids.length > 0 && (
                <div className="flex gap-1.5 flex-wrap mb-2">
                  {cve.technique_ids.map((t) => (
                    <MitreTechniqueChip key={t} techniqueId={t} />
                  ))}
                </div>
              )}
              {cve.ai_analysis && (
                <p className="text-sm text-white/60 mt-1">{cve.ai_analysis}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === "plan" && (
        <div className="space-y-6">
          <div className="space-y-2">
            {investigation.steps.length === 0 && (
              <p className="text-sm text-white/35">No plan steps recorded.</p>
            )}
            {investigation.steps.map((step) => (
              <InvestigationStepRow
                key={step.id}
                skill_slug={step.skill_slug || "(unknown skill)"}
                rationale={step.rationale}
                status={toStepStatus(step.status)}
              />
            ))}
          </div>

          <MitreCoveragePanel
            steps={investigation.steps}
            findings={investigation.findings}
          />
        </div>
      )}

      {tab === "execution" && (
        <div className="rounded-xl border border-white/[0.08] overflow-hidden">
          {investigation.skill_executions.length === 0 ? (
            <p className="text-sm text-white/35 px-4 py-6">No executions recorded.</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-white/[0.03] border-b border-white/[0.08] text-left text-white/40">
                  <th className="px-3 py-2.5 font-semibold">Skill</th>
                  <th className="px-3 py-2.5 font-semibold">Started</th>
                  <th className="px-3 py-2.5 font-semibold">Completed</th>
                  <th className="px-3 py-2.5 font-semibold">Exit</th>
                  <th className="px-3 py-2.5 font-semibold">Score</th>
                </tr>
              </thead>
              <tbody>
                {investigation.skill_executions
                  .slice()
                  .sort((a, b) => (a.started_at || "").localeCompare(b.started_at || ""))
                  .map((exec) => (
                    <tr key={exec.id} className="border-b border-white/[0.04] align-top">
                      <td className="px-3 py-3 font-mono text-[#EAF2FF]">
                        {exec.skill_slug || "—"}
                      </td>
                      <td className="px-3 py-3 text-white/55">{formatDate(exec.started_at)}</td>
                      <td className="px-3 py-3 text-white/55">{formatDate(exec.completed_at)}</td>
                      <td className="px-3 py-3 text-white/55">
                        {exec.exit_code ?? "—"}
                      </td>
                      <td className="px-3 py-3 text-white/55">
                        {exec.score_pct != null ? `${exec.score_pct}%` : "—"}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === "findings" && (
        <div className="space-y-4">
          {investigation.findings.length === 0 && (
            <p className="text-sm text-white/35">No findings recorded.</p>
          )}
          {investigation.findings.map((f) => (
            <FindingCard
              key={f.id}
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
          ))}
        </div>
      )}

      {tab === "remediation" && (
        <RemediationTabContent findings={investigation.findings} />
      )}

      {tab === "outcome" && <OutcomeTabContent investigation={investigation} />}
    </div>
  );
}

function MitreCoveragePanel({
  steps,
  findings,
}: {
  steps: { technique_id: string | null; technique_name: string | null }[];
  findings: { mitre_technique_id: string | null }[];
}) {
  const stepTechniques = new Map<string, string | null>();
  for (const s of steps) {
    if (s.technique_id) stepTechniques.set(s.technique_id, s.technique_name);
  }
  const findingTechniques = new Set(
    findings.map((f) => f.mitre_technique_id).filter((t): t is string => Boolean(t))
  );
  const allTechniques = new Set([...stepTechniques.keys(), ...findingTechniques]);

  if (allTechniques.size === 0) return null;

  return (
    <div>
      <h2 className="text-sm font-semibold text-white/60 mb-2">MITRE technique coverage</h2>
      <p className="text-xs text-white/35 mb-3">
        Techniques planned for (from investigation steps) vs. techniques a finding was actually
        recorded against — narrow, evidence-linked coverage, not a GRC framework mapping.
      </p>
      <div className="rounded-xl border border-white/[0.08] overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-white/[0.03] border-b border-white/[0.08] text-left text-white/40">
              <th className="px-3 py-2.5 font-semibold">Technique</th>
              <th className="px-3 py-2.5 font-semibold">Planned</th>
              <th className="px-3 py-2.5 font-semibold">Finding recorded</th>
            </tr>
          </thead>
          <tbody>
            {[...allTechniques].sort().map((t) => (
              <tr key={t} className="border-b border-white/[0.04]">
                <td className="px-3 py-2.5">
                  <MitreTechniqueChip
                    techniqueId={t}
                    techniqueName={stepTechniques.get(t) || undefined}
                  />
                </td>
                <td className="px-3 py-2.5 text-white/55">
                  {stepTechniques.has(t) ? "yes" : "—"}
                </td>
                <td className="px-3 py-2.5 text-white/55">
                  {findingTechniques.has(t) ? "yes" : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RemediationTabContent({
  findings,
}: {
  findings: import("@/lib/types").Finding[];
}) {
  const needsRemediation = findings.filter(
    (f) => f.status === "open" || f.status === "in_progress"
  );
  const grouped = {
    open: needsRemediation.filter((f) => f.status === "open"),
    in_progress: needsRemediation.filter((f) => f.status === "in_progress"),
  };

  if (needsRemediation.length === 0) {
    return <p className="text-sm text-white/35">No findings currently need remediation.</p>;
  }

  return (
    <div className="space-y-8">
      {(["open", "in_progress"] as const).map((status) =>
        grouped[status].length === 0 ? null : (
          <div key={status}>
            <h2 className="text-sm font-semibold text-white/60 mb-3 capitalize">
              {status.replace("_", " ")} ({grouped[status].length})
            </h2>
            <div className="space-y-4">
              {grouped[status].map((f) => (
                <FindingCard
                  key={f.id}
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
              ))}
            </div>
          </div>
        )
      )}
    </div>
  );
}

async function OutcomeTabContent({
  investigation,
}: {
  investigation: import("@/lib/types").InvestigationDetail;
}) {
  const techniqueIds = [
    ...new Set(
      investigation.steps.map((s) => s.technique_id).filter((t): t is string => Boolean(t))
    ),
  ];
  const cveIds = [...new Set(investigation.cve_references.map((c) => c.cve_id))];

  const [related, memories] = await Promise.all([
    findRelated({
      techniqueIds,
      cveIds,
      domain: investigation.domain,
      excludeId: investigation.id,
      limit: 10,
    }),
    // No stored ips/hostnames columns exist on an investigation today (only
    // technique_id/cve_id are persisted per-step/reference) — passing empty
    // arrays for those two mirrors what's actually available, same honesty
    // rule LocalHistoryAdapter's own domain-omission comment follows.
    findRelevantMemories({ cveIds, techniqueIds, limit: 20 }),
  ]);

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-sm font-semibold text-white/60 mb-1">Organizational memory</h2>
        <p className="text-xs text-white/35 mb-3">
          Durable claims extracted from past investigations&apos; analyst-confirmed outcomes
          (casky_pipeline/memory.py) whose entities overlap this investigation — confidence decays
          over a 90-day half-life and hard-expires per memory, so a stale claim drops out on its
          own rather than needing manual cleanup.
        </p>
        {memories.length === 0 && (
          <p className="text-sm text-white/35">No relevant organizational memory found.</p>
        )}
        <div className="space-y-3">
          {memories.map((m) => (
            <div
              key={m.id}
              className="rounded-xl p-4 bg-white/[0.03] border border-white/[0.07] space-y-2"
            >
              <div className="flex items-start justify-between gap-3">
                <p className="text-sm text-[#EAF2FF]">{m.statement}</p>
                {m.escalation_recommended ? (
                  <span className="shrink-0 text-xs px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                    escalate
                  </span>
                ) : (
                  <span className="shrink-0 text-xs px-1.5 py-0.5 rounded bg-white/5 text-white/45 border border-white/10">
                    stand down
                  </span>
                )}
              </div>
              <p className="text-xs text-white/55">{m.rationale}</p>
              <div className="flex items-center gap-3 text-xs text-white/35">
                <span>confidence {Math.round(m.effective_confidence * 100)}%</span>
                <Link
                  href={`/investigations/${m.source_investigation_id}`}
                  className="hover:text-white/60"
                >
                  source investigation →
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-sm font-semibold text-white/60 mb-1">Related investigations</h2>
        <p className="text-xs text-white/35 mb-3">
          Past investigations that overlap this one by shared MITRE techniques, shared CVEs, or the
          same domain — the local-history signal available to future plans.
        </p>
        {related.length === 0 && (
          <p className="text-sm text-white/35">No related investigations found.</p>
        )}
        <div className="space-y-3">
          {related.map((r) => (
            <Link
              key={r.id}
              href={`/investigations/${r.id}`}
              className="block rounded-xl p-4 bg-white/[0.03] border border-white/[0.07] hover:bg-white/[0.05] transition-colors"
            >
              <div className="flex items-center justify-between gap-3 mb-2">
                <span className="text-sm text-[#EAF2FF]">{r.domain || r.id}</span>
                <StatusPill status={r.status} />
              </div>
              <div className="flex gap-2 flex-wrap text-xs">
                {r.domain_match && (
                  <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                    same domain
                  </span>
                )}
                {r.matched_technique_ids.map((t) => (
                  <MitreTechniqueChip key={t} techniqueId={t} />
                ))}
                {r.matched_cve_ids.map((c) => (
                  <span
                    key={c}
                    className="px-1.5 py-0.5 rounded bg-white/5 text-white/55 font-mono"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
