/**
 * TypeScript mirror of the casky_db Postgres schema
 * (casky_db/migrations/0001_init.sql, 0002_outcomes_and_feedback.sql,
 * 0003_investigation_memories.sql) and of the nested shapes casky_db/store.py's
 * read functions return. Column names/types below are taken verbatim from
 * those migration files — do not add/rename fields without updating the SQL
 * there first.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type FindingStatus = "open" | "in_progress" | "resolved" | "accepted";
export type StepStatus = "pending" | "running" | "done" | "failed";

export interface Investigation {
  id: string;
  domain: string | null;
  evidence_text: string | null;
  status: string;
  confidence: number | null;
  evidence_gaps: string[];
  agent_used: string | null;
  model_used: string | null;
  created_at: string;
  updated_at: string;
  // migration 0002 — analyst-written outcome, the quality gate before memory
  // extraction runs (see casky_pipeline/memory.py). Both null/empty until an
  // operator records an outcome via the CLI's post-run prompt.
  outcome_summary: string | null;
  confirmed_technique_ids: string[];
}

/**
 * migration 0003 (investigation_memories) — an extracted, decaying
 * organizational-memory claim. `effective_confidence` is NOT a DB column —
 * it's computed client-side by decayedConfidence() (lib/memory.ts), mirroring
 * casky_pipeline/memory.py's decayed_confidence() exactly, so the UI's
 * ranking/floor matches what the pipeline itself would surface.
 */
export interface Memory {
  id: string;
  source_investigation_id: string;
  statement: string;
  rationale: string;
  conditions: Record<string, unknown>;
  applies_to: {
    cve_ids?: string[];
    technique_ids?: string[];
    ips?: string[];
    hostnames?: string[];
  };
  confidence: number;
  escalation_recommended: boolean;
  created_at: string;
  last_reinforced_at: string;
  expires_at: string | null;
  superseded_by: string | null;
}

export interface MemoryMatch extends Memory {
  effective_confidence: number;
}

export interface InvestigationStep {
  id: string;
  investigation_id: string;
  skill_slug: string | null;
  skill_category: string | null;
  skill_document: string | null;
  technique_id: string | null;
  technique_name: string | null;
  rationale: string | null;
  evidence_focus: string | null;
  step_order: number | null;
  status: StepStatus | string;
}

export interface CveReference {
  id: string;
  investigation_id: string;
  cve_id: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  is_kev: boolean;
  technique_ids: string[];
  skill_ids: string[];
  ai_analysis: string | null;
}

export interface SkillExecution {
  id: string;
  investigation_id: string;
  step_id: string | null;
  skill_slug: string | null;
  agent_used: string | null;
  model_used: string | null;
  exit_code: number | null;
  started_at: string | null;
  completed_at: string | null;
  output: string | null;
  score_pct: number | null;
}

export interface Finding {
  id: string;
  investigation_id: string;
  skill_execution_id: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  raw_evidence: string | null;
  mitre_technique_id: string | null;
  affected_asset: string | null;
  remediation: string | null;
  status: FindingStatus;
  created_at: string;
}

export interface ConsolidatedReport {
  id: string;
  investigation_id: string;
  generated_at: string;
  summary: string | null;
  risk_rating: string | null;
  markdown: string | null;
  report_json: ConsolidatedReportJson | null;
}

/**
 * Shape actually produced by harness.py's generate_consolidated_report()
 * (read directly from harness.py rather than assumed): plan_id, domain,
 * generated_at, steps_run, findings[] (each with title/severity/description
 * among other keys — the same shape record_findings() persists), and
 * summaries[] (plain strings). There is NO structured "remediation
 * actions" array (priority/effort/impact) anywhere in this shape — only
 * each finding's own free-text `remediation` field — so report_json does
 * NOT map 1:1 onto ui-kit's RemediationAction type. It DOES map onto
 * ui-kit's KeyFinding type (title/severity/description) via
 * findings[].
 */
export interface ConsolidatedReportJson {
  plan_id?: string;
  domain?: string;
  generated_at?: string;
  steps_run?: number;
  findings?: Array<{
    title?: string;
    severity?: string;
    description?: string;
    technique_id?: string;
    proof?: string;
    mitre_technique?: string;
    affected_asset?: string;
    remediation?: string;
    status?: string;
  }>;
  summaries?: string[];
}

export interface InvestigationDetail extends Investigation {
  steps: InvestigationStep[];
  cve_references: CveReference[];
  findings: Finding[];
  skill_executions: SkillExecution[];
  consolidated_report: ConsolidatedReport | null;
}

export interface RelatedInvestigation extends Investigation {
  matched_cve_ids: string[];
  matched_technique_ids: string[];
  domain_match: boolean;
}
