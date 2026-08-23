/**
 * Shared presentational types for @casky/ui-kit.
 *
 * These are intentionally NOT imported from apps/web/lib/supabase/types.ts —
 * this package must have zero dependency on that app's DB layer. They are
 * structurally compatible with the real `findings` table shape and
 * `consolidated_report` shape (apps/web/lib/supabase/types.ts) so apps/web
 * can pass its own row objects straight through as props, but this package
 * defines its own copies so it never pulls in @casky/supabase-client, auth,
 * workspaces, or billing.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'accepted';

export interface FindingCardData {
  title: string;
  description?: string | null;
  severity: Severity;
  cvss_score?: number | null;
  affected_asset?: string | null;
  remediation?: string | null;
  raw_evidence?: string | null;
  mitre_technique_id?: string | null;
  status?: FindingStatus | null;
}

export interface RemediationAction {
  priority: number | string;
  action: string;
  effort: string;
  impact: string;
}

export interface KeyFinding {
  title: string;
  severity: Severity;
  description: string;
}

export type StepStatus = 'pending' | 'running' | 'done' | 'failed';

export interface InvestigationStep {
  skill_slug: string;
  rationale?: string | null;
  status: StepStatus;
}
