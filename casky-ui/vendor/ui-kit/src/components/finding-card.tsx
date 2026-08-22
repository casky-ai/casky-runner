import type { ReactNode } from 'react';
import { cn } from '../lib/cn';
import { SeverityBadge } from './severity-badge';
import { MitreTechniqueChip } from './mitre-technique-chip';
import { MarkdownReport } from './markdown-report';
import type { FindingCardData } from '../types';

export interface FindingCardProps extends FindingCardData {
  className?: string;
  /**
   * Rendered top-right, next to the title — for a status selector or other
   * per-app control that isn't part of the plain finding shape (e.g.
   * apps/web's FindingStatusSelector, which needs a mutation callback this
   * package can't own).
   */
  actions?: ReactNode;
  /**
   * Rendered at the bottom of the card, below the collapsible sections —
   * for app-specific extras like a "from run" link or FeedbackWidget.
   */
  footer?: ReactNode;
}

/**
 * A single finding's card: severity badge, CVSS, MITRE technique chip,
 * title, description, and collapsible remediation/evidence sections.
 * Mirrors the layout of apps/web's findings page finding cards.
 */
export function FindingCard({
  title,
  description,
  severity,
  cvss_score,
  affected_asset,
  remediation,
  raw_evidence,
  mitre_technique_id,
  className,
  actions,
  footer,
}: FindingCardProps) {
  return (
    <div
      className={cn(
        'rounded-xl p-5 bg-white/[0.03] border border-white/[0.07]',
        className
      )}
    >
      <div className="flex items-start justify-between gap-4 mb-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={severity} />
            {cvss_score != null && (
              <span className="text-xs text-white/45">CVSS {cvss_score}</span>
            )}
            {mitre_technique_id && <MitreTechniqueChip techniqueId={mitre_technique_id} />}
          </div>
          <h3 className="font-semibold text-[#EAF2FF]">{title}</h3>
        </div>
        {actions}
      </div>

      {description && (
        <div className="mb-3">
          <MarkdownReport className="text-slate-300 text-sm" markdown={description} />
        </div>
      )}

      {affected_asset && (
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div>
            <div className="text-xs mb-1 text-white/35">Affected asset</div>
            <div className="font-mono text-xs text-[#EAF2FF]">{affected_asset}</div>
          </div>
        </div>
      )}

      {remediation && (
        <details className="mt-3">
          <summary className="text-xs cursor-pointer transition-colors hover:text-white text-white/45">
            Remediation steps
          </summary>
          <div className="mt-2 rounded-lg p-3 bg-white/5">
            <MarkdownReport className="text-slate-300 text-sm" markdown={remediation} />
          </div>
        </details>
      )}

      {raw_evidence && (
        <details className="mt-2">
          <summary className="text-xs cursor-pointer transition-colors hover:text-white text-white/45">
            Raw evidence
          </summary>
          <pre className="mt-2 text-slate-300 text-xs rounded-lg p-3 overflow-auto max-h-32 font-mono bg-black/30">
            {raw_evidence}
          </pre>
        </details>
      )}

      {footer && (
        <div className="mt-3 pt-3 border-t border-white/[0.06] flex justify-end">
          {footer}
        </div>
      )}
    </div>
  );
}
