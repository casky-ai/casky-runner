import { CircleDashed, Loader2, CircleCheck, CircleX } from 'lucide-react';
import { cn } from '../lib/cn';
import { STEP_STATUS_CLASSES } from '../tokens';
import type { InvestigationStep } from '../types';

export interface InvestigationStepRowProps extends InvestigationStep {
  className?: string;
}

const STATUS_ICON = {
  pending: CircleDashed,
  running: Loader2,
  done: CircleCheck,
  failed: CircleX,
} as const;

/**
 * A single row in an investigation plan's step-by-step table: a status
 * icon (pending/running/done/failed), the skill slug, and the rationale
 * for why that skill was chosen. No direct apps/web precedent — designed
 * to match the other components' visual language (dark-surface cards,
 * muted white text, semantic status colors).
 */
export function InvestigationStepRow({ skill_slug, rationale, status, className }: InvestigationStepRowProps) {
  const Icon = STATUS_ICON[status];
  return (
    <div
      className={cn(
        'flex items-start gap-3 px-3 py-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06]',
        className
      )}
    >
      <Icon
        size={16}
        className={cn('mt-0.5 shrink-0', STEP_STATUS_CLASSES[status], status === 'running' && 'animate-spin')}
        aria-label={`status: ${status}`}
      />
      <div className="min-w-0">
        <div className="text-sm font-mono font-medium text-[#EAF2FF] truncate">{skill_slug}</div>
        {rationale && <div className="text-xs text-white/45 mt-0.5">{rationale}</div>}
      </div>
    </div>
  );
}
