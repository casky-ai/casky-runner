import { cn } from '../lib/cn';
import { SEVERITY_BADGE_CLASSES } from '../tokens';
import type { Severity } from '../types';

export interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

/**
 * Small pill badge for a finding/risk severity, colored per the shared
 * severity → color mapping in ../tokens.ts.
 */
export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      data-severity={severity}
      className={cn(
        'text-xs px-2 py-0.5 rounded-full font-medium',
        SEVERITY_BADGE_CLASSES[severity],
        className
      )}
    >
      {severity}
    </span>
  );
}
