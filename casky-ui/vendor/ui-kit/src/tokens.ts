/**
 * Design tokens for @casky/ui-kit.
 *
 * This is the single source of truth for the color/spacing decisions baked
 * into the components in this package. It exists specifically so those
 * decisions live in ONE documented place instead of being re-typed as
 * inline hex/rgba strings scattered across component files (which is the
 * pattern apps/web itself currently uses — see apps/web/lib/supabase/types.ts
 * SEVERITY_COLORS/SEVERITY_BORDER and the inline `style={{ color: '...' }}`
 * usage throughout apps/web/app/(dashboard)/**). Components in this package
 * should read from here, not invent their own hex values.
 *
 * Severity color mapping is carried over 1:1 from
 * apps/web/lib/supabase/types.ts SEVERITY_COLORS / SEVERITY_BORDER
 * (critical=red, high=orange, medium=yellow, low=green [note: apps/web's
 * FindingSeverity 'low' currently maps to green there, NOT blue as an
 * earlier draft of this spec assumed — verified against the live file],
 * informational=slate).
 */

import type { Severity, StepStatus } from './types';

export const SEVERITY_BADGE_CLASSES: Record<Severity, string> = {
  informational: 'bg-slate-100 text-slate-700',
  low: 'bg-green-100 text-green-700',
  medium: 'bg-yellow-100 text-yellow-700',
  high: 'bg-orange-100 text-orange-700',
  critical: 'bg-red-100 text-red-700',
};

export const SEVERITY_BORDER_CLASSES: Record<Severity, string> = {
  informational: 'border-slate-300',
  low: 'border-green-300',
  medium: 'border-yellow-300',
  high: 'border-orange-300',
  critical: 'border-red-500',
};

/** Order to render/sort severities in, most severe first. */
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

export const STEP_STATUS_CLASSES: Record<StepStatus, string> = {
  pending: 'text-slate-400',
  running: 'text-blue-500',
  done: 'text-green-600',
  failed: 'text-red-600',
};

export const SPACING = {
  cardPadding: 'p-5',
  cardRadius: 'rounded-xl',
  sectionGap: 'space-y-3',
} as const;
