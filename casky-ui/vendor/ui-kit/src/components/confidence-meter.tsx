import { cn } from '../lib/cn';

export interface ConfidenceMeterProps {
  /** Confidence as a 0-1 fraction. Values outside [0,1] are clamped. */
  confidence: number;
  label?: string;
  className?: string;
}

/**
 * Simple labeled progress bar for a 0-1 confidence score.
 */
export function ConfidenceMeter({ confidence, label = 'Confidence', className }: ConfidenceMeterProps) {
  const clamped = Math.min(1, Math.max(0, confidence));
  const pct = Math.round(clamped * 100);

  return (
    <div className={cn('w-full', className)}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-slate-500">{label}</span>
        <span className="text-xs font-mono text-slate-600">{pct}%</span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
        className="h-1.5 w-full rounded-full bg-slate-200 overflow-hidden"
      >
        <div
          className="h-full rounded-full bg-emerald-500 transition-[width]"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
