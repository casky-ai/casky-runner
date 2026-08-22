import { cn } from '../lib/cn';

export interface MitreTechniqueChipProps {
  techniqueId: string;
  techniqueName?: string;
  className?: string;
}

/**
 * Small monospace chip for a MITRE ATT&CK technique id, e.g. "T1595".
 * Optionally shows the technique's human-readable name after the id.
 */
export function MitreTechniqueChip({ techniqueId, techniqueName, className }: MitreTechniqueChipProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 text-xs bg-red-950 text-red-300 border border-red-800 px-1.5 py-0.5 rounded font-mono',
        className
      )}
    >
      {techniqueId}
      {techniqueName ? <span className="font-sans text-red-300/80">· {techniqueName}</span> : null}
    </span>
  );
}
