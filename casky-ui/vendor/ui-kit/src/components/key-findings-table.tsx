import { cn } from '../lib/cn';
import { SEVERITY_BADGE_CLASSES } from '../tokens';
import type { KeyFinding } from '../types';

export interface KeyFindingsTableProps {
  findings: KeyFinding[];
  className?: string;
}

/**
 * Severity + title/description table for a consolidated report's
 * key_findings[]. Mirrors the "Key Findings" table in apps/web's CISO
 * report view (report-client.tsx).
 */
export function KeyFindingsTable({ findings, className }: KeyFindingsTableProps) {
  return (
    <div className={cn('rounded-lg overflow-hidden border border-white/[0.08]', className)}>
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-white/[0.03] border-b border-white/[0.08]">
            <th className="text-left px-3 py-2.5 font-semibold w-24 text-white/40">Severity</th>
            <th className="text-left px-3 py-2.5 font-semibold text-white/40">Finding</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr
              key={i}
              className={i < findings.length - 1 ? 'border-b border-white/[0.04]' : undefined}
            >
              <td className="px-3 py-3 align-top">
                <span
                  className={cn(
                    'px-1.5 py-0.5 rounded font-medium',
                    SEVERITY_BADGE_CLASSES[f.severity]
                  )}
                >
                  {f.severity}
                </span>
              </td>
              <td className="px-3 py-3 align-top">
                <p className="font-semibold mb-0.5 text-[#EAF2FF]">{f.title}</p>
                <p className="text-white/55">{f.description}</p>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
