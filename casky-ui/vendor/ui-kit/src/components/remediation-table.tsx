import { cn } from '../lib/cn';
import type { RemediationAction } from '../types';

export interface RemediationTableProps {
  actions: RemediationAction[];
  className?: string;
}

/**
 * Prioritized remediation actions table — priority, action, effort, impact.
 * Mirrors the "Remediation Actions" table in apps/web's CISO report view.
 */
export function RemediationTable({ actions, className }: RemediationTableProps) {
  return (
    <div className={cn('rounded-lg overflow-hidden border border-white/[0.08]', className)}>
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-white/[0.03] border-b border-white/[0.08]">
            <th className="text-center px-3 py-2.5 font-semibold w-8 text-white/40">#</th>
            <th className="text-left px-3 py-2.5 font-semibold text-white/40">Action</th>
            <th className="text-left px-3 py-2.5 font-semibold w-16 text-white/40">Effort</th>
            <th className="text-left px-3 py-2.5 font-semibold w-16 text-white/40">Impact</th>
          </tr>
        </thead>
        <tbody>
          {actions.map((a, i) => (
            <tr
              key={i}
              className={i < actions.length - 1 ? 'border-b border-white/[0.04]' : undefined}
            >
              <td className="px-3 py-3 text-center align-top font-mono font-bold text-white/30">
                {a.priority}
              </td>
              <td className="px-3 py-3 align-top text-white/75">{a.action}</td>
              <td className="px-3 py-3 align-top">
                <span className="px-1.5 py-0.5 rounded capitalize bg-white/5 text-white/45">
                  {a.effort}
                </span>
              </td>
              <td className="px-3 py-3 align-top">
                <span className="px-1.5 py-0.5 rounded capitalize bg-white/5 text-white/45">
                  {a.impact}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
