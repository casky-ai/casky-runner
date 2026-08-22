/**
 * Organizational-memory decay math — a direct port of
 * casky_pipeline/memory.py's decayed_confidence() (itself a port of the SaaS
 * product's packages/investigate/src/memory.ts decayedConfidence()). Kept as
 * its own module, not inlined into lib/db.ts, so the formula stays a single,
 * reviewable unit shared by findRelevantMemories() below.
 *
 * Same constants as the Python side: 90-day half-life, 0.15 minimum
 * confidence floor before a memory is considered too stale to surface.
 */

export const MEMORY_HALF_LIFE_DAYS = 90;
export const MIN_RETRIEVAL_CONFIDENCE = 0.15;

/**
 * Exponential half-life decay from last_reinforced_at. Returns 0 once past a
 * hard expiry, regardless of decay math — expires_at is an absolute cutoff,
 * not just another input to the curve.
 */
export function decayedConfidence(
  confidence: number,
  lastReinforcedAt: string,
  expiresAt: string | null,
  halfLifeDays: number = MEMORY_HALF_LIFE_DAYS
): number {
  if (expiresAt && new Date(expiresAt).getTime() <= Date.now()) return 0;
  const ageDays = (Date.now() - new Date(lastReinforcedAt).getTime()) / 86_400_000;
  if (ageDays <= 0) return confidence;
  return confidence * Math.pow(0.5, ageDays / halfLifeDays);
}
