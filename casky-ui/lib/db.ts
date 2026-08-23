/**
 * Typed query helpers against the casky_db Postgres schema, mirroring
 * casky_db/store.py's read/write functions 1:1 in shape (see that file for
 * the reference implementation this was ported from). Plain `pg` (node-
 * postgres), no ORM — matches the Python side's "single-admin local tool,
 * not high-concurrency" philosophy.
 *
 * This app has no JSON-file fallback (unlike the Python harness): if
 * DATABASE_URL is unset, every call here throws DatabaseUnavailable and
 * callers should render a clear error page, not a stack trace — see
 * app/error.tsx and the `requireDatabaseUrl()` check below.
 */
import { Pool, type QueryResultRow } from "pg";
import type {
  ConsolidatedReport,
  CveReference,
  Finding,
  FindingStatus,
  Investigation,
  InvestigationDetail,
  InvestigationStep,
  Memory,
  MemoryMatch,
  RelatedInvestigation,
  SkillExecution,
} from "./types";
import { decayedConfidence, MIN_RETRIEVAL_CONFIDENCE } from "./memory";

export class DatabaseUnavailable extends Error {}

let pool: Pool | null = null;

function requireDatabaseUrl(): string {
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new DatabaseUnavailable(
      "DATABASE_URL is not set. casky-ui has no file-based fallback (unlike " +
        "the Python harness) — it has no reason to run without a database. " +
        "Set DATABASE_URL to the same Postgres instance casky_db/casky.sh use " +
        "and restart."
    );
  }
  return url;
}

function getPool(): Pool {
  if (pool) return pool;
  const connectionString = requireDatabaseUrl();
  pool = new Pool({ connectionString, max: 10 });
  return pool;
}

async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<T[]> {
  try {
    const result = await getPool().query<T>(text, params);
    return result.rows;
  } catch (err) {
    if (err instanceof DatabaseUnavailable) throw err;
    throw new DatabaseUnavailable(
      `Database query failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/** Cheap connectivity probe for the health-check route and Settings page. */
export async function pingDatabase(): Promise<boolean> {
  try {
    await query("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

// ── Investigations ──────────────────────────────────────────────────────

export async function getInvestigation(id: string): Promise<InvestigationDetail | null> {
  const [investigation] = await query<Investigation>(
    "SELECT * FROM investigations WHERE id = $1",
    [id]
  );
  if (!investigation) return null;

  const [steps, cveReferences, findings, skillExecutions, consolidatedReports] =
    await Promise.all([
      query<InvestigationStep>(
        "SELECT * FROM investigation_steps WHERE investigation_id = $1 ORDER BY step_order",
        [id]
      ),
      query<CveReference>("SELECT * FROM cve_references WHERE investigation_id = $1", [id]),
      query<Finding>(
        "SELECT * FROM findings WHERE investigation_id = $1 ORDER BY created_at",
        [id]
      ),
      query<SkillExecution>("SELECT * FROM skill_executions WHERE investigation_id = $1", [id]),
      query<ConsolidatedReport>(
        `SELECT * FROM consolidated_reports WHERE investigation_id = $1
         ORDER BY generated_at DESC LIMIT 1`,
        [id]
      ),
    ]);

  return {
    ...investigation,
    steps,
    cve_references: cveReferences,
    findings,
    skill_executions: skillExecutions,
    consolidated_report: consolidatedReports[0] ?? null,
  };
}

export async function listInvestigations(opts: {
  status?: string;
  limit?: number;
} = {}): Promise<Investigation[]> {
  const limit = opts.limit ?? 50;
  if (opts.status) {
    return query<Investigation>(
      "SELECT * FROM investigations WHERE status = $1 ORDER BY created_at DESC LIMIT $2",
      [opts.status, limit]
    );
  }
  return query<Investigation>(
    "SELECT * FROM investigations ORDER BY created_at DESC LIMIT $1",
    [limit]
  );
}

export async function countInvestigationsByStatus(): Promise<Record<string, number>> {
  const rows = await query<{ status: string; count: string }>(
    "SELECT status, COUNT(*)::text AS count FROM investigations GROUP BY status"
  );
  const out: Record<string, number> = {};
  for (const r of rows) out[r.status] = Number(r.count);
  return out;
}

export async function countOpenFindingsBySeverity(): Promise<Record<string, number>> {
  const rows = await query<{ severity: string; count: string }>(
    `SELECT severity, COUNT(*)::text AS count FROM findings
     WHERE status IN ('open', 'in_progress') GROUP BY severity`
  );
  const out: Record<string, number> = {};
  for (const r of rows) out[r.severity] = Number(r.count);
  return out;
}

/**
 * Explainable overlap query — ported directly from casky_db/store.py's
 * find_related(): past investigations whose cve_references.cve_id
 * intersects cveIds, whose investigation_steps.technique_id intersects
 * techniqueIds, or whose domain equals `domain`, most-recent-first. Each
 * result carries matched_cve_ids/matched_technique_ids/domain_match so the
 * UI can explain *why* it surfaced, not just that it did.
 */
export async function findRelated(opts: {
  techniqueIds: string[];
  cveIds: string[];
  domain?: string | null;
  excludeId?: string | null;
  limit?: number;
}): Promise<RelatedInvestigation[]> {
  const techniqueIds = opts.techniqueIds ?? [];
  const cveIds = opts.cveIds ?? [];
  const domain = opts.domain ?? null;
  const excludeId = opts.excludeId ?? null;
  const limit = opts.limit ?? 5;

  const rows = await query<Investigation>(
    `
    SELECT DISTINCT i.id, i.domain, i.evidence_text, i.status, i.confidence,
           i.evidence_gaps, i.agent_used, i.model_used, i.created_at, i.updated_at
    FROM investigations i
    LEFT JOIN cve_references cr ON cr.investigation_id = i.id
    LEFT JOIN investigation_steps st ON st.investigation_id = i.id
    WHERE (
      cr.cve_id = ANY($1::text[])
      OR st.technique_id = ANY($2::text[])
      OR ($3::text IS NOT NULL AND i.domain = $3::text)
    )
    AND ($4::uuid IS NULL OR i.id != $4::uuid)
    ORDER BY i.created_at DESC
    LIMIT $5
    `,
    [cveIds, techniqueIds, domain, excludeId, limit]
  );

  const results: RelatedInvestigation[] = [];
  for (const row of rows) {
    let matchedCveIds: string[] = [];
    let matchedTechniqueIds: string[] = [];

    if (cveIds.length) {
      const r = await query<{ cve_id: string }>(
        `SELECT DISTINCT cve_id FROM cve_references
         WHERE investigation_id = $1 AND cve_id = ANY($2::text[])`,
        [row.id, cveIds]
      );
      matchedCveIds = r.map((x) => x.cve_id);
    }
    if (techniqueIds.length) {
      const r = await query<{ technique_id: string }>(
        `SELECT DISTINCT technique_id FROM investigation_steps
         WHERE investigation_id = $1 AND technique_id = ANY($2::text[])`,
        [row.id, techniqueIds]
      );
      matchedTechniqueIds = r.map((x) => x.technique_id);
    }

    results.push({
      ...row,
      matched_cve_ids: matchedCveIds,
      matched_technique_ids: matchedTechniqueIds,
      domain_match: Boolean(domain) && row.domain === domain,
    });
  }
  return results;
}

// ── Organizational memory (migration 0003) ──────────────────────────────
//
// Ported from casky_pipeline/memory.py's find_relevant_memories(): the SQL
// fetch mirrors casky_db/store.py's find_relevant_memories() (jsonb `?|`
// containment against applies_to, excluding hard-expired/superseded rows at
// the SQL level); decay math + the MIN_RETRIEVAL_CONFIDENCE floor are then
// applied here, same as the Python wrapper layers them on top of its own
// store.find_relevant_memories() — two independent appliers of the same
// formula (lib/memory.ts / casky_pipeline/memory.py), not a fork of it.

export async function findRelevantMemories(opts: {
  cveIds?: string[];
  techniqueIds?: string[];
  ips?: string[];
  hostnames?: string[];
  limit?: number;
}): Promise<MemoryMatch[]> {
  const cveIds = opts.cveIds ?? [];
  const techniqueIds = opts.techniqueIds ?? [];
  const ips = opts.ips ?? [];
  const hostnames = opts.hostnames ?? [];
  if (!cveIds.length && !techniqueIds.length && !ips.length && !hostnames.length) return [];

  const rows = await query<Memory>(
    `
    SELECT * FROM investigation_memories
    WHERE superseded_by IS NULL
      AND (expires_at IS NULL OR expires_at > now())
      AND (
        (applies_to->'cve_ids')        ?| $1::text[]
        OR (applies_to->'technique_ids') ?| $2::text[]
        OR (applies_to->'ips')           ?| $3::text[]
        OR (applies_to->'hostnames')     ?| $4::text[]
      )
    ORDER BY last_reinforced_at DESC
    LIMIT $5
    `,
    [cveIds, techniqueIds, ips, hostnames, opts.limit ?? 20]
  );

  const matches: MemoryMatch[] = rows
    .map((row) => ({
      ...row,
      effective_confidence: decayedConfidence(row.confidence, row.last_reinforced_at, row.expires_at),
    }))
    .filter((m) => m.effective_confidence >= MIN_RETRIEVAL_CONFIDENCE);

  matches.sort((a, b) => b.effective_confidence - a.effective_confidence);
  return matches;
}

// ── Findings ─────────────────────────────────────────────────────────────

export async function listFindings(opts: {
  status?: string;
  severity?: string;
  limit?: number;
} = {}): Promise<Finding[]> {
  const limit = opts.limit ?? 100;
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (opts.status) {
    params.push(opts.status);
    clauses.push(`status = $${params.length}`);
  }
  if (opts.severity) {
    params.push(opts.severity);
    clauses.push(`severity = $${params.length}`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  params.push(limit);
  return query<Finding>(
    `SELECT * FROM findings ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
    params
  );
}

export async function getFinding(id: string): Promise<Finding | null> {
  const [row] = await query<Finding>("SELECT * FROM findings WHERE id = $1", [id]);
  return row ?? null;
}

export async function updateFindingStatus(id: string, status: FindingStatus): Promise<void> {
  await query("UPDATE findings SET status = $1 WHERE id = $2", [status, id]);
}

export async function updateFindingRemediation(id: string, remediationText: string): Promise<void> {
  await query("UPDATE findings SET remediation = $1 WHERE id = $2", [remediationText, id]);
}

// ── Reports ──────────────────────────────────────────────────────────────

export async function listReports(opts: { limit?: number } = {}): Promise<
  Array<ConsolidatedReport & { domain: string | null }>
> {
  const limit = opts.limit ?? 50;
  return query(
    `SELECT cr.*, i.domain AS domain
     FROM consolidated_reports cr
     JOIN investigations i ON i.id = cr.investigation_id
     ORDER BY cr.generated_at DESC
     LIMIT $1`,
    [limit]
  );
}

export async function getReport(id: string): Promise<
  (ConsolidatedReport & { domain: string | null }) | null
> {
  const [row] = await query<ConsolidatedReport & { domain: string | null }>(
    `SELECT cr.*, i.domain AS domain
     FROM consolidated_reports cr
     JOIN investigations i ON i.id = cr.investigation_id
     WHERE cr.id = $1`,
    [id]
  );
  return row ?? null;
}

// ── Runtime settings ─────────────────────────────────────────────────────

export async function getSetting<T = unknown>(key: string, fallback: T | null = null): Promise<T | null> {
  const [row] = await query<{ value: T }>("SELECT value FROM runtime_settings WHERE key = $1", [
    key,
  ]);
  return row ? row.value : fallback;
}

export async function setSetting(key: string, value: unknown): Promise<void> {
  await query(
    `INSERT INTO runtime_settings (key, value, updated_at)
     VALUES ($1, $2::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [key, JSON.stringify(value)]
  );
}
