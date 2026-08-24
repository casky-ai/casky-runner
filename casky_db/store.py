"""Repository functions backing the Postgres persistence layer.

Plain SQL via psycopg (v3), no ORM — one connection per call, matching this
repo's "single-admin local tool, not high-concurrency" philosophy (see
PHASE1_CONTRACT.md-adjacent design notes and CLAUDE.md's minimalism theme).

IMPORTANT: this module must NOT import harness.py at runtime — harness.py
imports casky_db.store, and a reverse import would create a circular import.
Every function that takes a "plan"/"step"/"cve reference" accepts either a
plain dict (the shape casky_db.json_import reconstructs from on-disk JSON) or
any object exposing the same attributes (the shape harness.Plan/Step/
CveEnrichment already have) via the `_get()` duck-typing helper below. Type
hints reference harness's dataclasses only under `TYPE_CHECKING`, which never
executes at import time.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from harness import CveEnrichment, Plan, Step


class DatabaseUnavailable(Exception):
    """Raised instead of a raw psycopg traceback whenever DATABASE_URL is
    unset or the database can't be reached. Callers (harness.py) decide
    whether that's fatal — usually it means "fall back to the JSON files"."""


def _get(obj: Any, name: str, default: Any = None) -> Any:
    """Reads `name` off `obj`, which may be a dict or an attribute-bearing
    object (a real harness.Plan/Step/CveEnrichment, or any duck-typed
    stand-in) — see module docstring for why this indirection exists."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_VALID_FINDING_STATUSES = {"open", "in_progress", "resolved", "accepted"}


def _row(row: Any) -> dict | None:
    """Converts one psycopg dict-row result into a plain, JSON-friendly
    dict — notably stringifying uuid.UUID values (every id/*_id column in
    this schema), since every documented return shape here is "a dict",
    and callers (LocalHistoryAdapter, json_import round-trips, eventual API
    responses) should never need to know psycopg's Python type mapping for
    a Postgres UUID column."""
    if row is None:
        return None
    return {k: (str(v) if isinstance(v, uuid.UUID) else v) for k, v in row.items()}


def _rows(rows: Any) -> list[dict]:
    return [_row(r) for r in rows]


def _database_url(database_url: str | None) -> str:
    return database_url if database_url is not None else os.environ.get("DATABASE_URL", "")


def _connect(database_url: str | None = None):
    """Returns a live psycopg connection with dict-row results, or raises
    DatabaseUnavailable. Callers are responsible for closing it (use as a
    context manager: `with _connect() as conn:`)."""
    dsn = _database_url(database_url)
    if not dsn:
        raise DatabaseUnavailable("DATABASE_URL is not set")

    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise DatabaseUnavailable(f"psycopg is not installed: {exc}") from exc

    try:
        return psycopg.connect(dsn, row_factory=dict_row)
    except Exception as exc:
        raise DatabaseUnavailable(f"could not connect to database: {exc}") from exc


# ── Investigations ────────────────────────────────────────────────────────

def create_investigation(plan: "Plan | dict", database_url: str | None = None) -> None:
    """Inserts an investigation + its steps + its cve_references in one
    transaction. Accepts a harness.Plan instance or an equivalent dict (see
    module docstring)."""
    plan_id = _get(plan, "id") or str(uuid.uuid4())
    steps = _get(plan, "steps", []) or []
    cve_references = _get(plan, "cve_references", []) or []

    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO investigations
                    (id, domain, evidence_text, status, confidence, evidence_gaps,
                     agent_used, model_used, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, now()), now())
                ON CONFLICT (id) DO UPDATE SET
                    domain = EXCLUDED.domain,
                    evidence_text = EXCLUDED.evidence_text,
                    status = EXCLUDED.status,
                    confidence = EXCLUDED.confidence,
                    evidence_gaps = EXCLUDED.evidence_gaps,
                    updated_at = now()
                """,
                (
                    plan_id,
                    _get(plan, "domain", ""),
                    _get(plan, "evidence_text", ""),
                    _get(plan, "status", "draft") or "draft",
                    _get(plan, "confidence", 0.0),
                    list(_get(plan, "evidence_gaps", []) or []),
                    _get(plan, "agent_used"),
                    _get(plan, "model_used"),
                    _parse_ts(_get(plan, "created_at")),
                ),
            )

            for i, step in enumerate(steps):
                cur.execute(
                    """
                    INSERT INTO investigation_steps
                        (id, investigation_id, skill_slug, skill_category, skill_document,
                         technique_id, technique_name, rationale, evidence_focus,
                         step_order, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (
                        _get(step, "id") or str(uuid.uuid4()),
                        plan_id,
                        _get(step, "skill_slug", ""),
                        _get(step, "skill_category", ""),
                        _get(step, "skill_document", ""),
                        _get(step, "technique_id", ""),
                        _get(step, "technique_name", ""),
                        _get(step, "rationale", ""),
                        _get(step, "evidence_focus", ""),
                        _get(step, "step_order", i),
                        _get(step, "status", "pending") or "pending",
                    ),
                )

            for ref in cve_references:
                cur.execute(
                    """
                    INSERT INTO cve_references
                        (investigation_id, cve_id, cvss_score, cvss_severity, is_kev,
                         technique_ids, skill_ids, ai_analysis)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        plan_id,
                        _get(ref, "cve_id", ""),
                        _get(ref, "cvss_score"),
                        _get(ref, "cvss_severity", ""),
                        bool(_get(ref, "is_kev", False)),
                        list(_get(ref, "technique_ids", []) or []),
                        list(_get(ref, "skill_ids", []) or []),
                        _get(ref, "ai_analysis", ""),
                    ),
                )
        conn.commit()


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def update_step_status(step_id: str, status: str, database_url: str | None = None) -> None:
    """Updates one investigation_steps row's status. This is the durability
    primitive the manual (non---auto) investigation flow in harness.py's
    run_interactive_investigation() uses to persist progress after every
    single pasted-output capture — not batched to the end — so a killed or
    closed session can resume exactly where it left off instead of losing
    everything. No-ops (0 rows affected, no error) if step_id doesn't exist
    in investigation_steps — e.g. the owning plan was loaded from a local
    file or the platform rather than created in Postgres; the caller treats
    that the same as any other failure and falls back to local-file
    persistence instead of assuming this call means the write landed."""
    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE investigation_steps SET status = %s WHERE id = %s",
                (status, step_id),
            )
        conn.commit()


def record_skill_execution(
    investigation_id: str,
    step_id: str | None,
    run_id: str,
    skill_slug: str,
    agent_used: str | None,
    model_used: str | None,
    exit_code: int | None,
    started_at: datetime | str | None,
    completed_at: datetime | str | None,
    output: str | None,
    score_pct: int | None = None,
    database_url: str | None = None,
) -> None:
    """Records one 'casky run <category>' invocation. `run_id` doubles as the
    skill_executions row's primary key, since it's already the unique id
    generated per step run in AgentWorker.execute() / _ReportHandler."""
    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO skill_executions
                    (id, investigation_id, step_id, skill_slug, agent_used, model_used,
                     exit_code, started_at, completed_at, output, score_pct)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    exit_code = EXCLUDED.exit_code,
                    completed_at = EXCLUDED.completed_at,
                    output = EXCLUDED.output,
                    score_pct = EXCLUDED.score_pct
                """,
                (
                    run_id,
                    investigation_id,
                    step_id,
                    skill_slug,
                    agent_used,
                    model_used,
                    exit_code,
                    _parse_ts(started_at),
                    _parse_ts(completed_at),
                    output,
                    score_pct,
                ),
            )
        conn.commit()


def record_findings(
    investigation_id: str,
    skill_execution_id: str | None,
    findings: list[dict],
    database_url: str | None = None,
) -> None:
    """Persists findings in the casky.sh POST-body shape
    (`title`, `severity`, `description`, `proof`, `mitre_technique`) — mapping
    `proof` -> `raw_evidence` and `mitre_technique` -> `mitre_technique_id`."""
    if not findings:
        return

    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            for f in findings:
                severity = str(f.get("severity", "informational") or "informational").lower()
                if severity not in _VALID_SEVERITIES:
                    severity = "informational"
                status = str(f.get("status", "open") or "open").lower()
                if status not in _VALID_FINDING_STATUSES:
                    status = "open"

                cur.execute(
                    """
                    INSERT INTO findings
                        (investigation_id, skill_execution_id, title, description, severity,
                         raw_evidence, mitre_technique_id, affected_asset, remediation, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        investigation_id,
                        skill_execution_id,
                        f.get("title", ""),
                        f.get("description", ""),
                        severity,
                        f.get("proof", ""),
                        f.get("mitre_technique", ""),
                        f.get("affected_asset"),
                        f.get("remediation"),
                        status,
                    ),
                )
        conn.commit()


def save_consolidated_report(
    investigation_id: str,
    summary: str,
    risk_rating: str | None,
    markdown: str,
    report_json: dict,
    database_url: str | None = None,
) -> None:
    from psycopg.types.json import Jsonb

    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO consolidated_reports
                    (investigation_id, summary, risk_rating, markdown, report_json)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (investigation_id, summary, risk_rating, markdown, Jsonb(report_json)),
            )
        conn.commit()


def get_investigation(investigation_id: str, database_url: str | None = None) -> dict | None:
    """Full nested shape: investigation + steps + cve_references + findings +
    skill_executions + latest consolidated_report (or None if there isn't
    one). Returns None if no investigation with this id exists."""
    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM investigations WHERE id = %s", (investigation_id,))
            investigation = cur.fetchone()
            if investigation is None:
                return None

            cur.execute(
                "SELECT * FROM investigation_steps WHERE investigation_id = %s ORDER BY step_order",
                (investigation_id,),
            )
            steps = cur.fetchall()

            cur.execute(
                "SELECT * FROM cve_references WHERE investigation_id = %s", (investigation_id,)
            )
            cve_references = cur.fetchall()

            cur.execute(
                "SELECT * FROM findings WHERE investigation_id = %s ORDER BY created_at",
                (investigation_id,),
            )
            findings = cur.fetchall()

            cur.execute(
                "SELECT * FROM skill_executions WHERE investigation_id = %s", (investigation_id,)
            )
            skill_executions = cur.fetchall()

            cur.execute(
                """
                SELECT * FROM consolidated_reports
                WHERE investigation_id = %s
                ORDER BY generated_at DESC
                LIMIT 1
                """,
                (investigation_id,),
            )
            consolidated_report = cur.fetchone()

    result = _row(investigation)
    result["steps"] = _rows(steps)
    result["cve_references"] = _rows(cve_references)
    result["findings"] = _rows(findings)
    result["skill_executions"] = _rows(skill_executions)
    result["consolidated_report"] = _row(consolidated_report)
    return result


def list_investigations(
    status: str | None = None, limit: int = 50, database_url: str | None = None
) -> list[dict]:
    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            if status:
                cur.execute(
                    """
                    SELECT * FROM investigations
                    WHERE status = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (status, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM investigations ORDER BY created_at DESC LIMIT %s",
                    (limit,),
                )
            rows = cur.fetchall()
    return _rows(rows)


def find_related(
    technique_ids: list[str],
    cve_ids: list[str],
    domain: str | None,
    exclude_investigation_id: str | None = None,
    limit: int = 5,
    database_url: str | None = None,
) -> list[dict]:
    """Explainable overlap query: returns past investigations whose
    cve_references.cve_id intersects `cve_ids`, whose investigation_steps.
    technique_id intersects `technique_ids`, or whose domain equals `domain`
    — most-recent-first. Each result includes matched_technique_ids /
    matched_cve_ids / domain_match so the caller (LocalHistoryAdapter) can
    explain *why* it surfaced this investigation, not just that it did."""
    technique_ids = list(technique_ids or [])
    cve_ids = list(cve_ids or [])

    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT i.id, i.domain, i.evidence_text, i.status, i.confidence,
                       i.evidence_gaps, i.agent_used, i.model_used, i.created_at, i.updated_at
                FROM investigations i
                LEFT JOIN cve_references cr ON cr.investigation_id = i.id
                LEFT JOIN investigation_steps st ON st.investigation_id = i.id
                WHERE (
                    cr.cve_id = ANY(%(cve_ids)s::text[])
                    OR st.technique_id = ANY(%(technique_ids)s::text[])
                    OR (%(domain)s::text IS NOT NULL AND i.domain = %(domain)s::text)
                )
                AND (%(exclude_id)s::uuid IS NULL OR i.id != %(exclude_id)s::uuid)
                ORDER BY i.created_at DESC
                LIMIT %(limit)s
                """,
                {
                    "cve_ids": cve_ids,
                    "technique_ids": technique_ids,
                    "domain": domain,
                    "exclude_id": exclude_investigation_id,
                    "limit": limit,
                },
            )
            rows = cur.fetchall()

            results: list[dict] = []
            for row in rows:
                inv_id = row["id"]
                matched_cve_ids: list[str] = []
                matched_technique_ids: list[str] = []

                if cve_ids:
                    cur.execute(
                        """
                        SELECT DISTINCT cve_id FROM cve_references
                        WHERE investigation_id = %s AND cve_id = ANY(%s::text[])
                        """,
                        (inv_id, cve_ids),
                    )
                    matched_cve_ids = [r["cve_id"] for r in cur.fetchall()]

                if technique_ids:
                    cur.execute(
                        """
                        SELECT DISTINCT technique_id FROM investigation_steps
                        WHERE investigation_id = %s AND technique_id = ANY(%s::text[])
                        """,
                        (inv_id, technique_ids),
                    )
                    matched_technique_ids = [r["technique_id"] for r in cur.fetchall()]

                entry = _row(row)
                entry["matched_cve_ids"] = matched_cve_ids
                entry["matched_technique_ids"] = matched_technique_ids
                entry["domain_match"] = bool(domain) and row["domain"] == domain
                results.append(entry)

    return results


# ── Outcomes + feedback (migration 0002) ─────────────────────────────────────

_VALID_RATINGS = {"useful", "not_useful", "wrong_skill", "missing_skill"}


def record_outcome(
    investigation_id: str,
    outcome_summary: str,
    confirmed_technique_ids: list[str] | None = None,
    database_url: str | None = None,
) -> None:
    """Analyst-written outcome — the quality gate before memory extraction
    runs. Mirrors the SaaS product's outcome route: a human confirms what
    actually happened, rather than mining an auto-generated summary."""
    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET outcome_summary = %s,
                    confirmed_technique_ids = %s,
                    status = 'complete',
                    updated_at = now()
                WHERE id = %s
                """,
                (outcome_summary, list(confirmed_technique_ids or []), investigation_id),
            )
        conn.commit()


def record_feedback(
    investigation_id: str,
    step_order: int | None,
    skill_slug: str | None,
    rating: str,
    actual_finding: str | None = None,
    database_url: str | None = None,
) -> None:
    rating = str(rating or "").lower()
    if rating not in _VALID_RATINGS:
        raise ValueError(f"invalid rating {rating!r} — expected one of {sorted(_VALID_RATINGS)}")

    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO investigation_feedback
                    (investigation_id, step_order, skill_slug, rating, actual_finding)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (investigation_id, step_order, skill_slug, rating, actual_finding),
            )
        conn.commit()


# ── Organizational memory (migration 0003) ───────────────────────────────────

def store_memory(
    source_investigation_id: str,
    statement: str,
    rationale: str,
    conditions: dict,
    applies_to: dict,
    confidence: float,
    escalation_recommended: bool,
    expires_at: datetime | str | None = None,
    database_url: str | None = None,
) -> str:
    """Inserts one memory row, returns its generated id."""
    from psycopg.types.json import Jsonb

    memory_id = str(uuid.uuid4())
    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO investigation_memories
                    (id, source_investigation_id, statement, rationale, conditions,
                     applies_to, confidence, escalation_recommended, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    memory_id,
                    source_investigation_id,
                    statement,
                    rationale,
                    Jsonb(conditions or {}),
                    Jsonb(applies_to or {}),
                    confidence,
                    escalation_recommended,
                    _parse_ts(expires_at),
                ),
            )
        conn.commit()
    return memory_id


def find_relevant_memories(
    cve_ids: list[str],
    technique_ids: list[str],
    ips: list[str] | None = None,
    hostnames: list[str] | None = None,
    limit: int = 20,
    database_url: str | None = None,
) -> list[dict]:
    """Entity-overlap retrieval — same v1 approach as the SaaS product
    (Postgres jsonb containment against applies_to, not vector search; see
    migration 0003's comment). Excludes hard-expired and superseded rows at
    the SQL level; decay math (decayed_confidence()) is applied by the
    caller (memory.py) since it depends on wall-clock time, not something
    worth pushing into SQL for a single-admin local tool."""
    cve_ids = list(cve_ids or [])
    technique_ids = list(technique_ids or [])
    ips = list(ips or [])
    hostnames = list(hostnames or [])
    if not (cve_ids or technique_ids or ips or hostnames):
        return []

    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM investigation_memories
                WHERE superseded_by IS NULL
                  AND (expires_at IS NULL OR expires_at > now())
                  AND (
                    (applies_to->'cve_ids')       ?| %(cve_ids)s::text[]
                    OR (applies_to->'technique_ids') ?| %(technique_ids)s::text[]
                    OR (applies_to->'ips')           ?| %(ips)s::text[]
                    OR (applies_to->'hostnames')     ?| %(hostnames)s::text[]
                  )
                ORDER BY last_reinforced_at DESC
                LIMIT %(limit)s
                """,
                {
                    "cve_ids": cve_ids,
                    "technique_ids": technique_ids,
                    "ips": ips,
                    "hostnames": hostnames,
                    "limit": limit,
                },
            )
            rows = cur.fetchall()
    return _rows(rows)


def get_setting(key: str, default: Any = None, database_url: str | None = None) -> Any:
    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM runtime_settings WHERE key = %s", (key,))
            row = cur.fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: Any, database_url: str | None = None) -> None:
    from psycopg.types.json import Jsonb

    with _connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO runtime_settings (key, value, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                """,
                (key, Jsonb(value)),
            )
        conn.commit()
