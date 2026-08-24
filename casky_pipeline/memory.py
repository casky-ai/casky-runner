"""Organizational memory: extraction, decay, and dual-mode (Postgres/JSON-file)
storage + retrieval — Casky Box's mirror of the SaaS product's
packages/investigate/src/memory.ts + agents/memory-extractor.ts.

Combined into one module (extraction + storage), matching this repo's own
precedent for "agent + persistence together" (see local_history_adapter.py
calling casky_db.store directly) rather than inventing a new agents/
subpackage this repo doesn't otherwise have — pipeline.py's stage classes
live inline in one file for the same reason.

Dual-mode storage is not optional here the way it might be on the SaaS side:
DATABASE_URL is unset for most Casky Box installs (JSON-file mode is the
default, not an edge case — see harness.py's generate_local_plan() and
casky_db/store.py's module docstring). Both extract_and_store_memories() and
find_relevant_memories() must work with no Postgres at all.
"""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from casky_pipeline.llm_providers import LLMProvider
from casky_pipeline.pipeline import _log_stage_failure, _parse_json_response

MAX_MEMORIES = 5
MEMORY_HALF_LIFE_DAYS = 90.0
# Below this decayed confidence, a memory is too stale to be worth surfacing —
# dropped from find_relevant_memories() results entirely. Same floor as the
# SaaS side's MIN_RETRIEVAL_CONFIDENCE.
MIN_RETRIEVAL_CONFIDENCE = 0.15

DEFAULT_MEMORIES_DIR = Path.home() / ".casky" / "memories"


# ── Extraction (LLM stage) ────────────────────────────────────────────────────

@dataclass
class MemoryCandidate:
    statement: str
    rationale: str
    conditions: dict[str, Any] = field(default_factory=dict)
    applies_to: dict[str, list[str]] = field(default_factory=dict)
    confidence: float = 0.5
    escalation_recommended: bool = True
    expires_in_days: float | None = None


@dataclass
class MemoryExtractorOutput:
    memories: list[MemoryCandidate] = field(default_factory=list)


class MemoryExtractor:
    """Same shape as pipeline.py's stage classes (TechniqueValidator, etc.):
    a SYSTEM_PROMPT class attribute, async run(input, provider), degrade to
    an empty output (never raise) on a malformed/unparsable LLM response."""

    SYSTEM_PROMPT = f"""You are a senior security analyst distilling durable, reusable lessons from a completed investigation — the kind of institutional knowledge a departing analyst would want to leave behind for the next person who sees similar evidence.

Turn the investigation record into a small number of structured memories. Each memory must generalize beyond this single investigation — never just restate the outcome. Think: "what should the next investigator with similar evidence be told, and why should they believe it?"

For each memory:
1. statement — the durable claim, in plain language (e.g. "Logins from Tokyo for this identity are expected during this period")
2. rationale — why we believe it, referencing what was actually verified
3. conditions — the scope under which it's true (JSON object; omit fields you can't support with evidence)
4. applies_to — ONLY entities you can point to directly in the evidence (cve_ids, technique_ids, ips, hostnames — omit any array you have nothing for)
5. confidence — 0 to 1, calibrated against how well-supported the investigation's own outcome was
6. escalation_recommended — true if future similar activity should still be escalated/reviewed; false if it can stand down
7. expires_in_days — how long this claim should remain trustworthy (omit/null only for genuinely permanent facts; most memories should have a numeric TTL)

Respond with ONLY a JSON object — no prose, no markdown code fences — exactly this shape:
{{
  "memories": [
    {{
      "statement": "...",
      "rationale": "...",
      "conditions": {{}},
      "applies_to": {{}},
      "confidence": 0.85,
      "escalation_recommended": false,
      "expires_in_days": 14
    }}
  ]
}}

Rules:
- Maximum {MAX_MEMORIES} memories
- Return zero memories if the investigation taught nothing generalizable
- Never fabricate an entity that isn't in the evidence or the investigation record"""

    async def run(self, investigation: dict, provider: LLMProvider) -> MemoryExtractorOutput:
        user_prompt = self._build_user_prompt(investigation)
        raw = await provider.complete(self.SYSTEM_PROMPT, user_prompt, max_tokens=1536, cacheable_system=True)
        try:
            data = _parse_json_response(raw)
            memories: list[MemoryCandidate] = []
            for m in (data.get("memories", []) or [])[:MAX_MEMORIES]:
                statement = m.get("statement")
                rationale = m.get("rationale")
                if not statement or not rationale:
                    continue  # dropped, not defaulted — same rule as the TS extractor
                confidence = float(m.get("confidence", 0.5) or 0.5)
                memories.append(MemoryCandidate(
                    statement=statement,
                    rationale=rationale,
                    conditions=dict(m.get("conditions", {}) or {}),
                    applies_to=dict(m.get("applies_to", {}) or {}),
                    confidence=min(1.0, max(0.0, confidence)),
                    escalation_recommended=bool(m.get("escalation_recommended", True)),
                    expires_in_days=m.get("expires_in_days"),
                ))
            return MemoryExtractorOutput(memories=memories)
        except Exception as exc:
            _log_stage_failure("MemoryExtractor", exc, raw)
            return MemoryExtractorOutput()

    @staticmethod
    def _build_user_prompt(investigation: dict) -> str:
        feedback = investigation.get("feedback", []) or []
        feedback_lines = "\n".join(
            f"- step {f.get('step_order', 'plan-level')} ({f.get('skill_slug', 'n/a')}): {f.get('rating', '')}"
            + (f" — found: {f['actual_finding']}" if f.get("actual_finding") else "")
            for f in feedback
        ) or "(no per-step feedback recorded)"

        steps = investigation.get("steps", []) or []
        skill_sequence = " -> ".join(s.get("skill_slug", "") for s in steps)

        return (
            f"## Investigation\n"
            f"Domain: {investigation.get('domain', '')}\n"
            f"Techniques investigated: {', '.join(t.get('technique_id', '') for t in steps if t.get('technique_id')) or 'none'}\n"
            f"Confirmed techniques: {', '.join(investigation.get('confirmed_technique_ids', []) or []) or 'none'}\n"
            f"Skill sequence: {skill_sequence}\n"
            f"Plan-time confidence: {investigation.get('confidence', 0.0)}\n\n"
            f"## Feedback\n{feedback_lines}\n\n"
            f"## Outcome (analyst-written)\n{investigation.get('outcome_summary', '')}\n\n"
            f"## Evidence (truncated)\n{(investigation.get('evidence_text') or '')[:4000]}"
        )


# ── Decay ──────────────────────────────────────────────────────────────────

def decayed_confidence(
    confidence: float,
    last_reinforced_at: datetime | str,
    expires_at: datetime | str | None,
    half_life_days: float = MEMORY_HALF_LIFE_DAYS,
) -> float:
    """Exponential half-life decay from last_reinforced_at. Returns 0 once
    past a hard expiry, regardless of decay math — expires_at is an absolute
    cutoff, not just another input to the curve. Same formula as the SaaS
    product's decayedConfidence() in memory.ts."""
    now = datetime.now(timezone.utc)
    exp = _as_aware_datetime(expires_at)
    if exp is not None and exp <= now:
        return 0.0

    last = _as_aware_datetime(last_reinforced_at)
    if last is None:
        return confidence
    age_days = (now - last).total_seconds() / 86_400.0
    if age_days <= 0:
        return confidence
    return confidence * (0.5 ** (age_days / half_life_days))


def _as_aware_datetime(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _run_coro_sync(coro):
    """Runs an async coroutine to completion from synchronous code — whether
    or not an asyncio event loop is already running on this thread.

    Live-caught: harness.py's --auto mode calls extract_and_store_memories()
    (sync) from _capture_outcome_and_extract_memory() (sync), which itself
    runs inside _run_harness() — an async function driven by main()'s own
    top-level asyncio.run(_run_harness(...)). A plain asyncio.run(coro) here
    then raises "asyncio.run() cannot be called from a running event loop",
    and extract_and_store_memories()'s own try/except swallows that into a
    "skipped_reason", silently dropping every memory from every --auto-mode
    run. (The manual, non---auto investigation flow's own asyncio.run() call
    for LLM synthesis already returns before it reaches this point, so it
    never hit this — only --auto mode did.)

    The fix: detect a running loop and, only then, run the coroutine to
    completion on a fresh event loop in a separate thread — asyncio.run() is
    only ever called on a thread with no loop already running, so it never
    raises for that reason. When no loop is running (the common case — most
    callers are synchronous top-level CLI code), this is just asyncio.run()."""
    import asyncio
    import threading

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: list = []
    error: list = []

    def _target() -> None:
        try:
            result.append(asyncio.run(coro))
        except Exception as exc:
            error.append(exc)

    thread = threading.Thread(target=_target)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]


# ── Extraction + storage (dual-mode) ─────────────────────────────────────────

def extract_and_store_memories(
    investigation: dict,
    provider: LLMProvider,
    database_url: str | None = None,
    memories_dir: Path | None = None,
) -> dict:
    """Extracts memories from a completed investigation record and stores
    them — Postgres when database_url is configured and reachable, else a
    JSON file under memories_dir. Never raises: every failure degrades to
    {"stored": 0, "skipped_reason": ...} so a bad extraction can never break
    the CLI flow it's called from (mirrors the SaaS route's try/catch)."""
    investigation_id = investigation.get("id")
    outcome_summary = investigation.get("outcome_summary")
    if not investigation_id or not outcome_summary:
        return {"stored": 0, "skipped_reason": "missing investigation id or outcome_summary"}

    try:
        output = _run_coro_sync(MemoryExtractor().run(investigation, provider))
    except Exception as exc:
        return {"stored": 0, "skipped_reason": f"{type(exc).__name__}: {exc}"}

    if not output.memories:
        return {"stored": 0, "skipped_reason": "extractor returned no generalizable memories"}

    try:
        from casky_db import store
    except ImportError as exc:
        return _fallback_to_json(investigation_id, output.memories, memories_dir, f"casky_db not importable: {exc}")

    # Decide Postgres-vs-JSON mode from the FIRST write, not mid-batch — a
    # partial Postgres write followed by a full JSON-file fallback would
    # duplicate whatever already landed in Postgres. If the very first
    # store_memory() call hits DatabaseUnavailable (unset/unreachable —
    # the expected, non-error state for most installs), the whole batch
    # goes to JSON instead. A failure on a LATER call (already in Postgres
    # mode) just stops the batch and returns what succeeded so far, rather
    # than risking a duplicating fallback.
    stored = 0
    for i, m in enumerate(output.memories):
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=m.expires_in_days)
            if m.expires_in_days is not None
            else None
        )
        try:
            store.store_memory(
                source_investigation_id=investigation_id,
                statement=m.statement,
                rationale=m.rationale,
                conditions=m.conditions,
                applies_to=m.applies_to,
                confidence=m.confidence,
                escalation_recommended=m.escalation_recommended,
                expires_at=expires_at,
                database_url=database_url,
            )
            stored += 1
        except store.DatabaseUnavailable as exc:
            if i == 0:
                return _fallback_to_json(investigation_id, output.memories, memories_dir, str(exc))
            return {"stored": stored, "skipped_reason": f"database became unavailable mid-batch: {exc}"}
        except Exception as exc:
            if i == 0:
                return _fallback_to_json(investigation_id, output.memories, memories_dir, str(exc))
            return {"stored": stored, "skipped_reason": f"{type(exc).__name__}: {exc}"}

    return {"stored": stored}


def _fallback_to_json(investigation_id: str, memories: list[MemoryCandidate], memories_dir: Path | None, reason: str) -> dict:
    try:
        _write_memories_json(investigation_id, memories, memories_dir)
        return {"stored": len(memories), "skipped_reason": f"stored to JSON file (postgres unavailable: {reason})"}
    except Exception as write_exc:
        return {"stored": 0, "skipped_reason": f"postgres failed ({reason}) and JSON fallback failed ({write_exc})"}


def _write_memories_json(investigation_id: str, memories: list[MemoryCandidate], memories_dir: Path | None) -> None:
    directory = memories_dir or DEFAULT_MEMORIES_DIR
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()

    rows = []
    for m in memories:
        expires_at = (
            (datetime.now(timezone.utc) + timedelta(days=m.expires_in_days)).isoformat()
            if m.expires_in_days is not None
            else None
        )
        rows.append({
            "id": str(uuid.uuid4()),
            "source_investigation_id": investigation_id,
            "statement": m.statement,
            "rationale": m.rationale,
            "conditions": m.conditions,
            "applies_to": m.applies_to,
            "confidence": m.confidence,
            "escalation_recommended": m.escalation_recommended,
            "created_at": now,
            "last_reinforced_at": now,
            "expires_at": expires_at,
            "superseded_by": None,
        })

    memory_file = directory / f"{investigation_id}.json"
    existing: list[dict] = []
    if memory_file.exists():
        try:
            existing = json.loads(memory_file.read_text())
        except Exception:
            existing = []
    memory_file.write_text(json.dumps(existing + rows, indent=2))


def find_relevant_memories(
    cve_ids: list[str],
    technique_ids: list[str],
    ips: list[str] | None = None,
    hostnames: list[str] | None = None,
    database_url: str | None = None,
    memories_dir: Path | None = None,
) -> list[dict]:
    """Entity-overlap retrieval, dual-mode. Returns dicts shaped like
    investigation_memories rows plus an "effective_confidence" key (decay
    applied). Never raises — degrades to [] on any failure, same contract
    as find_related()/LocalHistoryAdapter."""
    cve_ids = list(cve_ids or [])
    technique_ids = list(technique_ids or [])
    ips = list(ips or [])
    hostnames = list(hostnames or [])
    if not (cve_ids or technique_ids or ips or hostnames):
        return []

    rows: list[dict] = []
    try:
        from casky_db import store

        rows = store.find_relevant_memories(
            cve_ids=cve_ids, technique_ids=technique_ids, ips=ips, hostnames=hostnames,
            database_url=database_url,
        )
    except Exception:
        rows = _read_memories_json(memories_dir)

    wanted = set(cve_ids) | set(technique_ids) | set(ips) | set(hostnames)
    matches: list[dict] = []
    for row in rows:
        applies = row.get("applies_to") or {}
        row_entities = (
            list(applies.get("cve_ids", []) or [])
            + list(applies.get("technique_ids", []) or [])
            + list(applies.get("ips", []) or [])
            + list(applies.get("hostnames", []) or [])
        )
        if not any(e in wanted for e in row_entities):
            continue
        if row.get("superseded_by"):
            continue

        effective = decayed_confidence(
            float(row.get("confidence", 0.0) or 0.0),
            row.get("last_reinforced_at") or row.get("created_at"),
            row.get("expires_at"),
        )
        if effective < MIN_RETRIEVAL_CONFIDENCE:
            continue

        matches.append({**row, "effective_confidence": effective})

    matches.sort(key=lambda r: r["effective_confidence"], reverse=True)
    return matches


def _read_memories_json(memories_dir: Path | None) -> list[dict]:
    """Scans every *.json file under memories_dir — one file per source
    investigation (see _write_memories_json) — for the JSON-file fallback
    mode. Not optional: this is the default storage mode for most Casky Box
    installs (no DATABASE_URL configured)."""
    directory = memories_dir or DEFAULT_MEMORIES_DIR
    if not directory.exists():
        return []

    rows: list[dict] = []
    for f in directory.glob("*.json"):
        try:
            rows.extend(json.loads(f.read_text()))
        except Exception as exc:  # noqa: BLE001 — one malformed file must not break retrieval
            print(f"[casky_pipeline:memory] skipping malformed memory file {f}: {exc}", file=sys.stderr)
    return rows
