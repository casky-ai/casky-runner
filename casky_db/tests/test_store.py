"""Tests for casky_db.store — the Postgres repository functions.

Requires a real, reachable Postgres — see casky_db/tests/conftest.py's
docstring for how to point these at one locally. Skips cleanly (not a hard
failure) when DATABASE_URL is unset or the server isn't reachable.
"""

from __future__ import annotations

import uuid

import pytest

from casky_db import store
from casky_db.migrate import run_migrations


@pytest.fixture
def migrated_db(test_db_dsn: str) -> str:
    run_migrations(test_db_dsn)
    return test_db_dsn


def _sample_plan(plan_id: str | None = None) -> dict:
    plan_id = plan_id or str(uuid.uuid4())
    return {
        "id": plan_id,
        "domain": "web-app",
        "evidence_text": "GET flood against /admin",
        "status": "approved",
        "created_at": "2026-08-20T10:00:00",
        "confidence": 0.82,
        "evidence_gaps": ["No WAF logs"],
        "steps": [
            {
                "id": str(uuid.uuid4()),
                "skill_slug": "web-app-recon-basics",
                "skill_category": "web-app",
                "skill_document": "# doc",
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "rationale": "r",
                "evidence_focus": "e",
                "step_order": 1,
                "status": "pending",
            }
        ],
        "cve_references": [
            {
                "cve_id": "CVE-2024-1234",
                "cvss_score": 9.1,
                "cvss_severity": "critical",
                "is_kev": True,
                "technique_ids": ["T1595"],
                "skill_ids": ["web-app-recon-basics"],
                "ai_analysis": "",
            }
        ],
    }


# ── create_investigation / get_investigation round-trip ─────────────────────

def test_create_and_get_investigation_round_trip(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    got = store.get_investigation(plan["id"], database_url=migrated_db)

    assert got is not None
    assert got["id"] == plan["id"]
    assert got["domain"] == "web-app"
    assert got["status"] == "approved"
    assert float(got["confidence"]) == pytest.approx(0.82)
    assert got["evidence_gaps"] == ["No WAF logs"]

    assert len(got["steps"]) == 1
    assert got["steps"][0]["skill_slug"] == "web-app-recon-basics"
    assert got["steps"][0]["technique_id"] == "T1595"

    assert len(got["cve_references"]) == 1
    assert got["cve_references"][0]["cve_id"] == "CVE-2024-1234"
    assert got["cve_references"][0]["is_kev"] is True

    assert got["findings"] == []
    assert got["skill_executions"] == []
    assert got["consolidated_report"] is None


def test_get_investigation_returns_none_for_unknown_id(migrated_db: str):
    assert store.get_investigation(str(uuid.uuid4()), database_url=migrated_db) is None


def test_create_investigation_accepts_dict_shape_from_json_import(migrated_db: str):
    """create_investigation must work from a plain dict (json_import.py's
    reconstructed shape), not just an object with attributes."""
    plan = _sample_plan()
    assert isinstance(plan, dict)
    store.create_investigation(plan, database_url=migrated_db)
    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert got is not None


# ── record_findings field mapping ────────────────────────────────────────────

def test_record_findings_maps_proof_and_mitre_technique_fields(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    store.record_findings(
        plan["id"],
        None,
        [
            {
                "title": "Reflected XSS",
                "severity": "high",
                "description": "desc",
                "proof": "the raw evidence blob",
                "mitre_technique": "T1059",
            }
        ],
        database_url=migrated_db,
    )

    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert len(got["findings"]) == 1
    finding = got["findings"][0]
    assert finding["title"] == "Reflected XSS"
    assert finding["severity"] == "high"
    assert finding["raw_evidence"] == "the raw evidence blob"      # proof -> raw_evidence
    assert finding["mitre_technique_id"] == "T1059"                # mitre_technique -> mitre_technique_id
    assert finding["status"] == "open"


def test_record_findings_falls_back_to_informational_for_bad_severity(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    store.record_findings(
        plan["id"], None,
        [{"title": "t", "severity": "not-a-real-severity", "description": "d", "proof": "p", "mitre_technique": ""}],
        database_url=migrated_db,
    )

    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert got["findings"][0]["severity"] == "informational"


def test_record_findings_empty_list_is_a_no_op(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)
    store.record_findings(plan["id"], None, [], database_url=migrated_db)
    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert got["findings"] == []


# ── record_skill_execution ──────────────────────────────────────────────────

def test_record_skill_execution_round_trip(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)
    step_id = plan["steps"][0]["id"]
    run_id = str(uuid.uuid4())

    store.record_skill_execution(
        investigation_id=plan["id"],
        step_id=step_id,
        run_id=run_id,
        skill_slug="web-app-recon-basics",
        agent_used="claude",
        model_used="claude-sonnet-5",
        exit_code=0,
        started_at="2026-08-20T10:05:00",
        completed_at="2026-08-20T10:06:00",
        output="ran fine",
        database_url=migrated_db,
    )

    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert len(got["skill_executions"]) == 1
    execu = got["skill_executions"][0]
    assert execu["id"] == run_id
    assert execu["step_id"] == step_id
    assert execu["exit_code"] == 0
    assert execu["output"] == "ran fine"


# ── update_step_status ───────────────────────────────────────────────────────
# The durability primitive harness.py's manual (non---auto) investigation flow
# calls after every single captured step — see _persist_step_capture.

def test_update_step_status_round_trip(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)
    step_id = plan["steps"][0]["id"]

    store.update_step_status(step_id, "captured", database_url=migrated_db)

    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert got["steps"][0]["status"] == "captured"


def test_update_step_status_is_a_silent_no_op_for_unknown_step_id(migrated_db: str):
    """No investigation_steps row for this id (e.g. the owning plan was never
    inserted into Postgres at all) — must not raise. harness.py's
    _persist_step_capture relies on the FOLLOWING record_skill_execution call
    to surface that as a failure (a foreign-key violation) and fall back to
    local-file persistence; this call alone succeeding-but-doing-nothing is
    the documented, intentional behavior."""
    store.update_step_status(str(uuid.uuid4()), "captured", database_url=migrated_db)


# ── save_consolidated_report ────────────────────────────────────────────────

def test_save_consolidated_report_round_trip(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    store.save_consolidated_report(
        investigation_id=plan["id"],
        summary="one-line summary",
        risk_rating="high",
        markdown="# Report\n",
        report_json={"findings": [], "steps_run": 1},
        database_url=migrated_db,
    )

    got = store.get_investigation(plan["id"], database_url=migrated_db)
    report = got["consolidated_report"]
    assert report is not None
    assert report["summary"] == "one-line summary"
    assert report["risk_rating"] == "high"
    assert report["markdown"] == "# Report\n"
    assert report["report_json"] == {"findings": [], "steps_run": 1}


def test_get_investigation_returns_latest_consolidated_report(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    store.save_consolidated_report(
        plan["id"], "first", None, "# v1", {"v": 1}, database_url=migrated_db
    )
    store.save_consolidated_report(
        plan["id"], "second", None, "# v2", {"v": 2}, database_url=migrated_db
    )

    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert got["consolidated_report"]["summary"] == "second"


# ── find_related ─────────────────────────────────────────────────────────────

def test_find_related_matches_on_technique_id_overlap(migrated_db: str):
    matching = _sample_plan()  # technique_id T1595
    store.create_investigation(matching, database_url=migrated_db)

    non_matching = _sample_plan()
    non_matching["steps"][0]["technique_id"] = "T9999"
    non_matching["cve_references"][0]["cve_id"] = "CVE-2000-0000"
    non_matching["domain"] = "cloud"
    store.create_investigation(non_matching, database_url=migrated_db)

    related = store.find_related(
        technique_ids=["T1595"], cve_ids=[], domain=None, database_url=migrated_db
    )

    ids = {r["id"] for r in related}
    assert matching["id"] in ids
    assert non_matching["id"] not in ids
    match = next(r for r in related if r["id"] == matching["id"])
    assert "T1595" in match["matched_technique_ids"]


def test_find_related_matches_on_cve_id_overlap(migrated_db: str):
    matching = _sample_plan()
    store.create_investigation(matching, database_url=migrated_db)

    related = store.find_related(
        technique_ids=[], cve_ids=["CVE-2024-1234"], domain=None, database_url=migrated_db
    )
    ids = {r["id"] for r in related}
    assert matching["id"] in ids
    match = next(r for r in related if r["id"] == matching["id"])
    assert "CVE-2024-1234" in match["matched_cve_ids"]


def test_find_related_matches_on_domain(migrated_db: str):
    matching = _sample_plan()  # domain=web-app
    store.create_investigation(matching, database_url=migrated_db)

    related = store.find_related(
        technique_ids=[], cve_ids=[], domain="web-app", database_url=migrated_db
    )
    ids = {r["id"] for r in related}
    assert matching["id"] in ids
    match = next(r for r in related if r["id"] == matching["id"])
    assert match["domain_match"] is True


def test_find_related_excludes_the_given_investigation_id(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    related = store.find_related(
        technique_ids=["T1595"], cve_ids=[], domain=None,
        exclude_investigation_id=plan["id"], database_url=migrated_db,
    )
    assert plan["id"] not in {r["id"] for r in related}


def test_find_related_returns_no_matches_for_unrelated_query(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    related = store.find_related(
        technique_ids=["T0000"], cve_ids=["CVE-0000-0000"], domain="malware",
        database_url=migrated_db,
    )
    assert plan["id"] not in {r["id"] for r in related}


# ── list_investigations ─────────────────────────────────────────────────────

def test_list_investigations_filters_by_status(migrated_db: str):
    approved = _sample_plan()
    approved["status"] = "approved"
    store.create_investigation(approved, database_url=migrated_db)

    draft = _sample_plan()
    draft["status"] = "draft"
    store.create_investigation(draft, database_url=migrated_db)

    only_approved = store.list_investigations(status="approved", database_url=migrated_db)
    ids = {r["id"] for r in only_approved}
    assert approved["id"] in ids
    assert draft["id"] not in ids


# ── outcomes + feedback (migration 0002) ─────────────────────────────────────

def test_record_outcome_sets_summary_confirmed_techniques_and_status(migrated_db: str):
    plan = _sample_plan()
    plan["status"] = "approved"
    store.create_investigation(plan, database_url=migrated_db)

    store.record_outcome(
        plan["id"], "Confirmed: reflected XSS on /admin.", ["T1059", "T1595"],
        database_url=migrated_db,
    )

    got = store.get_investigation(plan["id"], database_url=migrated_db)
    assert got["outcome_summary"] == "Confirmed: reflected XSS on /admin."
    assert set(got["confirmed_technique_ids"]) == {"T1059", "T1595"}
    assert got["status"] == "complete"


def test_record_feedback_rejects_invalid_rating(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)
    with pytest.raises(ValueError):
        store.record_feedback(plan["id"], 1, "some-skill", "thumbs_up", database_url=migrated_db)


def test_record_feedback_accepts_all_four_valid_ratings(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)
    for rating in ("useful", "not_useful", "wrong_skill", "missing_skill"):
        store.record_feedback(plan["id"], 1, "some-skill", rating, database_url=migrated_db)  # must not raise


# ── organizational memory (migration 0003) ───────────────────────────────────

def test_store_memory_and_find_relevant_memories_round_trip(migrated_db: str):
    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    memory_id = store.store_memory(
        source_investigation_id=plan["id"],
        statement="Logins from Tokyo for this identity are expected during this period",
        rationale="John confirmed travel to Japan this week",
        conditions={"domain": "identity"},
        applies_to={"technique_ids": ["T1595"]},
        confidence=0.85,
        escalation_recommended=False,
        database_url=migrated_db,
    )
    assert memory_id

    matches = store.find_relevant_memories(
        cve_ids=[], technique_ids=["T1595"], database_url=migrated_db,
    )
    assert len(matches) == 1
    assert matches[0]["id"] == memory_id
    assert matches[0]["statement"].startswith("Logins from Tokyo")
    assert matches[0]["escalation_recommended"] is False


def test_find_relevant_memories_excludes_hard_expired(migrated_db: str):
    from datetime import datetime, timedelta, timezone

    plan = _sample_plan()
    store.create_investigation(plan, database_url=migrated_db)

    store.store_memory(
        source_investigation_id=plan["id"], statement="stale claim", rationale="r",
        conditions={}, applies_to={"technique_ids": ["T1595"]}, confidence=0.9,
        escalation_recommended=False,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        database_url=migrated_db,
    )

    matches = store.find_relevant_memories(cve_ids=[], technique_ids=["T1595"], database_url=migrated_db)
    assert matches == []


def test_find_relevant_memories_no_entities_returns_empty(migrated_db: str):
    assert store.find_relevant_memories(cve_ids=[], technique_ids=[], database_url=migrated_db) == []


# ── runtime_settings ─────────────────────────────────────────────────────────

def test_set_and_get_setting_round_trip(migrated_db: str):
    store.set_setting("some_key", {"nested": [1, 2, 3]}, database_url=migrated_db)
    assert store.get_setting("some_key", database_url=migrated_db) == {"nested": [1, 2, 3]}


def test_get_setting_returns_default_when_missing(migrated_db: str):
    assert store.get_setting("does-not-exist", default="fallback", database_url=migrated_db) == "fallback"


def test_set_setting_upserts(migrated_db: str):
    store.set_setting("k", "v1", database_url=migrated_db)
    store.set_setting("k", "v2", database_url=migrated_db)
    assert store.get_setting("k", database_url=migrated_db) == "v2"


# ── DatabaseUnavailable ──────────────────────────────────────────────────────

def test_database_unavailable_raised_for_missing_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(store.DatabaseUnavailable):
        store.get_investigation("whatever", database_url="")


def test_database_unavailable_raised_for_bogus_database_url():
    with pytest.raises(store.DatabaseUnavailable):
        store.get_investigation("whatever", database_url="postgresql://bad:bad@127.0.0.1:1/nope")
