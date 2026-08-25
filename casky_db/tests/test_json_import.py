"""Tests for casky_db.json_import — the one-time plans_dir/reports_dir ->
Postgres importer.

Requires a real, reachable Postgres — see casky_db/tests/conftest.py's
docstring for how to point these at one locally. Skips cleanly (not a hard
failure) when DATABASE_URL is unset or the server isn't reachable.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from casky_db import store
from casky_db.json_import import import_json_plans
from casky_db.migrate import run_migrations


@pytest.fixture
def migrated_db(test_db_dsn: str) -> str:
    run_migrations(test_db_dsn)
    return test_db_dsn


def _write_plan_fixture(plans_dir: Path, plan_id: str) -> None:
    plan_data = {
        "id": plan_id,
        "domain": "web-app",
        "evidence_text": "evidence text",
        "status": "approved",
        "created_at": "2026-08-20T10:00:00",
        "cve_references": [
            {
                "cve_id": "CVE-2024-9999",
                "cvss_score": 8.8,
                "cvss_severity": "high",
                "is_kev": False,
                "technique_ids": ["T1595"],
                "skill_ids": [],
            }
        ],
        "evidence_gaps": ["gap"],
        "confidence": 0.75,
        "investigation_steps": [
            {
                "id": str(uuid.uuid4()),
                "skill_slug": "web-app-recon-basics",
                "skill_category": "web-app",
                "skill_document": "doc",
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "rationale": "r",
                "evidence_focus": "e",
                "step_order": 1,
                "status": "pending",
            }
        ],
    }
    (plans_dir / f"{plan_id}.json").write_text(json.dumps(plan_data, indent=2))


def _write_report_fixture(reports_dir: Path, plan_id: str, run_id: str) -> None:
    plan_reports_dir = reports_dir / plan_id
    plan_reports_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "findings": [
            {
                "title": "Finding A",
                "severity": "medium",
                "description": "d",
                "proof": "p",
                "mitre_technique": "T1595",
            }
        ],
        "summary": "one finding",
        "raw_output": "...",
    }
    (plan_reports_dir / f"{run_id}.json").write_text(json.dumps(report, indent=2))
    consolidated = {
        "plan_id": plan_id,
        "domain": "web-app",
        "generated_at": "2026-08-20T11:00:00",
        "steps_run": 1,
        "findings": report["findings"],
        "summaries": ["one finding"],
    }
    (plan_reports_dir / "consolidated.json").write_text(json.dumps(consolidated, indent=2))


def test_import_plan_and_reports(tmp_path: Path, migrated_db: str):
    plans_dir = tmp_path / "plans"
    reports_dir = tmp_path / "reports"
    plans_dir.mkdir()
    reports_dir.mkdir()

    plan_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    _write_plan_fixture(plans_dir, plan_id)
    _write_report_fixture(reports_dir, plan_id, run_id)

    summary = import_json_plans(plans_dir, reports_dir, database_url=migrated_db)

    assert summary["plans_imported"] == 1
    assert summary["plans_skipped_existing"] == 0
    assert summary["findings_imported"] == 1
    assert summary["reports_imported"] == 1
    assert summary["errors"] == []

    got = store.get_investigation(plan_id, database_url=migrated_db)
    assert got is not None
    assert got["domain"] == "web-app"
    assert len(got["steps"]) == 1
    assert len(got["cve_references"]) == 1
    assert len(got["findings"]) == 1
    assert got["findings"][0]["raw_evidence"] == "p"
    assert got["consolidated_report"] is not None
    assert got["consolidated_report"]["report_json"]["steps_run"] == 1


def test_import_prefers_synthesized_summary_over_joined_raw_summaries(tmp_path: Path, migrated_db: str):
    """harness.py's generate_consolidated_report() now writes both "summary"
    (one LLM-synthesized narrative) and "summaries" (raw, pre-synthesis, kept
    for backward compat) — the importer must prefer the synthesized one."""
    plans_dir = tmp_path / "plans"
    reports_dir = tmp_path / "reports"
    plans_dir.mkdir()
    reports_dir.mkdir()

    plan_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    _write_plan_fixture(plans_dir, plan_id)
    _write_report_fixture(reports_dir, plan_id, run_id)

    consolidated_file = reports_dir / plan_id / "consolidated.json"
    consolidated = json.loads(consolidated_file.read_text())
    consolidated["summary"] = "One synthesized narrative."
    consolidated["summaries"] = ["raw step summary one", "raw step summary two"]
    consolidated_file.write_text(json.dumps(consolidated, indent=2))

    import_json_plans(plans_dir, reports_dir, database_url=migrated_db)

    got = store.get_investigation(plan_id, database_url=migrated_db)
    assert got["consolidated_report"]["summary"] == "One synthesized narrative."


def test_import_is_idempotent_on_existing_plans(tmp_path: Path, migrated_db: str):
    plans_dir = tmp_path / "plans"
    reports_dir = tmp_path / "reports"
    plans_dir.mkdir()
    reports_dir.mkdir()

    plan_id = str(uuid.uuid4())
    _write_plan_fixture(plans_dir, plan_id)

    first = import_json_plans(plans_dir, reports_dir, database_url=migrated_db)
    assert first["plans_imported"] == 1
    assert first["plans_skipped_existing"] == 0

    second = import_json_plans(plans_dir, reports_dir, database_url=migrated_db)
    assert second["plans_imported"] == 0
    assert second["plans_skipped_existing"] == 1


def test_import_collects_malformed_plan_into_errors_without_aborting(tmp_path: Path, migrated_db: str):
    plans_dir = tmp_path / "plans"
    reports_dir = tmp_path / "reports"
    plans_dir.mkdir()
    reports_dir.mkdir()

    (plans_dir / "broken.json").write_text("{not valid json")

    good_id = str(uuid.uuid4())
    _write_plan_fixture(plans_dir, good_id)

    summary = import_json_plans(plans_dir, reports_dir, database_url=migrated_db)

    assert summary["plans_imported"] == 1  # the good one still imports
    assert len(summary["errors"]) == 1
    assert "broken.json" in summary["errors"][0]

    got = store.get_investigation(good_id, database_url=migrated_db)
    assert got is not None


def test_import_missing_plans_dir_reports_error_not_exception(tmp_path: Path, migrated_db: str):
    missing = tmp_path / "does-not-exist"
    summary = import_json_plans(missing, tmp_path / "reports", database_url=migrated_db)
    assert summary["plans_imported"] == 0
    assert len(summary["errors"]) == 1


def test_import_plan_missing_id_field_collected_as_error(tmp_path: Path, migrated_db: str):
    plans_dir = tmp_path / "plans"
    reports_dir = tmp_path / "reports"
    plans_dir.mkdir()
    reports_dir.mkdir()
    (plans_dir / "no-id.json").write_text(json.dumps({"domain": "web-app"}))

    summary = import_json_plans(plans_dir, reports_dir, database_url=migrated_db)
    assert summary["plans_imported"] == 0
    assert len(summary["errors"]) == 1
