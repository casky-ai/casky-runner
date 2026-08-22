"""Regression guard for harness.py's Postgres <-> JSON-file fallback (Part B).

Proves local-mode-with-no-Postgres keeps working exactly as it did before
casky_db existed: generate_local_plan() must fall back to the on-disk
plans_dir/<plan.id>.json write whenever DATABASE_URL is empty OR the
database turns out to be unreachable, and must use casky_db.store instead
of the file write when the database *is* reachable. No real Postgres
connection is made in this file — casky_db.store is monkeypatched/mocked
throughout, same pattern as test_harness_integration.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import harness  # noqa: E402  (path insert must happen first)
from casky_db import store as db_store  # noqa: E402
from casky_pipeline.pipeline import ClassifierOutput  # noqa: E402


@pytest.fixture
def skills_library(tmp_path: Path) -> Path:
    lib = tmp_path / "skills-library"
    (lib / "skills" / "web-app-recon-basics" / "scripts").mkdir(parents=True)
    (lib / "skills" / "web-app-recon-basics" / "SKILL.md").write_text("# Recon\n")
    index = {
        "skills": [
            {"name": "web-app-recon-basics", "subdomain": "web-app", "description": "recon"}
        ]
    }
    (lib / "index.json").write_text(json.dumps(index))
    return lib


@pytest.fixture
def isolated_config(tmp_path: Path, skills_library: Path, monkeypatch):
    monkeypatch.setattr(harness.config, "skills_library_path", skills_library)
    monkeypatch.setattr(harness.config, "plans_dir", tmp_path / "plans")
    monkeypatch.setattr(harness.config, "api_key", "")
    monkeypatch.setattr(harness.config, "database_url", "")  # explicit: DB off unless a test opts in
    return harness.config


@pytest.fixture
def canned_pipeline(monkeypatch):
    async def fake_run_pipeline(classifier_input, provider, on_progress=None):
        return ClassifierOutput(
            steps=[
                {
                    "skill_slug": "web-app-recon-basics",
                    "skill_category": "web-application-security",
                    "technique_id": "T1595",
                    "technique_name": "Active Scanning",
                    "rationale": "r",
                    "evidence_focus": "e",
                    "step_order": 1,
                    "confidence": 0.9,
                    "evidence_gaps": [],
                }
            ],
            evidence_gaps=[],
            confidence=0.9,
        )

    monkeypatch.setattr(harness, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: object())


def test_database_url_unset_falls_back_to_json_file(isolated_config, canned_pipeline, monkeypatch):
    """DATABASE_URL empty -> create_investigation() must never even be
    attempted, and the plan must land on disk exactly as before Part B."""
    def fail_if_called(*a, **kw):
        raise AssertionError("create_investigation() must not be called when DATABASE_URL is empty")

    monkeypatch.setattr(db_store, "create_investigation", fail_if_called)

    plan = harness.generate_local_plan("Unusual GET flood against /admin")

    assert plan is not None
    plan_file = isolated_config.plans_dir / f"{plan.id}.json"
    assert plan_file.exists()
    on_disk = json.loads(plan_file.read_text())
    assert on_disk["id"] == plan.id
    assert len(on_disk["investigation_steps"]) == 1


def test_database_unreachable_falls_back_to_json_file(isolated_config, canned_pipeline, monkeypatch):
    """DATABASE_URL set but the DB is unreachable -> DatabaseUnavailable is
    caught, a warning is printed, and the JSON-file write still happens."""
    monkeypatch.setattr(harness.config, "database_url", "postgresql://bad:bad@127.0.0.1:1/nope")

    def raise_unavailable(plan, database_url=None):
        raise db_store.DatabaseUnavailable("could not connect to database: simulated failure")

    monkeypatch.setattr(db_store, "create_investigation", raise_unavailable)

    plan = harness.generate_local_plan("Unusual GET flood against /admin")

    assert plan is not None
    plan_file = isolated_config.plans_dir / f"{plan.id}.json"
    assert plan_file.exists(), "must still fall back to the JSON file when the DB is unreachable"


def test_database_available_uses_store_instead_of_json_file(isolated_config, canned_pipeline, monkeypatch):
    """The mirror case: when DATABASE_URL is set and create_investigation()
    succeeds, the plan is NOT written to plans_dir (store.create_investigation
    replaces the JSON-file write per the Part B spec — the file write is
    additive only for reports/consolidated reports, not the plan itself)."""
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")

    calls = []

    def fake_create_investigation(plan, database_url=None):
        calls.append((plan.id, database_url))

    monkeypatch.setattr(db_store, "create_investigation", fake_create_investigation)

    plan = harness.generate_local_plan("Unusual GET flood against /admin")

    assert plan is not None
    assert len(calls) == 1
    assert calls[0][0] == plan.id
    assert calls[0][1] == "postgresql://casky:casky@db:5432/casky"

    plan_file = isolated_config.plans_dir / f"{plan.id}.json"
    assert not plan_file.exists(), "DB-backed save must not also write the JSON file"


def test_unexpected_store_exception_also_falls_back_gracefully(isolated_config, canned_pipeline, monkeypatch):
    """Defense-in-depth: even a non-DatabaseUnavailable exception out of
    create_investigation() must not crash plan generation."""
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")

    def raise_weird(plan, database_url=None):
        raise RuntimeError("some unexpected bug")

    monkeypatch.setattr(db_store, "create_investigation", raise_weird)

    plan = harness.generate_local_plan("Unusual GET flood against /admin")

    assert plan is not None
    plan_file = isolated_config.plans_dir / f"{plan.id}.json"
    assert plan_file.exists()
