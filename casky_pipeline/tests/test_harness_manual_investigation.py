"""Tests for the resumable manual (non---auto) investigation flow:
run_interactive_investigation() and its helpers. Live-caught bug this closes:
casky harness (no --auto) printed "Paste the output back to this window...
Claude will analyze and synthesize findings into a report" and then just
exited — neither promise was implemented. This flow now actually captures
pasted output, saves progress after every step (so a killed/closed session
resumes instead of losing everything), and synthesizes findings via the same
BYO-LLM provider + hardened JSON parser the classifier pipeline uses.

Same conventions as test_harness_outcome_capture.py / test_harness_db_fallback.py:
casky_db.store and the LLM-facing calls are mocked/monkeypatched throughout,
no real network, DB, or stdin I/O.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import harness  # noqa: E402
from casky_db import store as db_store  # noqa: E402


def _step(**overrides) -> "harness.Step":
    base = dict(
        id="step-1", skill_slug="detecting-network-scanning-with-ids-signatures",
        skill_category="network", skill_document="", technique_id="T1046",
        technique_name="Network Service Discovery", rationale="find the scan",
        evidence_focus="IDS alerts", step_order=0, status="pending", manual_output="",
    )
    base.update(overrides)
    return harness.Step(**base)


def _plan(**overrides) -> "harness.Plan":
    base = dict(
        id="plan-1", domain="network", evidence_text="TCP SYN scan evidence", status="approved",
        steps=[], created_at="2026-08-01T00:00:00", cve_references=[],
        evidence_gaps=[], confidence=0.8,
    )
    base.update(overrides)
    return harness.Plan(**base)


@pytest.fixture
def isolated_config(monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "")
    return harness.config


@pytest.fixture
def fake_input(monkeypatch):
    """Feeds successive input() calls from a queue; raises EOFError once
    exhausted (matching real interactive-input-closed behavior), mirroring
    _capture_step_paste's own try/except EOFError handling."""
    lines: list[str] = []

    def fake(prompt=""):
        if not lines:
            raise EOFError
        return lines.pop(0)

    monkeypatch.setattr("builtins.input", fake)
    return lines


# ── _capture_step_paste ──────────────────────────────────────────────────────

def test_capture_step_paste_joins_lines_until_end_sentinel(fake_input):
    fake_input.extend(["first line", "second line", "END"])
    text, skipped = harness._capture_step_paste(1, 1)
    assert text == "first line\nsecond line"
    assert skipped is False


def test_capture_step_paste_skip_sentinel_as_first_line(fake_input):
    fake_input.extend(["SKIP"])
    text, skipped = harness._capture_step_paste(1, 1)
    assert text == ""
    assert skipped is True


def test_capture_step_paste_skip_only_honored_as_first_line(fake_input):
    """'SKIP' pasted mid-output (e.g. it's literally in a log line) must not
    be treated as the skip sentinel — only as the very first line."""
    fake_input.extend(["some output", "SKIP", "END"])
    text, skipped = harness._capture_step_paste(1, 1)
    assert text == "some output\nSKIP"
    assert skipped is False


def test_capture_step_paste_handles_eof_without_end_sentinel(fake_input):
    fake_input.extend(["partial output"])  # no END line — input() then raises EOFError
    text, skipped = harness._capture_step_paste(1, 1)
    assert text == "partial output"
    assert skipped is False


# ── _persist_step_capture ────────────────────────────────────────────────────

def test_persist_step_capture_json_mode_never_touches_postgres(isolated_config, monkeypatch):
    def fail_if_called(*a, **kw):
        raise AssertionError("db_store must not be called when DATABASE_URL is empty")
    monkeypatch.setattr(db_store, "update_step_status", fail_if_called)
    monkeypatch.setattr(db_store, "record_skill_execution", fail_if_called)

    saved = {}
    monkeypatch.setattr(harness, "_save_local_plan_file", lambda plan: saved.setdefault("plan", plan))

    step = _step(status="captured", manual_output="ip addr output")
    harness._persist_step_capture(_plan(steps=[step]), step)

    assert saved["plan"].steps[0].manual_output == "ip addr output"


def test_persist_step_capture_postgres_mode_calls_both_store_functions(monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")

    calls = []
    monkeypatch.setattr(db_store, "update_step_status", lambda *a, **kw: calls.append(("status", a, kw)))
    monkeypatch.setattr(db_store, "record_skill_execution", lambda *a, **kw: calls.append(("exec", a, kw)))

    def fail_if_called(plan):
        raise AssertionError("must not fall back to local file when Postgres succeeds")
    monkeypatch.setattr(harness, "_save_local_plan_file", fail_if_called)

    step = _step(status="captured", manual_output="scan detected")
    harness._persist_step_capture(_plan(id="plan-9", steps=[step]), step)

    assert calls[0][0] == "status"
    assert calls[0][1] == ("step-1", "captured")
    assert calls[1][0] == "exec"
    exec_kwargs = calls[1][2]
    assert exec_kwargs["investigation_id"] == "plan-9"
    assert exec_kwargs["step_id"] == "step-1"
    assert exec_kwargs["output"] == "scan detected"
    assert exec_kwargs["agent_used"] == "manual-paste"


def test_persist_step_capture_falls_back_to_local_file_on_postgres_failure(monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://bad:bad@127.0.0.1:1/nope")
    monkeypatch.setattr(db_store, "update_step_status", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("down")))

    saved = {"n": 0}
    monkeypatch.setattr(harness, "_save_local_plan_file", lambda plan: saved.__setitem__("n", saved["n"] + 1))

    step = _step(status="captured")
    harness._persist_step_capture(_plan(steps=[step]), step)

    assert saved["n"] == 1


# ── run_interactive_investigation: resume behavior ──────────────────────────

def test_resume_skips_already_captured_steps(isolated_config, fake_input, monkeypatch):
    monkeypatch.setattr(harness, "_save_local_plan_file", lambda plan: None)

    done_step = _step(id="s1", status="captured", manual_output="already have this")
    pending_step = _step(id="s2", status="pending")
    plan = _plan(steps=[done_step, pending_step])

    fake_input.extend(["fresh output", "END"])

    async def fake_synth(*a, **kw):
        return {"summary": "s", "findings": []}
    monkeypatch.setattr(harness, "_synthesize_manual_findings", fake_synth)
    monkeypatch.setattr(harness, "_save_manual_investigation_report", lambda plan, synthesis: "somewhere")
    # Not under test here — test_harness_outcome_capture.py owns this behavior.
    monkeypatch.setattr(harness, "_capture_outcome_and_extract_memory", lambda plan: None)

    harness.run_interactive_investigation(plan, plan.steps)

    assert done_step.manual_output == "already have this"  # untouched
    assert pending_step.status == "captured"
    assert pending_step.manual_output == "fresh output"


def test_no_captured_output_skips_synthesis_entirely(isolated_config, fake_input, monkeypatch):
    monkeypatch.setattr(harness, "_save_local_plan_file", lambda plan: None)
    step = _step(status="pending")
    plan = _plan(steps=[step])
    fake_input.extend(["SKIP"])  # skip the only step -> nothing captured

    def fail_if_called(*a, **kw):
        raise AssertionError("synthesis must not run with zero captured steps")
    monkeypatch.setattr(harness, "_synthesize_manual_findings", fail_if_called)

    harness.run_interactive_investigation(plan, plan.steps)
    assert step.status == "skipped"


def test_synthesis_failure_is_caught_progress_already_saved(isolated_config, fake_input, monkeypatch):
    monkeypatch.setattr(harness, "_save_local_plan_file", lambda plan: None)
    step = _step(status="pending")
    plan = _plan(steps=[step])
    fake_input.extend(["some output", "END"])

    async def raise_timeout(*a, **kw):
        raise RuntimeError("LLM timeout")
    monkeypatch.setattr(harness, "_synthesize_manual_findings", raise_timeout)

    def fail_if_called(*a, **kw):
        raise AssertionError("must not attempt to save a report when synthesis failed")
    monkeypatch.setattr(harness, "_save_manual_investigation_report", fail_if_called)

    # Must not raise — the whole point is captured output survives even if
    # synthesis itself fails.
    harness.run_interactive_investigation(plan, plan.steps)
    assert step.status == "captured"
    assert step.manual_output == "some output"


# ── _synthesize_manual_findings ──────────────────────────────────────────────

class _FakeProvider:
    def __init__(self, raw: str):
        self._raw = raw

    async def complete(self, system_prompt, user_prompt, max_tokens=4096, cacheable_system=True):
        return self._raw


@pytest.mark.asyncio
async def test_synthesize_manual_findings_parses_provider_response(monkeypatch):
    raw = (
        '```json\n{"summary": "Scan confirmed.", "risk_rating": "medium", '
        '"findings": [{"title": "Port scan", "severity": "medium", '
        '"mitre_technique": "T1046"}]}\n```'
    )
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: _FakeProvider(raw))

    step = _step(manual_output="SYN scan detected against 172.16.4.21")
    result = await harness._synthesize_manual_findings(_plan(), [step])

    assert result["summary"] == "Scan confirmed."
    assert result["findings"][0]["title"] == "Port scan"


# ── _save_manual_investigation_report ────────────────────────────────────────

def test_save_report_json_mode_writes_local_file(isolated_config, tmp_path, monkeypatch):
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)
    synthesis = {"summary": "sum", "risk_rating": "low", "findings": [
        {"title": "t", "severity": "low", "mitre_technique": "T1046"},
    ]}

    location = harness._save_manual_investigation_report(_plan(id="plan-42"), synthesis)

    report_path = tmp_path / "plan-42" / "REPORT.md"
    assert location == str(report_path)
    assert report_path.exists()
    assert "sum" in report_path.read_text()
    assert "t" in report_path.read_text()


def test_save_report_postgres_mode_never_writes_local_file(tmp_path, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)
    monkeypatch.setattr(db_store, "record_findings", lambda *a, **kw: None)
    monkeypatch.setattr(db_store, "save_consolidated_report", lambda *a, **kw: None)

    synthesis = {"summary": "sum", "risk_rating": "low", "findings": []}
    location = harness._save_manual_investigation_report(_plan(id="plan-7"), synthesis)

    assert location == "Postgres (investigation plan-7)"
    assert not (tmp_path / "plan-7").exists()


def test_save_report_falls_back_to_local_file_on_postgres_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://bad:bad@127.0.0.1:1/nope")
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)

    def raise_err(*a, **kw):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(db_store, "record_findings", raise_err)

    synthesis = {"summary": "sum", "risk_rating": "low", "findings": []}
    location = harness._save_manual_investigation_report(_plan(id="plan-3"), synthesis)

    assert location == str(tmp_path / "plan-3" / "REPORT.md")
    assert (tmp_path / "plan-3" / "REPORT.md").exists()


# ── _plan_from_db_investigation / list_db_plans ──────────────────────────────

def test_plan_from_db_investigation_resumes_status_and_manual_output():
    data = {
        "id": "inv-1", "domain": "network", "evidence_text": "ev", "status": "approved",
        "created_at": "2026-08-01T00:00:00", "confidence": 0.7,
        "evidence_gaps": ["gap 1"], "cve_references": [],
        "steps": [
            {"id": "s1", "skill_slug": "skill-a", "skill_category": "network",
             "technique_id": "T1046", "technique_name": "Network Service Discovery",
             "rationale": "r", "evidence_focus": "e", "step_order": 0, "status": "captured"},
            {"id": "s2", "skill_slug": "skill-b", "skill_category": "network",
             "technique_id": "T1018", "technique_name": "Remote System Discovery",
             "rationale": "r", "evidence_focus": "e", "step_order": 1, "status": "pending"},
        ],
        "skill_executions": [
            {"step_id": "s1", "output": "pasted nmap output"},
        ],
    }

    plan = harness._plan_from_db_investigation(data)

    assert plan.id == "inv-1"
    assert len(plan.steps) == 2
    assert plan.steps[0].id == "s1"
    assert plan.steps[0].status == "captured"
    assert plan.steps[0].manual_output == "pasted nmap output"
    assert plan.steps[1].status == "pending"
    assert plan.steps[1].manual_output == ""


def test_list_db_plans_resumes_each_investigation(monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")
    monkeypatch.setattr(db_store, "list_investigations", lambda *a, **kw: [{"id": "inv-1"}, {"id": "inv-2"}])

    fetched = {
        "inv-1": {"id": "inv-1", "domain": "d1", "evidence_text": "", "status": "approved",
                   "created_at": "", "confidence": 0.5, "evidence_gaps": [], "cve_references": [],
                   "steps": [], "skill_executions": []},
        "inv-2": None,  # deleted between list and get — must be skipped, not crash
    }
    monkeypatch.setattr(db_store, "get_investigation", lambda inv_id, database_url=None: fetched.get(inv_id))

    plans = harness.list_db_plans()

    assert len(plans) == 1
    assert plans[0].id == "inv-1"
