"""Tests for --auto mode's skill_executions persistence — AgentWorker.execute()
and _ReportHandler.do_POST()'s Postgres writes.

Live-caught by the user checking real investigations in casky-ui: the
"Execution" tab showed "No executions recorded." for every single --auto-mode
run, even ones that completed successfully with real findings. Root cause:
_ReportHandler.do_POST() (the bare HTTP handler receiving the agent's own
report POST mid-run) never wrote a skill_executions row — by its own comment,
it "has no closure over AgentWorker/AgentResult", so it genuinely lacked
step_id/agent_used/exit_code/timestamps, and chose not to fabricate them.
AgentWorker.execute() DOES have all of that, so it now pre-creates the row
(started_at set) before spawning the subprocess, and updates it (exit_code,
completed_at, output) after — the pre-create closes a race, since it means
the row already exists by the time do_POST's mid-run POST arrives, letting
findings link to it (skill_execution_id) instead of NULL.

No real subprocess or HTTP socket is exercised: asyncio.create_subprocess_exec
is replaced with a fake process, and casky_db.store is mocked throughout.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import harness  # noqa: E402
from casky_db import store as db_store  # noqa: E402


def _make_step(**overrides) -> "harness.Step":
    base = dict(
        id="step-1", skill_slug="detecting-network-scanning-with-ids-signatures",
        skill_category="network", skill_document="# Skill\n\nDo the thing.\n",
        technique_id="T1046", technique_name="Network Service Discovery",
        rationale="r", evidence_focus="e", step_order=0,
    )
    base.update(overrides)
    return harness.Step(**base)


def _make_plan(**overrides) -> "harness.Plan":
    base = dict(
        id="plan-1", domain="network", evidence_text="ev", status="approved",
        steps=[], created_at="2026-08-01T00:00:00", cve_references=[],
        evidence_gaps=[], confidence=0.8,
    )
    base.update(overrides)
    return harness.Plan(**base)


class _FakeStdout:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = list(lines)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._lines:
            raise StopAsyncIteration
        return self._lines.pop(0)


def _make_fake_proc(returncode: int = 0, stdout_lines: list[str] | None = None):
    proc = MagicMock()
    proc.stdin = MagicMock()
    proc.stdout = _FakeStdout([line.encode() for line in (stdout_lines or ["ok"])])
    proc.returncode = returncode
    proc.wait = AsyncMock(return_value=returncode)
    return proc


@pytest.fixture
def isolated_config(monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "")
    return harness.config


@pytest.fixture
def no_skills_library(tmp_path, monkeypatch):
    lib = tmp_path / "skills-library"
    lib.mkdir()
    monkeypatch.setattr(harness.config, "skills_library_path", lib)


# ── AgentWorker.execute(): pre-create + upsert skill_executions ─────────────

def test_agent_worker_json_mode_never_touches_postgres(isolated_config, no_skills_library, monkeypatch):
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", AsyncMock(return_value=_make_fake_proc())
    )

    def fail_if_called(*a, **kw):
        raise AssertionError("record_skill_execution must not be called when DATABASE_URL is empty")
    monkeypatch.setattr(db_store, "record_skill_execution", fail_if_called)

    result = asyncio.run(
        harness.AgentWorker().execute(_make_plan(), _make_step(), "http://casky-runner:8765", [])
    )
    assert result.exit_code == 0


def test_agent_worker_pre_creates_then_updates_the_same_execution_row(no_skills_library, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec",
        AsyncMock(return_value=_make_fake_proc(returncode=0, stdout_lines=["line one", "line two"])),
    )

    calls = []
    monkeypatch.setattr(db_store, "record_skill_execution", lambda *a, **kw: calls.append(kw))

    result = asyncio.run(
        harness.AgentWorker().execute(_make_plan(id="plan-9"), _make_step(), "http://casky-runner:8765", [])
    )

    assert len(calls) == 2
    pre, post = calls

    # Same row both times (run_id doubles as skill_executions.id).
    assert pre["run_id"] == post["run_id"] == result.run_id
    assert pre["investigation_id"] == post["investigation_id"] == "plan-9"
    assert pre["step_id"] == post["step_id"] == "step-1"

    # Pre-create: started, nothing else known yet.
    assert pre["exit_code"] is None
    assert pre["completed_at"] is None
    assert pre["output"] is None
    assert pre["started_at"] is not None

    # Post-update: the real outcome.
    assert post["exit_code"] == 0
    assert post["completed_at"] is not None
    assert post["output"] == "line one\nline two"


def test_agent_worker_postgres_failure_never_crashes_the_step(no_skills_library, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://bad:bad@127.0.0.1:1/nope")
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", AsyncMock(return_value=_make_fake_proc())
    )
    monkeypatch.setattr(
        db_store, "record_skill_execution",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("db down")),
    )

    # Must not raise — a Postgres failure here must never block the actual
    # investigation step, only skip its own (additive) persistence.
    result = asyncio.run(
        harness.AgentWorker().execute(_make_plan(), _make_step(), "http://casky-runner:8765", [])
    )
    assert result.exit_code == 0


def test_agent_worker_records_nonzero_exit_code(no_skills_library, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec",
        AsyncMock(return_value=_make_fake_proc(returncode=1)),
    )

    calls = []
    monkeypatch.setattr(db_store, "record_skill_execution", lambda *a, **kw: calls.append(kw))

    result = asyncio.run(
        harness.AgentWorker().execute(_make_plan(), _make_step(), "http://casky-runner:8765", [])
    )

    assert result.exit_code == 1
    assert calls[1]["exit_code"] == 1


# ── _ReportHandler.do_POST(): findings link to the pre-created execution ────

def _post_report(run_id: str, findings: list[dict]) -> tuple[int, bytes]:
    """Drives _ReportHandler.do_POST() over a real (ephemeral-port) HTTP
    round trip — the handler subclasses BaseHTTPRequestHandler, which does
    enough socket-level setup in its own __init__ that calling do_POST()
    directly without a real connection isn't a clean option."""
    import http.client
    import json
    import threading
    from http.server import HTTPServer

    server = HTTPServer(("127.0.0.1", 0), harness._ReportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        body = json.dumps({"findings": findings}).encode()
        conn.request(
            "POST", f"/api/runs/{run_id}/report", body=body,
            headers={"Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def isolated_report_globals(monkeypatch):
    monkeypatch.setattr(harness, "_local_reports", {})
    monkeypatch.setattr(harness, "_local_plan_id", "plan-1")


def test_report_post_links_findings_to_the_run_id_not_none(
    isolated_report_globals, tmp_path, monkeypatch
):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)

    calls = []
    monkeypatch.setattr(db_store, "record_findings", lambda *a, **kw: calls.append(a))

    status, _ = _post_report("run-abc", [{"title": "t", "severity": "high"}])

    assert status == 200
    assert len(calls) == 1
    investigation_id, skill_execution_id, findings = calls[0]
    assert investigation_id == "plan-1"
    assert skill_execution_id == "run-abc"  # NOT None
    assert findings == [{"title": "t", "severity": "high"}]


def test_report_post_json_mode_never_touches_postgres(isolated_report_globals, tmp_path, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "")
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)

    def fail_if_called(*a, **kw):
        raise AssertionError("record_findings must not be called when DATABASE_URL is empty")
    monkeypatch.setattr(db_store, "record_findings", fail_if_called)

    status, _ = _post_report("run-abc", [{"title": "t", "severity": "high"}])
    assert status == 200
