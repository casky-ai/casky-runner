"""Tests for --auto mode's skill_executions persistence — AgentWorker.execute()
and _ReportHandler.do_POST()'s Postgres writes — plus TranscriptAccumulator,
the --output-format stream-json parser that turns "the agent says it ran the
script" into a verifiable transcript of the real Bash commands it ran and the
real output they returned.

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

Requested directly for a workshop demo: "deterministically show that we are
running the skills and the agent.py". This doesn't make execution
deterministic — the agent still decides how to accomplish the task, same
steering-not-enforcement policy as ever — but it does turn the question from
"take the agent's word for it" into "here is the literal shell command it ran
and the literal output it got back". CASKY_CAPTURE_TRANSCRIPT=1 (casky.sh)
switches the subprocess to --output-format stream-json --verbose; the JSONL
shape used in these fixtures was confirmed directly against the real,
installed Claude Code CLI before being encoded here, not assumed from docs.

No real subprocess or HTTP socket is exercised: asyncio.create_subprocess_exec
is replaced with a fake process, and casky_db.store is mocked throughout.
"""

from __future__ import annotations

import asyncio
import json
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


# ── stream-json event fixtures — shape confirmed against the real CLI ───────

def _assistant_text(text: str) -> str:
    return json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}})


def _assistant_tool_use(tool_use_id: str, command: str) -> str:
    return json.dumps({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": tool_use_id, "name": "Bash", "input": {"command": command}}
    ]}})


def _tool_result(tool_use_id: str, stdout: str, is_error: bool = False) -> str:
    return json.dumps({
        "type": "user",
        "message": {"content": [
            {"tool_use_id": tool_use_id, "type": "tool_result", "content": stdout, "is_error": is_error}
        ]},
        "tool_use_result": {"stdout": stdout, "stderr": "", "interrupted": False},
    })


def _result_event(text: str) -> str:
    return json.dumps({"type": "result", "result": text, "is_error": False})


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
    default_lines = [
        _assistant_text("Working on it."),
        _result_event("Done."),
    ]
    proc = MagicMock()
    proc.stdin = MagicMock()
    proc.stdout = _FakeStdout([line.encode() for line in (stdout_lines or default_lines)])
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


# ── TranscriptAccumulator ────────────────────────────────────────────────────

def test_transcript_accumulator_extracts_bash_command_and_result():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_assistant_tool_use("t1", "python3 /opt/skills-library/skills/x/scripts/agent.py"))
    acc.ingest_line(_tool_result("t1", "scan complete, 3 open ports"))
    acc.ingest_line(_result_event("Found 3 open ports."))

    assert len(acc.tool_calls) == 1
    assert acc.tool_calls[0]["command"] == "python3 /opt/skills-library/skills/x/scripts/agent.py"
    assert acc.tool_calls[0]["output"] == "scan complete, 3 open ports"
    assert acc.final_result == "Found 3 open ports."


def test_transcript_accumulator_handles_string_shaped_tool_use_result():
    """Live-caught, real traceback, not a hypothetical: tool_use_result isn't
    always {"stdout": ..., "stderr": ...} — for some tool results the CLI
    emits it as a plain string instead. The naive tr.get("stdout") crashed
    with AttributeError: 'str' object has no attribute 'get', taking down
    the whole step. This looked exactly like a concurrency bug (every run
    with 2+ steps failed, the one successful run only ever ran one step) but
    wasn't one — any single step whose agent happened to use a tool with
    this result shape would hit it alone; more concurrent steps just meant
    more chances of at least one hitting it."""
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_assistant_tool_use("t1", "python3 /opt/skills-library/skills/x/scripts/agent.py"))
    acc.ingest_line(json.dumps({
        "type": "user",
        "message": {"content": [
            {"tool_use_id": "t1", "type": "tool_result", "content": "fallback text", "is_error": False}
        ]},
        "tool_use_result": "a plain string, not a dict",
    }))
    acc.ingest_line(_result_event("Done despite the odd shape."))

    assert acc.tool_calls[0]["output"] == "a plain string, not a dict"
    assert acc.final_result == "Done despite the odd shape."


def test_transcript_accumulator_skips_non_dict_content_blocks():
    """Same defensive posture as the tool_use_result fix above, applied
    everywhere else this code assumes a dict — a content block that's
    somehow not a dict (e.g. a bare string) must be skipped, not crash the
    whole ingest_line() call."""
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(json.dumps({
        "type": "assistant",
        "message": {"content": ["not a dict", {"type": "text", "text": "still works"}]},
    }))
    assert acc.narration_parts == ["still works"]


def test_transcript_accumulator_coerces_non_string_result_to_string():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(json.dumps({"type": "result", "result": {"unexpected": "shape"}}))
    assert acc.final_result == "{'unexpected': 'shape'}"


def test_transcript_accumulator_ignores_non_bash_tool_calls():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(json.dumps({
        "type": "assistant",
        "message": {"content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/etc/hosts"}}]},
    }))
    assert acc.tool_calls == []


def test_transcript_accumulator_never_raises_on_malformed_line():
    acc = harness.TranscriptAccumulator()
    display = acc.ingest_line("not valid json at all")
    assert display == "not valid json at all"
    assert acc.tool_calls == []


def test_skill_script_invoked_true_when_command_contains_the_path():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_assistant_tool_use("t1", "python3 /opt/skills-library/skills/x/scripts/agent.py --target foo"))
    assert acc.skill_script_invoked(Path("/opt/skills-library/skills/x/scripts/agent.py")) is True


def test_skill_script_invoked_false_when_agent_used_something_else():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_assistant_tool_use("t1", "nmap -sV casky-target"))
    assert acc.skill_script_invoked(Path("/opt/skills-library/skills/x/scripts/agent.py")) is False


def test_skill_script_invoked_false_when_no_script_path_given():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_assistant_tool_use("t1", "python3 /opt/skills-library/skills/x/scripts/agent.py"))
    assert acc.skill_script_invoked(None) is False


def test_build_output_includes_verified_banner_and_full_transcript():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_assistant_tool_use("t1", "python3 /opt/skills-library/skills/x/scripts/agent.py"))
    acc.ingest_line(_tool_result("t1", "3 open ports found"))
    acc.ingest_line(_result_event("Scan complete: 3 open ports."))

    output = acc.build_output(Path("/opt/skills-library/skills/x/scripts/agent.py"))

    assert "Scan complete: 3 open ports." in output
    assert "[VERIFIED] Skill script executed: YES" in output
    assert "Tool Call Transcript (1 real invocation(s))" in output
    assert "$ python3 /opt/skills-library/skills/x/scripts/agent.py" in output
    assert "3 open ports found" in output


def test_build_output_says_no_when_skill_script_never_ran():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_assistant_tool_use("t1", "nmap -sV casky-target"))
    acc.ingest_line(_tool_result("t1", "22/tcp open"))
    acc.ingest_line(_result_event("Found SSH open."))

    output = acc.build_output(Path("/opt/skills-library/skills/x/scripts/agent.py"))
    assert "[VERIFIED] Skill script executed: NO" in output


def test_build_output_omits_verification_and_transcript_when_no_script_configured():
    acc = harness.TranscriptAccumulator()
    acc.ingest_line(_result_event("Nothing to check."))
    output = acc.build_output(None)
    assert "VERIFIED" not in output
    assert "Tool Call Transcript" not in output


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
        AsyncMock(return_value=_make_fake_proc(returncode=0, stdout_lines=[
            _assistant_text("Working on it."),
            _result_event("All done."),
        ])),
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

    # Post-update: the real outcome — no skill script configured in this
    # fixture (no_skills_library), so build_output() is just the narration.
    assert post["exit_code"] == 0
    assert post["completed_at"] is not None
    assert post["output"] == "All done."


def test_agent_worker_records_verified_yes_when_skill_script_actually_ran(tmp_path, monkeypatch):
    """End-to-end: a real skill script on disk, a fake agent subprocess that
    actually invokes it — confirms the VERIFIED banner reaches both the
    persisted output (skill_executions.output, casky-ui's Execution tab) and
    the live output_lines buffer (the on-screen dashboard panel), not just
    one or the other."""
    lib = tmp_path / "skills-library"
    scripts = lib / "skills" / "detecting-network-scanning-with-ids-signatures" / "scripts"
    scripts.mkdir(parents=True)
    script_path = scripts / "agent.py"
    script_path.write_text("# stub\n")
    monkeypatch.setattr(harness.config, "skills_library_path", lib)
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec",
        AsyncMock(return_value=_make_fake_proc(returncode=0, stdout_lines=[
            _assistant_tool_use("t1", f"python3 {script_path} --target casky-target"),
            _tool_result("t1", "Detected 1714-port SYN scan pattern."),
            _result_event("Confirmed network scanning via IDS signature match."),
        ])),
    )

    calls = []
    monkeypatch.setattr(db_store, "record_skill_execution", lambda *a, **kw: calls.append(kw))
    live_lines: list[str] = []

    asyncio.run(
        harness.AgentWorker().execute(_make_plan(), _make_step(), "http://casky-runner:8765", live_lines)
    )

    post = calls[1]
    assert "[VERIFIED] Skill script executed: YES" in post["output"]
    assert "Detected 1714-port SYN scan pattern." in post["output"]
    assert any("[VERIFIED] Skill script executed: YES" in line for line in live_lines)


def test_agent_worker_records_verified_no_when_agent_used_something_else(tmp_path, monkeypatch):
    lib = tmp_path / "skills-library"
    scripts = lib / "skills" / "detecting-network-scanning-with-ids-signatures" / "scripts"
    scripts.mkdir(parents=True)
    script_path = scripts / "agent.py"
    script_path.write_text("# stub\n")
    monkeypatch.setattr(harness.config, "skills_library_path", lib)
    monkeypatch.setattr(harness.config, "database_url", "")

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec",
        AsyncMock(return_value=_make_fake_proc(returncode=0, stdout_lines=[
            _assistant_tool_use("t1", "nmap -sV casky-target"),
            _tool_result("t1", "22/tcp open ssh"),
            _result_event("Found SSH open."),
        ])),
    )

    result = asyncio.run(
        harness.AgentWorker().execute(_make_plan(), _make_step(), "http://casky-runner:8765", [])
    )
    assert "[VERIFIED] Skill script executed: NO" in result.output


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
