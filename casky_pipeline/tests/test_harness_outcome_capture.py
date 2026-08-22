"""Tests for harness._capture_outcome_and_extract_memory — the CLI's
outcome-capture prompt that gates memory extraction, same "human-confirmed
judgment, not an auto-summary" quality bar as the SaaS product's outcome
route. Same conventions as test_harness_db_fallback.py: casky_db.store and
the LLM-facing calls are mocked/monkeypatched throughout, no real network or
DB I/O, no real Prompt.ask (never actually blocks on stdin in a test run).
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


def _plan(**overrides) -> "harness.Plan":
    base = dict(
        id="plan-1", domain="identity", evidence_text="ev", status="approved",
        steps=[], created_at="2026-08-01T00:00:00", cve_references=[],
        evidence_gaps=[], confidence=0.8,
    )
    base.update(overrides)
    return harness.Plan(**base)


@pytest.fixture
def no_prompt_input(monkeypatch):
    """Controls what Prompt.ask returns, in call order, without ever
    touching real stdin."""
    answers: list[str] = []

    def fake_ask(prompt_text, default=""):
        return answers.pop(0) if answers else default

    monkeypatch.setattr(harness.Prompt, "ask", fake_ask)
    return answers


@pytest.fixture
def isolated_config(monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "")
    return harness.config


def test_empty_outcome_summary_skips_extraction_entirely(isolated_config, no_prompt_input, monkeypatch):
    no_prompt_input.extend(["   "])  # whitespace-only outcome summary

    called = {"n": 0}
    monkeypatch.setattr(harness, "extract_and_store_memories", lambda *a, **kw: called.__setitem__("n", called["n"] + 1))

    harness._capture_outcome_and_extract_memory(_plan())
    assert called["n"] == 0


def test_json_mode_never_calls_record_outcome(isolated_config, no_prompt_input, monkeypatch):
    """DATABASE_URL empty -> record_outcome() must never even be attempted,
    matching generate_local_plan()'s own JSON-file-mode guarantee."""
    no_prompt_input.extend(["Confirmed benign — travel window.", "T1078"])

    def fail_if_called(*a, **kw):
        raise AssertionError("record_outcome() must not be called when DATABASE_URL is empty")
    monkeypatch.setattr(db_store, "record_outcome", fail_if_called)

    captured = {}
    def fake_extract(investigation, provider, database_url=None):
        captured["investigation"] = investigation
        return {"stored": 1}
    monkeypatch.setattr(harness, "extract_and_store_memories", fake_extract)
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: object())

    harness._capture_outcome_and_extract_memory(_plan())

    assert captured["investigation"]["outcome_summary"] == "Confirmed benign — travel window."
    assert captured["investigation"]["confirmed_technique_ids"] == ["T1078"]
    assert captured["investigation"]["id"] == "plan-1"


def test_postgres_mode_calls_record_outcome_before_extraction(no_prompt_input, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://casky:casky@db:5432/casky")
    no_prompt_input.extend(["Confirmed benign.", ""])

    calls = []
    monkeypatch.setattr(db_store, "record_outcome", lambda *a, **kw: calls.append(a))
    monkeypatch.setattr(harness, "extract_and_store_memories", lambda *a, **kw: {"stored": 0})
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: object())

    harness._capture_outcome_and_extract_memory(_plan())

    assert len(calls) == 1
    assert calls[0][0] == "plan-1"
    assert calls[0][1] == "Confirmed benign."


def test_record_outcome_database_unavailable_skips_extraction(no_prompt_input, monkeypatch):
    monkeypatch.setattr(harness.config, "database_url", "postgresql://bad:bad@127.0.0.1:1/nope")
    no_prompt_input.extend(["Confirmed benign.", ""])

    def raise_unavailable(*a, **kw):
        raise db_store.DatabaseUnavailable("simulated failure")
    monkeypatch.setattr(db_store, "record_outcome", raise_unavailable)

    called = {"n": 0}
    monkeypatch.setattr(harness, "extract_and_store_memories", lambda *a, **kw: called.__setitem__("n", called["n"] + 1))

    harness._capture_outcome_and_extract_memory(_plan())
    assert called["n"] == 0, "extraction must not run once the outcome itself failed to record"


def test_extraction_failure_is_caught_never_crashes_cli(isolated_config, no_prompt_input, monkeypatch):
    no_prompt_input.extend(["Confirmed benign.", ""])

    def raise_weird(*a, **kw):
        raise RuntimeError("LLM timeout")
    monkeypatch.setattr(harness, "extract_and_store_memories", raise_weird)
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: object())

    # Must not raise.
    harness._capture_outcome_and_extract_memory(_plan())
