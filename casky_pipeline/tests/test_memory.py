"""Unit tests for casky_pipeline.memory — decay math, dual-mode storage, and
entity-overlap retrieval.

casky_db.store is mocked throughout (patched at the point it's imported into,
same convention as test_local_history_adapter.py) — no real Postgres
connection is ever made here. JSON-file mode is exercised for real against
tmp_path.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from casky_pipeline.llm_providers import LLMProvider
from casky_pipeline.memory import (
    MIN_RETRIEVAL_CONFIDENCE,
    decayed_confidence,
    extract_and_store_memories,
    find_relevant_memories,
)


class FakeLLMProvider(LLMProvider):
    def __init__(self, response: str) -> None:
        self.response = response

    async def complete(self, system_prompt, user_prompt, max_tokens=2048, cacheable_system=True):
        return self.response


def _memory_response(**overrides) -> str:
    m = {
        "statement": "s", "rationale": "r", "conditions": {},
        "applies_to": {"identities": ["john@example.com"]},
        "confidence": 0.7, "escalation_recommended": False, "expires_in_days": 30,
    }
    m.update(overrides)
    return json.dumps({"memories": [m]})


def _investigation(**overrides) -> dict:
    base = {
        "id": "inv-1", "domain": "identity", "evidence_text": "ev",
        "confidence": 0.8, "outcome_summary": "Confirmed benign.",
        "confirmed_technique_ids": [], "steps": [], "feedback": [],
    }
    base.update(overrides)
    return base


# ── decayed_confidence ────────────────────────────────────────────────────────

def test_decay_full_confidence_at_zero_days():
    now = datetime.now(timezone.utc).isoformat()
    assert decayed_confidence(0.8, now, None) == pytest.approx(0.8, abs=1e-3)


def test_decay_half_confidence_at_one_half_life():
    ninety_days_ago = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    assert decayed_confidence(0.8, ninety_days_ago, None, half_life_days=90) == pytest.approx(0.4, abs=1e-2)


def test_decay_zero_past_hard_expiry_regardless_of_decay_math():
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    one_minute_ago = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert decayed_confidence(0.99, yesterday, one_minute_ago) == 0.0


def test_decay_by_age_alone_when_permanent():
    one_eighty_days_ago = (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()
    assert decayed_confidence(0.8, one_eighty_days_ago, None, half_life_days=90) == pytest.approx(0.2, abs=1e-2)


# ── extract_and_store_memories ────────────────────────────────────────────────

def test_missing_outcome_summary_skips_without_calling_llm():
    provider = FakeLLMProvider(_memory_response())
    result = extract_and_store_memories(_investigation(outcome_summary=""), provider)
    assert result["stored"] == 0
    assert "outcome_summary" in result["skipped_reason"]


def test_extractor_producing_nothing_is_reported_not_an_error():
    provider = FakeLLMProvider(json.dumps({"memories": []}))
    result = extract_and_store_memories(_investigation(), provider)
    assert result["stored"] == 0
    assert "no generalizable memories" in result["skipped_reason"]


def test_postgres_unavailable_on_first_call_falls_back_to_json(tmp_path):
    from casky_db.store import DatabaseUnavailable

    provider = FakeLLMProvider(_memory_response())
    with patch("casky_db.store.store_memory", side_effect=DatabaseUnavailable("DATABASE_URL is not set")):
        result = extract_and_store_memories(_investigation(), provider, memories_dir=tmp_path)

    assert result["stored"] == 1
    assert "postgres unavailable" in result["skipped_reason"]
    memory_file = tmp_path / "inv-1.json"
    assert memory_file.exists()
    rows = json.loads(memory_file.read_text())
    assert rows[0]["statement"] == "s"
    assert rows[0]["source_investigation_id"] == "inv-1"


def test_postgres_success_stores_via_store_memory_not_json(tmp_path):
    provider = FakeLLMProvider(_memory_response())
    with patch("casky_db.store.store_memory", return_value="mem-1") as mock_store:
        result = extract_and_store_memories(_investigation(), provider, database_url="postgresql://x", memories_dir=tmp_path)

    assert result["stored"] == 1
    assert "skipped_reason" not in result
    mock_store.assert_called_once()
    assert not (tmp_path / "inv-1.json").exists()


def test_failure_mid_batch_after_first_success_does_not_duplicate_to_json(tmp_path):
    """A partial Postgres write followed by a full JSON fallback would
    duplicate whatever already landed in Postgres — must not happen."""
    provider = FakeLLMProvider(json.dumps({"memories": [
        {"statement": "a", "rationale": "a", "conditions": {}, "applies_to": {}, "confidence": 0.5, "escalation_recommended": True},
        {"statement": "b", "rationale": "b", "conditions": {}, "applies_to": {}, "confidence": 0.5, "escalation_recommended": True},
    ]}))
    calls = {"n": 0}

    def flaky_store(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return "mem-id"

    with patch("casky_db.store.store_memory", side_effect=flaky_store):
        result = extract_and_store_memories(_investigation(), provider, database_url="postgresql://x", memories_dir=tmp_path)

    assert result["stored"] == 1  # only the first write succeeded
    assert not (tmp_path / "inv-1.json").exists()  # never falls back mid-batch


# ── find_relevant_memories ────────────────────────────────────────────────────

def test_no_entities_returns_empty_without_querying():
    with patch("casky_db.store.find_relevant_memories") as mock_find:
        result = find_relevant_memories(cve_ids=[], technique_ids=[])
    assert result == []
    mock_find.assert_not_called()


def test_postgres_path_filters_by_effective_confidence_floor():
    stale_row = {
        "id": "mem-old", "statement": "stale", "rationale": "r",
        "applies_to": {"technique_ids": ["T1078"]},
        "confidence": 0.2, "escalation_recommended": False,
        "created_at": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
        "last_reinforced_at": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
        "expires_at": None, "superseded_by": None, "source_investigation_id": "inv-old",
    }
    with patch("casky_db.store.find_relevant_memories", return_value=[stale_row]):
        result = find_relevant_memories(cve_ids=[], technique_ids=["T1078"])
    assert result == [], "a heavily-decayed match below MIN_RETRIEVAL_CONFIDENCE must be dropped"

    fresh_row = dict(stale_row, id="mem-fresh", confidence=0.9,
                      created_at=datetime.now(timezone.utc).isoformat(),
                      last_reinforced_at=datetime.now(timezone.utc).isoformat())
    with patch("casky_db.store.find_relevant_memories", return_value=[fresh_row]):
        fresh_result = find_relevant_memories(cve_ids=[], technique_ids=["T1078"])
    assert len(fresh_result) == 1
    assert fresh_result[0]["id"] == "mem-fresh"
    assert MIN_RETRIEVAL_CONFIDENCE > 0


def test_postgres_unavailable_falls_back_to_json_file(tmp_path):
    from casky_db.store import DatabaseUnavailable

    directory = tmp_path
    directory.mkdir(exist_ok=True)
    (directory / "inv-1.json").write_text(json.dumps([{
        "id": "mem-1", "statement": "s", "rationale": "r",
        "applies_to": {"identities": ["john@example.com"]},
        "confidence": 0.9, "escalation_recommended": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_reinforced_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": None, "superseded_by": None, "source_investigation_id": "inv-1",
    }]))

    with patch("casky_db.store.find_relevant_memories", side_effect=DatabaseUnavailable("no db")):
        result = find_relevant_memories(cve_ids=[], technique_ids=[], memories_dir=directory)
    # No cve/technique overlap requested against an identities-only memory — expect no match,
    # but the read path itself must not raise. Re-run with a matching entity type via
    # technique_ids to prove the fallback path actually surfaces rows when they DO match.
    assert result == []

    (directory / "inv-2.json").write_text(json.dumps([{
        "id": "mem-2", "statement": "s2", "rationale": "r2",
        "applies_to": {"technique_ids": ["T1078"]},
        "confidence": 0.9, "escalation_recommended": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_reinforced_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": None, "superseded_by": None, "source_investigation_id": "inv-2",
    }]))
    with patch("casky_db.store.find_relevant_memories", side_effect=DatabaseUnavailable("no db")):
        result2 = find_relevant_memories(cve_ids=[], technique_ids=["T1078"], memories_dir=directory)
    assert len(result2) == 1
    assert result2[0]["id"] == "mem-2"
    assert "effective_confidence" in result2[0]
