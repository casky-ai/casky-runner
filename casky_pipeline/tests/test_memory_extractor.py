"""Unit tests for casky_pipeline.memory.MemoryExtractor.

Uses a fake in-process LLMProvider (same pattern as test_pipeline.py's
FakeLLMProvider), never calls a real API.
"""

from __future__ import annotations

import json

import pytest

from casky_pipeline.llm_providers import LLMProvider
from casky_pipeline.memory import MAX_MEMORIES, MemoryExtractor


class FakeLLMProvider(LLMProvider):
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[dict] = []

    async def complete(self, system_prompt, user_prompt, max_tokens=2048, cacheable_system=True):
        self.calls.append({"system_prompt": system_prompt, "user_prompt": user_prompt})
        return self.response


def _investigation(**overrides) -> dict:
    base = {
        "id": "inv-1",
        "domain": "identity",
        "evidence_text": "Login from Tokyo for user john@example.com",
        "confidence": 0.8,
        "outcome_summary": "Confirmed benign — John was traveling in Japan this week.",
        "confirmed_technique_ids": [],
        "steps": [{"technique_id": "T1078", "skill_slug": "analyzing-identity-anomaly"}],
        "feedback": [],
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_valid_output_parses_into_memory_candidates():
    response = json.dumps({
        "memories": [{
            "statement": "Logins from Tokyo for this identity are expected during this period",
            "rationale": "John confirmed travel to Japan this week",
            "conditions": {"domain": "identity"},
            "applies_to": {"identities": ["john@example.com"]},
            "confidence": 0.85,
            "escalation_recommended": False,
            "expires_in_days": 14,
        }]
    })
    provider = FakeLLMProvider(response)
    output = await MemoryExtractor().run(_investigation(), provider)

    assert len(output.memories) == 1
    m = output.memories[0]
    assert m.statement.startswith("Logins from Tokyo")
    assert m.confidence == pytest.approx(0.85)
    assert m.escalation_recommended is False
    assert m.expires_in_days == 14


@pytest.mark.asyncio
async def test_malformed_json_degrades_to_empty_output_not_raise():
    provider = FakeLLMProvider("not json at all")
    output = await MemoryExtractor().run(_investigation(), provider)
    assert output.memories == []


@pytest.mark.asyncio
async def test_missing_memories_key_degrades_to_empty_output():
    provider = FakeLLMProvider(json.dumps({"not_memories": []}))
    output = await MemoryExtractor().run(_investigation(), provider)
    assert output.memories == []


@pytest.mark.asyncio
async def test_caps_at_max_memories_even_if_model_returns_more():
    response = json.dumps({
        "memories": [
            {
                "statement": f"statement {i}", "rationale": f"rationale {i}",
                "conditions": {}, "applies_to": {}, "confidence": 0.5,
                "escalation_recommended": True, "expires_in_days": None,
            }
            for i in range(MAX_MEMORIES + 3)
        ]
    })
    provider = FakeLLMProvider(response)
    output = await MemoryExtractor().run(_investigation(), provider)
    assert len(output.memories) == MAX_MEMORIES


@pytest.mark.asyncio
async def test_entries_missing_statement_or_rationale_are_dropped():
    response = json.dumps({
        "memories": [
            {"statement": "valid", "rationale": "valid rationale", "conditions": {}, "applies_to": {}, "confidence": 0.5, "escalation_recommended": True},
            {"rationale": "missing statement", "conditions": {}, "applies_to": {}, "confidence": 0.5, "escalation_recommended": True},
            {"statement": "missing rationale", "conditions": {}, "applies_to": {}, "confidence": 0.5, "escalation_recommended": True},
        ]
    })
    provider = FakeLLMProvider(response)
    output = await MemoryExtractor().run(_investigation(), provider)
    assert len(output.memories) == 1
    assert output.memories[0].statement == "valid"


@pytest.mark.asyncio
async def test_confidence_clamped_to_unit_interval():
    response = json.dumps({
        "memories": [
            {"statement": "a", "rationale": "a", "conditions": {}, "applies_to": {}, "confidence": 1.7, "escalation_recommended": True},
            {"statement": "b", "rationale": "b", "conditions": {}, "applies_to": {}, "confidence": -0.4, "escalation_recommended": True},
        ]
    })
    provider = FakeLLMProvider(response)
    output = await MemoryExtractor().run(_investigation(), provider)
    assert output.memories[0].confidence == 1.0
    assert output.memories[1].confidence == 0.0
