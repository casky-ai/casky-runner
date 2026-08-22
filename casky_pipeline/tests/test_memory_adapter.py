"""Unit tests for casky_pipeline.adapters.memory_adapter.MemoryAdapter.enrich().

casky_pipeline.memory.find_relevant_memories is mocked throughout — same
pattern as test_local_history_adapter.py: patch the dependency where it's
imported *into*, assert enrich() never raises.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from casky_pipeline.adapters.base import AdapterConfig, AdapterEntities
from casky_pipeline.adapters.memory_adapter import MemoryAdapter


@pytest.mark.asyncio
async def test_no_entities_returns_empty_result_without_querying():
    adapter = MemoryAdapter()
    with patch("casky_pipeline.memory.find_relevant_memories") as mock_find:
        result = await adapter.enrich(AdapterEntities(), AdapterConfig())

    assert result.adapter_name == "memory"
    assert result.nodes == []
    assert result.error is None
    mock_find.assert_not_called()


@pytest.mark.asyncio
async def test_no_matches_emits_a_gap_not_an_error():
    adapter = MemoryAdapter()
    with patch("casky_pipeline.memory.find_relevant_memories", return_value=[]):
        result = await adapter.enrich(AdapterEntities(technique_ids=["T1078"]), AdapterConfig())

    assert result.error is None
    assert result.nodes == []
    assert any("organizational memory" in g for g in result.gaps)


@pytest.mark.asyncio
async def test_unexpected_exception_degrades_to_error_result_not_raise():
    adapter = MemoryAdapter()
    with patch("casky_pipeline.memory.find_relevant_memories", side_effect=RuntimeError("boom")):
        result = await adapter.enrich(AdapterEntities(technique_ids=["T1078"]), AdapterConfig())

    assert result.nodes == []
    assert result.error is not None
    assert "boom" in result.error


@pytest.mark.asyncio
async def test_matches_are_converted_into_graph_nodes():
    fake_matches = [{
        "id": "mem-1",
        "statement": "Logins from Tokyo for this identity are expected",
        "rationale": "John confirmed travel to Japan this week",
        "escalation_recommended": False,
        "effective_confidence": 0.82,
        "source_investigation_id": "inv-old",
    }]
    adapter = MemoryAdapter()
    with patch("casky_pipeline.memory.find_relevant_memories", return_value=fake_matches) as mock_find:
        result = await adapter.enrich(
            AdapterEntities(technique_ids=["T1078"]), AdapterConfig(extra={"database_url": "postgresql://x"})
        )

    mock_find.assert_called_once()
    _, kwargs = mock_find.call_args
    assert kwargs["technique_ids"] == ["T1078"]
    assert kwargs["database_url"] == "postgresql://x"

    assert result.error is None
    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.id == "memory:mem-1"
    assert node.type == "memory"
    assert node.properties["escalation_recommended"] is False
    assert node.properties["confidence"] == pytest.approx(0.82)
