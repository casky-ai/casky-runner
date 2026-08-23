"""Unit tests for casky_pipeline.adapters.local_history_adapter.LocalHistoryAdapter.enrich().

casky_db.store is mocked throughout — no real Postgres connection is ever
made. Same pattern as test_cve_mcp_adapter.py / test_local_playbook_adapter.py:
patch the dependency where it's imported *into*, assert enrich() never raises.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from casky_pipeline.adapters.base import AdapterConfig, AdapterEntities
from casky_pipeline.adapters.local_history_adapter import LocalHistoryAdapter


@pytest.mark.asyncio
async def test_no_entities_returns_empty_result_without_querying_store():
    adapter = LocalHistoryAdapter()
    with patch("casky_db.store.find_related") as mock_find_related:
        result = await adapter.enrich(AdapterEntities(), AdapterConfig())

    assert result.adapter_name == "local_history"
    assert result.nodes == []
    assert result.error is None
    mock_find_related.assert_not_called()


@pytest.mark.asyncio
async def test_degrades_gracefully_when_database_unavailable():
    """The documented, expected transitional state — DATABASE_URL unset —
    must degrade to an explanatory gap, never raise."""
    from casky_db.store import DatabaseUnavailable

    adapter = LocalHistoryAdapter()
    with patch("casky_db.store.find_related", side_effect=DatabaseUnavailable("DATABASE_URL is not set")):
        result = await adapter.enrich(
            AdapterEntities(technique_ids=["T1595"]), AdapterConfig()
        )

    assert result.adapter_name == "local_history"
    assert result.nodes == []
    assert result.error is None
    assert any("DATABASE_URL" in g for g in result.gaps)


@pytest.mark.asyncio
async def test_unexpected_exception_degrades_to_error_result_not_raise():
    adapter = LocalHistoryAdapter()
    with patch("casky_db.store.find_related", side_effect=RuntimeError("boom")):
        result = await adapter.enrich(
            AdapterEntities(technique_ids=["T1595"]), AdapterConfig()
        )

    assert result.adapter_name == "local_history"
    assert result.nodes == []
    assert result.error is not None
    assert "boom" in result.error


@pytest.mark.asyncio
async def test_matches_are_converted_into_graph_nodes():
    fake_matches = [
        {
            "id": "abc12345-0000-0000-0000-000000000000",
            "domain": "web-app",
            "status": "approved",
            "confidence": 0.9,
            "created_at": "2026-08-01T00:00:00",
            "matched_technique_ids": ["T1595"],
            "matched_cve_ids": [],
            "domain_match": False,
        }
    ]
    adapter = LocalHistoryAdapter()
    with patch("casky_db.store.find_related", return_value=fake_matches) as mock_find_related:
        result = await adapter.enrich(
            AdapterEntities(technique_ids=["T1595"], cve_ids=["CVE-2024-1234"]),
            AdapterConfig(),
        )

    mock_find_related.assert_called_once()
    _, kwargs = mock_find_related.call_args
    assert kwargs["technique_ids"] == ["T1595"]
    assert kwargs["cve_ids"] == ["CVE-2024-1234"]
    # AdapterEntities has no domain field — this adapter honestly passes
    # domain=None rather than inventing one (see its enrich() docstring).
    assert kwargs["domain"] is None

    assert result.error is None
    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.id == "past_investigation:abc12345-0000-0000-0000-000000000000"
    assert node.type == "past_investigation"
    assert node.properties["matched_technique_ids"] == ["T1595"]
    assert node.properties["domain"] == "web-app"


@pytest.mark.asyncio
async def test_no_matches_returns_empty_nodes():
    adapter = LocalHistoryAdapter()
    with patch("casky_db.store.find_related", return_value=[]):
        result = await adapter.enrich(
            AdapterEntities(technique_ids=["T1595"]), AdapterConfig()
        )

    assert result.nodes == []
    assert result.error is None
