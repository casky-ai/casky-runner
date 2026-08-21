"""Unit tests for casky_pipeline.adapters.cve_mcp_adapter.CveMcpAdapter.enrich().

The mcp stdio client/session is mocked throughout — no real subprocess or
network call is ever made.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from casky_pipeline.adapters.base import AdapterConfig, AdapterEntities, AdapterResult
from casky_pipeline.adapters.cve_mcp_adapter import CveMcpAdapter


class FakeContentBlock:
    def __init__(self, text: str) -> None:
        self.text = text


class FakeToolResult:
    def __init__(self, content: list[FakeContentBlock]) -> None:
        self.content = content


def _make_async_cm(return_value):
    """Builds a MagicMock usable as `async with obj() as x: ...`."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=return_value)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _patch_mcp(session_mock: MagicMock):
    """Patches stdio_client and ClientSession as imported into the adapter
    module so `async with stdio_client(params) as (read, write): async with
    ClientSession(read, write) as session: ...` yields `session_mock` without
    touching the real mcp package."""
    stdio_cm = _make_async_cm((MagicMock(name="read"), MagicMock(name="write")))
    session_cm = _make_async_cm(session_mock)

    stdio_client_patch = patch(
        "casky_pipeline.adapters.cve_mcp_adapter.stdio_client",
        return_value=stdio_cm,
    )
    client_session_patch = patch(
        "casky_pipeline.adapters.cve_mcp_adapter.ClientSession",
        return_value=session_cm,
    )
    return stdio_client_patch, client_session_patch


@pytest.mark.asyncio
async def test_empty_cve_ids_returns_empty_result_without_invoking_mcp():
    with patch(
        "casky_pipeline.adapters.cve_mcp_adapter.stdio_client"
    ) as mock_stdio, patch(
        "casky_pipeline.adapters.cve_mcp_adapter.ClientSession"
    ) as mock_session_cls:
        adapter = CveMcpAdapter()
        result = await adapter.enrich(AdapterEntities(cve_ids=[]), AdapterConfig())

    assert result == AdapterResult(adapter_name="cve_mcp")
    mock_stdio.assert_not_called()
    mock_session_cls.assert_not_called()


@pytest.mark.asyncio
async def test_successful_lookup_produces_expected_node_and_edge_shapes():
    data = {
        "CVE-2024-1234": {
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "is_kev": True,
            "technique_ids": ["T1190"],
        }
    }
    session_mock = MagicMock()
    session_mock.initialize = AsyncMock(return_value=None)
    session_mock.call_tool = AsyncMock(
        return_value=FakeToolResult(content=[FakeContentBlock(json.dumps(data))])
    )

    stdio_patch, session_patch = _patch_mcp(session_mock)
    with stdio_patch, session_patch:
        adapter = CveMcpAdapter()
        result = await adapter.enrich(
            AdapterEntities(cve_ids=["CVE-2024-1234"]), AdapterConfig()
        )

    assert result.error is None
    assert result.gaps == []

    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.id == "cve:CVE-2024-1234"
    assert node.type == "cve"
    assert node.label == "CVE-2024-1234"
    assert node.properties == {
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "is_kev": True,
    }

    assert len(result.edges) == 1
    edge = result.edges[0]
    assert edge.source_id == "cve:CVE-2024-1234"
    assert edge.target_id == "technique:T1190"
    assert edge.relation == "maps_to"

    session_mock.call_tool.assert_awaited_once_with(
        "lookup_cve", {"cve_ids": ["CVE-2024-1234"]}
    )


@pytest.mark.asyncio
async def test_missing_cve_in_response_produces_gap_message():
    data: dict = {}  # CVE-2024-9999 not present in the mcp response
    session_mock = MagicMock()
    session_mock.initialize = AsyncMock(return_value=None)
    session_mock.call_tool = AsyncMock(
        return_value=FakeToolResult(content=[FakeContentBlock(json.dumps(data))])
    )

    stdio_patch, session_patch = _patch_mcp(session_mock)
    with stdio_patch, session_patch:
        adapter = CveMcpAdapter()
        result = await adapter.enrich(
            AdapterEntities(cve_ids=["CVE-2024-9999"]), AdapterConfig()
        )

    assert result.error is None
    assert result.nodes == []
    assert result.edges == []
    assert result.gaps == ["No CVE enrichment data returned for CVE-2024-9999"]


@pytest.mark.asyncio
async def test_mcp_exception_is_caught_and_returned_as_adapter_result_error():
    with patch(
        "casky_pipeline.adapters.cve_mcp_adapter.stdio_client",
        side_effect=ConnectionError("boom"),
    ):
        adapter = CveMcpAdapter()
        result = await adapter.enrich(
            AdapterEntities(cve_ids=["CVE-2024-0001"]), AdapterConfig()
        )

    assert result.adapter_name == "cve_mcp"
    assert result.error is not None
    assert "ConnectionError" in result.error
    assert "boom" in result.error
    assert result.nodes == []
    assert result.edges == []
    assert result.gaps == []
