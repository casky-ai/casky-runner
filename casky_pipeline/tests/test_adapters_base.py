"""Unit tests for casky_pipeline.adapters.base.run_adapters()."""

from __future__ import annotations

import pytest

from casky_pipeline.adapters.base import (
    AdapterConfig,
    AdapterEntities,
    AdapterResult,
    ContextEngineAdapter,
    GraphEdge,
    GraphNode,
    run_adapters,
)


class FakeOkAdapter(ContextEngineAdapter):
    """A well-behaved adapter that returns nodes/edges with no source_adapter
    pre-set, so run_adapters() must stamp it."""

    name = "fake_ok"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        return AdapterResult(
            adapter_name=self.name,
            nodes=[GraphNode(id="n1", type="asset", label="Node 1")],
            edges=[GraphEdge(source_id="n1", target_id="n2", relation="affects")],
        )


class FakeRaisingAdapter(ContextEngineAdapter):
    """A buggy adapter that raises instead of catching internally — exercises
    run_adapters()'s return_exceptions=True backstop."""

    name = "fake_raising"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        raise RuntimeError("boom")


class FakeGracefulAdapter(ContextEngineAdapter):
    """An adapter that degrades gracefully per the ContextEngineAdapter
    contract: it returns (does not raise) an AdapterResult with error set."""

    name = "fake_graceful"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        return AdapterResult(adapter_name=self.name, error="degraded: no creds")


class FakeEmptyAdapter(ContextEngineAdapter):
    """An adapter that finds nothing but doesn't error."""

    name = "fake_empty"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        return AdapterResult(adapter_name=self.name)


def _entities() -> AdapterEntities:
    return AdapterEntities(cve_ids=["CVE-2024-0001"])


def _config() -> AdapterConfig:
    return AdapterConfig()


@pytest.mark.asyncio
async def test_stamps_source_adapter_on_nodes_and_edges():
    adapter = FakeOkAdapter()
    results = await run_adapters([adapter], _entities(), _config())

    assert len(results) == 1
    result = results[0]
    assert result.error is None
    assert len(result.nodes) == 1
    assert result.nodes[0].source_adapter == "fake_ok"
    assert len(result.edges) == 1
    assert result.edges[0].source_adapter == "fake_ok"


@pytest.mark.asyncio
async def test_raising_adapter_produces_error_result_instead_of_propagating():
    adapter = FakeRaisingAdapter()

    # Must not raise out of run_adapters().
    results = await run_adapters([adapter], _entities(), _config())

    assert len(results) == 1
    result = results[0]
    assert isinstance(result, AdapterResult)
    assert result.adapter_name == "fake_raising"
    assert result.error is not None
    assert "RuntimeError" in result.error
    assert "boom" in result.error
    assert result.nodes == []
    assert result.edges == []


@pytest.mark.asyncio
async def test_results_returned_in_same_order_as_input_adapters():
    adapters: list[ContextEngineAdapter] = [
        FakeRaisingAdapter(),
        FakeOkAdapter(),
        FakeGracefulAdapter(),
        FakeEmptyAdapter(),
    ]

    results = await run_adapters(adapters, _entities(), _config())

    assert [r.adapter_name for r in results] == [a.name for a in adapters]
    assert len(results) == len(adapters)


@pytest.mark.asyncio
async def test_adapter_returning_its_own_error_result_passes_through_unchanged():
    adapter = FakeGracefulAdapter()

    results = await run_adapters([adapter], _entities(), _config())

    assert len(results) == 1
    result = results[0]
    assert result.adapter_name == "fake_graceful"
    assert result.error == "degraded: no creds"
    assert result.nodes == []
    assert result.edges == []
    assert result.gaps == []
