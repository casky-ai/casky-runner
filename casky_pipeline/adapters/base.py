"""Context engine adapter interface — the pluggable enrichment layer.

Every adapter takes extracted entities + config and returns a partial graph
(nodes/edges) plus any evidence gaps it noticed. Adapters run concurrently via
run_adapters() and MUST NOT let one failing adapter block the others.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    id: str                                   # stable, globally-unique within one investigation
    type: str                                 # e.g. "cve", "technique", "asset", "playbook_step"
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    source_adapter: str = ""                  # populated by run_adapters(), not by the adapter itself


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: str                             # e.g. "exploits", "maps_to", "affects", "suggested_by"
    properties: dict[str, Any] = field(default_factory=dict)
    source_adapter: str = ""                  # populated by run_adapters(), not by the adapter itself


@dataclass
class AdapterResult:
    adapter_name: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    error: str | None = None                  # set when the adapter degraded gracefully; still a valid result
    duration_ms: float = 0.0


@dataclass
class AdapterEntities:
    """Decoupled mirror of harness.ExtractedEntities (harness.py:68-74).
    Adapters must not import harness.py directly — the integration agent
    converts ExtractedEntities -> AdapterEntities at the call site."""
    cve_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)


@dataclass
class AdapterConfig:
    """Generic per-adapter config bag, populated from Config/env at the call site."""
    timeout_s: float = 15.0
    extra: dict[str, Any] = field(default_factory=dict)


class ContextEngineAdapter(ABC):
    """One pluggable enrichment source. Subclasses: CveMcpAdapter (Agent A),
    LocalPlaybookAdapter (Agent B). Future adapters (platform CVE spotlights,
    platform playbooks) follow the same shape."""

    name: str = "base"

    @abstractmethod
    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        """MUST NOT raise for expected failure modes (timeout, network error,
        missing/invalid credentials, empty input). Catch internally and return
        AdapterResult(adapter_name=self.name, error=str(exc)) instead — this
        keeps run_adapters() simple and keeps a bad adapter from ever reading
        as 'crashed' versus 'found nothing'. Only let truly unexpected
        exceptions (bugs) propagate; run_adapters()'s return_exceptions=True
        is the last-resort backstop, not the primary error path."""
        raise NotImplementedError


async def run_adapters(
    adapters: list[ContextEngineAdapter],
    entities: AdapterEntities,
    config: AdapterConfig,
) -> list[AdapterResult]:
    """Runs every adapter concurrently; one failing/raising adapter never
    blocks the others. Always returns len(adapters) results, in the same
    order as `adapters`."""
    started = time.monotonic()
    raw = await asyncio.gather(
        *(a.enrich(entities, config) for a in adapters),
        return_exceptions=True,
    )
    results: list[AdapterResult] = []
    for adapter, r in zip(adapters, raw):
        if isinstance(r, BaseException):
            results.append(
                AdapterResult(
                    adapter_name=adapter.name,
                    error=f"{type(r).__name__}: {r}",
                    duration_ms=(time.monotonic() - started) * 1000,
                )
            )
        else:
            for n in r.nodes:
                n.source_adapter = n.source_adapter or adapter.name
            for e in r.edges:
                e.source_adapter = e.source_adapter or adapter.name
            results.append(r)
    return results
