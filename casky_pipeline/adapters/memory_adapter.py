"""Organizational memory adapter — surfaces relevant memories (extracted
reasoning from past investigation outcomes, see casky_pipeline/memory.py)
whose entities overlap the current investigation.

Same shape as LocalHistoryAdapter/LocalPlaybookAdapter/CveMcpAdapter: never
raises, degrades to an empty AdapterResult (plus an explanatory gap) when
storage is unavailable — DATABASE_URL unset is the expected, non-error
transitional state (find_relevant_memories() already falls back to the
JSON-file store in that case, so this adapter only sees an empty result,
not an error, in the common case).

Unlike LocalHistoryAdapter today (informational-only per harness.py's
generate_local_plan() comment), memory nodes are intended to feed the
classifier pipeline directly — they're threaded into ClassifierInput's
context_nodes/context_edges the same way CVE/playbook nodes already are.
"""

from __future__ import annotations

from casky_pipeline.adapters.base import (
    AdapterConfig,
    AdapterEntities,
    AdapterResult,
    ContextEngineAdapter,
    GraphNode,
)


class MemoryAdapter(ContextEngineAdapter):
    name = "memory"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        if not (entities.technique_ids or entities.cve_ids or entities.ips or entities.hostnames):
            return AdapterResult(adapter_name=self.name)

        try:
            from casky_pipeline.memory import find_relevant_memories

            database_url = config.extra.get("database_url")
            matches = find_relevant_memories(
                cve_ids=entities.cve_ids,
                technique_ids=entities.technique_ids,
                ips=entities.ips,
                hostnames=entities.hostnames,
                database_url=database_url,
            )
        except Exception as exc:  # noqa: BLE001 — must degrade, never raise (base.py contract)
            return AdapterResult(adapter_name=self.name, error=f"{type(exc).__name__}: {exc}")

        if not matches:
            return AdapterResult(
                adapter_name=self.name,
                gaps=["No relevant organizational memory found for these entities"],
            )

        nodes: list[GraphNode] = []
        for m in matches:
            nodes.append(
                GraphNode(
                    id=f"memory:{m.get('id', '')}",
                    type="memory",
                    label=str(m.get("statement", "")),
                    properties={
                        "statement": m.get("statement", ""),
                        "rationale": m.get("rationale", ""),
                        "escalation_recommended": m.get("escalation_recommended", True),
                        "confidence": m.get("effective_confidence", 0.0),
                        "source_investigation_id": m.get("source_investigation_id", ""),
                    },
                )
            )

        return AdapterResult(adapter_name=self.name, nodes=nodes)
