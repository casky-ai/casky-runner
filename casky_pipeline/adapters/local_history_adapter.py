"""Local investigation history adapter — surfaces past investigations from
the Postgres store (casky_db.store) whose CVEs/MITRE techniques/domain
overlap the current one, via store.find_related().

Same shape as LocalPlaybookAdapter/CveMcpAdapter: never raises, degrades to
an empty AdapterResult (plus an explanatory gap) when the store is
unavailable — DATABASE_URL unset is Part B's real, expected transitional
state for anyone who hasn't set up Postgres yet, not an error.
"""

from __future__ import annotations

from casky_pipeline.adapters.base import (
    AdapterConfig,
    AdapterEntities,
    AdapterResult,
    ContextEngineAdapter,
    GraphNode,
)


class LocalHistoryAdapter(ContextEngineAdapter):
    name = "local_history"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        try:
            from casky_db import store
        except ImportError as exc:  # pragma: no cover - packaging issue, not logic
            return AdapterResult(adapter_name=self.name, error=f"{type(exc).__name__}: {exc}")

        if not (entities.technique_ids or entities.cve_ids):
            return AdapterResult(adapter_name=self.name)

        try:
            # AdapterEntities has no `domain` field (see base.py) — this
            # adapter runs *before* a domain is known for the investigation
            # being built (domain is derived from the classifier's own
            # output later in generate_local_plan()), so `domain=None` here
            # is honest, not a placeholder for a field that should exist.
            related = store.find_related(
                technique_ids=entities.technique_ids,
                cve_ids=entities.cve_ids,
                domain=None,
            )
        except store.DatabaseUnavailable:
            return AdapterResult(
                adapter_name=self.name,
                gaps=["local investigation history unavailable — DATABASE_URL not configured"],
            )
        except Exception as exc:  # noqa: BLE001 — must degrade, never raise (base.py contract)
            return AdapterResult(adapter_name=self.name, error=f"{type(exc).__name__}: {exc}")

        nodes: list[GraphNode] = []
        for inv in related:
            matched_techniques = inv.get("matched_technique_ids", [])
            matched_cves = inv.get("matched_cve_ids", [])
            label_bits = []
            if inv.get("domain"):
                label_bits.append(str(inv["domain"]))
            label_bits.append(f"investigation {str(inv.get('id', ''))[:8]}")
            nodes.append(
                GraphNode(
                    id=f"past_investigation:{inv.get('id', '')}",
                    type="past_investigation",
                    label=" — ".join(label_bits),
                    properties={
                        "domain": inv.get("domain", ""),
                        "status": inv.get("status", ""),
                        "confidence": inv.get("confidence"),
                        "created_at": str(inv.get("created_at", "")),
                        "matched_technique_ids": matched_techniques,
                        "matched_cve_ids": matched_cves,
                        "domain_match": inv.get("domain_match", False),
                    },
                )
            )

        return AdapterResult(adapter_name=self.name, nodes=nodes)
