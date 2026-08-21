"""Ports harness.py's enrich_with_cve_mcp() (harness.py:271-290) into the
ContextEngineAdapter shape. Same stdio invocation, same tool call — do not
switch to the (unused) SSE container in docker/mcp/."""

from __future__ import annotations

import json
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from casky_pipeline.adapters.base import (
    AdapterConfig,
    AdapterEntities,
    AdapterResult,
    ContextEngineAdapter,
    GraphEdge,
    GraphNode,
)

CVE_MCP_COMMAND = "/opt/cve-mcp/bin/python3"   # matches repo-root Dockerfile venv path
CVE_MCP_ARGS = ["-m", "cve_mcp.server"]


class CveMcpAdapter(ContextEngineAdapter):
    name = "cve_mcp"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        if not entities.cve_ids:
            return AdapterResult(adapter_name=self.name)

        try:
            params = StdioServerParameters(command=CVE_MCP_COMMAND, args=CVE_MCP_ARGS)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "lookup_cve", {"cve_ids": entities.cve_ids}
                    )
                    data: dict[str, Any] = {}
                    if result.content:
                        data = json.loads(result.content[0].text)
        except Exception as exc:  # noqa: BLE001 — must degrade, never raise (see base.py contract)
            return AdapterResult(adapter_name=self.name, error=f"{type(exc).__name__}: {exc}")

        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        gaps: list[str] = []
        for cve_id in entities.cve_ids:
            cve_data = data.get(cve_id)
            if not cve_data:
                gaps.append(f"No CVE enrichment data returned for {cve_id}")
                continue
            node_id = f"cve:{cve_id}"
            nodes.append(GraphNode(
                id=node_id,
                type="cve",
                label=cve_id,
                properties={
                    "cvss_score": cve_data.get("cvss_score"),
                    "cvss_severity": cve_data.get("cvss_severity", ""),
                    "is_kev": cve_data.get("is_kev", False),
                },
            ))
            for tech_id in cve_data.get("technique_ids", []):
                edges.append(GraphEdge(
                    source_id=node_id,
                    target_id=f"technique:{tech_id}",
                    relation="maps_to",
                ))
        return AdapterResult(adapter_name=self.name, nodes=nodes, edges=edges, gaps=gaps)
