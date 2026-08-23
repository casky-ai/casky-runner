"""Local playbook adapter — matches investigation entities against a library
of hand-authored YAML playbooks bundled under casky_pipeline/playbooks/.

Each playbook is a starter investigation template for a MITRE ATT&CK
technique family within a given domain (cloud, identity, web-app, ...).

Matching is two-tiered:
  1. Technique-ID intersection (always runs, free, deterministic): any
     playbook whose mitre_techniques intersects entities.technique_ids
     becomes a *candidate*. This is the entire matching strategy when no
     `provider` is configured (the default) — see PHASE1_CONTRACT.md
     Section 3.3 for the original design.
  2. Intent-based LLM matching (only when a `provider` is configured, and
     only over the candidate pool from step 1, not the full playbook set —
     this keeps prompt size bounded, mirroring the TypeScript
     PlaybookMatcherAgent's behavior of reasoning over plausible candidates
     rather than the whole library on every call). The LLM decides which
     candidates are genuine intent matches — i.e. does the evidence's actual
     narrative match what the playbook investigates, not just overlapping
     T-codes — and supplies a `match_reasoning` string per confirmed match,
     stored in that playbook's GraphNode.properties.

When a playbook matches (by either path), its steps are surfaced as
playbook_step nodes suggested_by the matching technique, and its
evidence_gaps are surfaced verbatim.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from casky_pipeline.adapters.base import (
    AdapterConfig,
    AdapterEntities,
    AdapterResult,
    ContextEngineAdapter,
    GraphEdge,
    GraphNode,
)
from casky_pipeline.llm_providers import LLMProvider

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"

# AdapterConfig.extra key the integration call site may populate with the raw
# evidence text, so the intent-matching prompt can reason about the actual
# narrative rather than just the extracted entities. enrich()'s ABC signature
# only receives AdapterEntities, not raw evidence — this is the sanctioned
# side channel (see ContextEngineAdapter.enrich in adapters/base.py, which
# must not change). Optional: if absent, the prompt simply omits evidence
# text and reasons from the entities alone.
EVIDENCE_TEXT_CONFIG_KEY = "evidence_text"


def _strip_code_fences(text: str) -> str:
    """Defensively strips a leading/trailing ``` fence — same pattern used by
    pipeline.py's stage response handling and, before it, harness.py's
    classifier response handling (harness.py:416-420)."""
    output = (text or "").strip()
    if output.startswith("```"):
        output = "\n".join(output.split("\n")[1:])
    if output.endswith("```"):
        output = "\n".join(output.split("\n")[:-1])
    return output.strip()


class LocalPlaybookAdapter(ContextEngineAdapter):
    name = "local_playbook"

    SYSTEM_PROMPT = """You are a playbook intent-matching agent inside a security investigation pipeline.

You will be given a block of raw security evidence (logs, alerts, tool output, analyst notes) and a \
list of CANDIDATE investigation playbooks. Every candidate already shares at least one MITRE ATT&CK \
technique ID with the evidence — that overlap got them onto the candidate list, but a shared T-code \
alone does not mean the playbook is actually relevant. The same technique ID can show up in evidence \
for completely different attack narratives.

Your job: for each candidate playbook, decide whether the evidence's ACTUAL NARRATIVE — what really \
appears to be happening, not just which T-codes are mentioned — genuinely matches what that playbook \
investigates. Read each playbook's name/domain/description and compare it against what the evidence \
actually shows.

CRITICAL CONSTRAINT: you may ONLY return playbook_id values that literally appear in the candidate \
list below. Never invent a playbook_id that is not present in the candidates. If a candidate's \
technique overlap is coincidental and the underlying narrative does not match, leave it out of your \
"matches" entirely — do not include a rejected candidate with a negative reasoning string, just omit it.

For every candidate you confirm as a genuine match, provide:
- playbook_id: copied verbatim from the candidate's id
- match_reasoning: one or two sentences explaining why the evidence's narrative genuinely matches \
this playbook's investigation scope (not just the T-code overlap)

Respond with ONLY a JSON object — no prose, no markdown code fences — exactly this shape:
{
  "matches": [
    {"playbook_id": "credential-dumping-investigation", "match_reasoning": "..."}
  ]
}

If none of the candidates are genuine matches, respond with {"matches": []}."""

    def __init__(
        self,
        playbooks_dir: Path | None = None,
        provider: LLMProvider | None = None,
    ) -> None:
        self.playbooks_dir = playbooks_dir or PLAYBOOKS_DIR
        self.provider = provider

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        """Load every *.yaml under self.playbooks_dir, build the technique-ID
        candidate pool, optionally narrow it via intent-based LLM matching
        when self.provider is set, and emit:
          - one GraphNode(type="playbook", id=f"playbook:{playbook.id}") per matched playbook
            (properties include "match_reasoning" when the LLM path confirmed it)
          - one GraphNode(type="playbook_step", id=f"playbook_step:{playbook.id}:{i}") per step
          - GraphEdge(relation="suggested_by", source_id=step_node_id,
            target_id=f"technique:{step.technique_id}") per step
          - gaps = the matched playbook(s)' evidence_gaps list
        Never raises (per ContextEngineAdapter.enrich contract) — a missing or
        malformed YAML file is a single skipped playbook + nothing more, and a
        failed/malformed LLM response degrades to the technique-ID candidate
        pool rather than raising.
        """
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        gaps: list[str] = []

        wanted = set(entities.technique_ids)
        if not wanted:
            return AdapterResult(adapter_name=self.name)

        try:
            yaml_paths = sorted(self.playbooks_dir.glob("*.yaml"))
        except Exception as exc:  # noqa: BLE001 — directory itself unreadable; degrade, don't raise
            return AdapterResult(adapter_name=self.name, error=f"{type(exc).__name__}: {exc}")

        candidates: list[dict[str, Any]] = []

        for path in yaml_paths:
            try:
                with path.open("r", encoding="utf-8") as f:
                    doc: Any = yaml.safe_load(f)

                if not isinstance(doc, dict):
                    # Empty file, a bare scalar/list, or otherwise not a
                    # playbook document — skip this one file, keep going.
                    continue

                playbook_id = doc["id"]
                mitre_techniques = doc.get("mitre_techniques") or []
                steps = doc.get("steps") or []
                evidence_gaps = doc.get("evidence_gaps") or []
                name = doc.get("name", playbook_id)
                domain = doc.get("domain", "")
                description = doc.get("description", "")
            except Exception:
                # Missing file, unparseable YAML, missing required "id" key,
                # or any other malformed-document condition — skip this
                # single playbook and move on to the next file.
                continue

            if not (set(mitre_techniques) & wanted):
                continue  # no matching techniques -> this playbook contributes nothing

            candidates.append(
                {
                    "id": playbook_id,
                    "name": name,
                    "domain": domain,
                    "description": description,
                    "mitre_techniques": list(mitre_techniques),
                    "steps": steps,
                    "evidence_gaps": evidence_gaps,
                }
            )

        if not candidates:
            return AdapterResult(adapter_name=self.name)

        # selected_ids is None -> no LLM narrowing happened (no provider, or
        # the LLM path degraded) -> keep the full technique-ID candidate pool.
        # selected_ids is a set() -> the LLM ran successfully and this is the
        # (possibly empty) set of playbook ids it confirmed as genuine matches.
        selected_ids: set[str] | None = None
        match_reasoning_by_id: dict[str, str] = {}

        if self.provider is not None:
            selected_ids, match_reasoning_by_id = await self._llm_match(entities, config, candidates)

        for cand in candidates:
            playbook_id = cand["id"]
            if selected_ids is not None and playbook_id not in selected_ids:
                continue  # LLM determined this candidate isn't a genuine intent match

            playbook_node_id = f"playbook:{playbook_id}"
            properties: dict[str, Any] = {
                "domain": cand["domain"],
                "mitre_techniques": cand["mitre_techniques"],
                "description": cand["description"],
            }
            if playbook_id in match_reasoning_by_id:
                properties["match_reasoning"] = match_reasoning_by_id[playbook_id]

            nodes.append(
                GraphNode(
                    id=playbook_node_id,
                    type="playbook",
                    label=cand["name"],
                    properties=properties,
                )
            )

            for i, step in enumerate(cand["steps"]):
                try:
                    if not isinstance(step, dict):
                        continue
                    technique_id = step.get("technique_id", "")
                    step_node_id = f"playbook_step:{playbook_id}:{i}"
                    nodes.append(
                        GraphNode(
                            id=step_node_id,
                            type="playbook_step",
                            label=step.get("skill_slug", step_node_id),
                            properties=dict(step),
                        )
                    )
                    edges.append(
                        GraphEdge(
                            source_id=step_node_id,
                            target_id=f"technique:{technique_id}",
                            relation="suggested_by",
                        )
                    )
                except Exception:
                    # A single malformed step should never take down the
                    # rest of an otherwise-valid playbook.
                    continue

            gaps.extend(cand["evidence_gaps"])

        return AdapterResult(adapter_name=self.name, nodes=nodes, edges=edges, gaps=gaps)

    async def _llm_match(
        self,
        entities: AdapterEntities,
        config: AdapterConfig,
        candidates: list[dict[str, Any]],
    ) -> tuple[set[str] | None, dict[str, str]]:
        """Calls self.provider to narrow `candidates` down to genuine
        intent-based matches. Returns (selected_ids, match_reasoning_by_id).

        On any failure (provider raises, response isn't valid JSON, response
        JSON doesn't have the expected shape) returns (None, {}) — the
        sentinel that tells enrich() to fall back to the full technique-ID
        candidate pool. Never raises."""
        try:
            user_prompt = self._build_user_prompt(entities, config, candidates)
            raw = await self.provider.complete(
                self.SYSTEM_PROMPT, user_prompt, cacheable_system=True
            )
            data = json.loads(_strip_code_fences(raw))
            matches = data.get("matches", [])
            if not isinstance(matches, list):
                raise ValueError("'matches' must be a list")

            candidate_ids = {c["id"] for c in candidates}
            selected_ids: set[str] = set()
            match_reasoning_by_id: dict[str, str] = {}
            for m in matches:
                if not isinstance(m, dict):
                    continue
                playbook_id = m.get("playbook_id", "")
                if playbook_id not in candidate_ids:
                    # Never trust a hallucinated/out-of-pool id.
                    continue
                selected_ids.add(playbook_id)
                match_reasoning_by_id[playbook_id] = m.get("match_reasoning", "")

            return selected_ids, match_reasoning_by_id
        except Exception:
            # Malformed JSON, provider raised, unexpected shape, etc. —
            # degrade to the technique-ID candidate pool, never raise.
            return None, {}

    @staticmethod
    def _build_user_prompt(
        entities: AdapterEntities,
        config: AdapterConfig,
        candidates: list[dict[str, Any]],
    ) -> str:
        evidence_text = ""
        if config is not None and config.extra:
            evidence_text = config.extra.get(EVIDENCE_TEXT_CONFIG_KEY, "") or ""

        candidate_lines = []
        for cand in candidates:
            candidate_lines.append(
                json.dumps(
                    {
                        "playbook_id": cand["id"],
                        "name": cand["name"],
                        "domain": cand["domain"],
                        "description": cand["description"],
                        "shared_mitre_techniques": sorted(
                            set(cand["mitre_techniques"]) & set(entities.technique_ids)
                        ),
                    }
                )
            )

        parts = []
        if evidence_text:
            parts.append(f"EVIDENCE:\n{evidence_text}")
        else:
            parts.append(
                "EVIDENCE: (raw evidence text not provided to this adapter — "
                "reason from the extracted entities below only)"
            )
        parts.append(
            "EXTRACTED ENTITIES: technique_ids="
            f"{list(entities.technique_ids)}, cve_ids={list(entities.cve_ids)}, "
            f"ips={list(entities.ips)}, hostnames={list(entities.hostnames)}"
        )
        parts.append("CANDIDATE PLAYBOOKS (one JSON object per line):\n" + "\n".join(candidate_lines))
        return "\n\n".join(parts)
