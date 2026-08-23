"""Unit tests for LocalPlaybookAdapter (casky_pipeline/adapters/local_playbook_adapter.py).

Covers:
  1. A playbook whose mitre_techniques intersects the input entities is
     matched and produces nodes/edges.
  2. A playbook with no matching techniques produces nothing.
  3. A malformed/unparseable YAML file alongside valid ones is skipped
     without raising.
  4. evidence_gaps from a matched playbook are surfaced in the result.
  5. (added) Intent-based LLM matching via an optional `provider`:
     confirming a candidate attaches match_reasoning; rejecting one drops
     it; malformed LLM JSON degrades to the technique-ID candidate pool;
     zero technique-ID candidates means the provider is never called; and
     the original 6 no-provider tests above are unaffected.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from casky_pipeline.adapters.base import AdapterConfig, AdapterEntities
from casky_pipeline.adapters.local_playbook_adapter import LocalPlaybookAdapter
from casky_pipeline.llm_providers import LLMProvider

VALID_PLAYBOOK_YAML = """\
id: test-playbook-one
name: Test Playbook One
domain: identity
mitre_techniques:
  - T1003
  - T1552
description: >
  A test playbook used only by the LocalPlaybookAdapter unit tests.
steps:
  - skill_slug: mimikatz-detection
    skill_category: identity-security
    technique_id: T1003
    technique_name: OS Credential Dumping
    rationale: Evidence references LSASS access patterns.
    evidence_focus: LSASS process handles
    step_order: 1
  - skill_slug: dpapi-sweep
    skill_category: identity-security
    technique_id: T1552
    technique_name: Unsecured Credentials
    rationale: Credentials may be stored in DPAPI blobs.
    evidence_focus: DPAPI master key access
    step_order: 2
evidence_gaps:
  - No EDR telemetry confirming LSASS access source process
  - Password rotation history unavailable
"""

NON_MATCHING_PLAYBOOK_YAML = """\
id: test-playbook-two
name: Test Playbook Two
domain: network
mitre_techniques:
  - T1021.001
description: >
  A test playbook whose techniques never intersect the entities under test.
steps:
  - skill_slug: rdp-review
    skill_category: network-security
    technique_id: T1021.001
    technique_name: Remote Desktop Protocol
    rationale: Some rationale.
    evidence_focus: RDP logon events
    step_order: 1
evidence_gaps:
  - Some unrelated gap
"""

MALFORMED_YAML = """\
id: broken
name: [unterminated list
  this is not valid yaml: : :
domain identity
mitre_techniques
  - T1003
"""


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


@pytest.mark.asyncio
async def test_matching_playbook_produces_nodes_and_edges(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path)
    entities = AdapterEntities(technique_ids=["T1003"])
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    assert result.adapter_name == "local_playbook"

    playbook_nodes = [n for n in result.nodes if n.type == "playbook"]
    step_nodes = [n for n in result.nodes if n.type == "playbook_step"]
    assert len(playbook_nodes) == 1
    assert playbook_nodes[0].id == "playbook:test-playbook-one"
    assert len(step_nodes) == 2  # both steps in the playbook are emitted once matched

    suggested_edges = [e for e in result.edges if e.relation == "suggested_by"]
    assert len(suggested_edges) == 2
    targets = {e.target_id for e in suggested_edges}
    assert "technique:T1003" in targets
    assert "technique:T1552" in targets
    sources = {e.source_id for e in suggested_edges}
    assert "playbook_step:test-playbook-one:0" in sources
    assert "playbook_step:test-playbook-one:1" in sources


@pytest.mark.asyncio
async def test_non_matching_playbook_produces_nothing(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-two.yaml", NON_MATCHING_PLAYBOOK_YAML)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path)
    entities = AdapterEntities(technique_ids=["T9999"])  # not present in any playbook
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    assert result.nodes == []
    assert result.edges == []
    assert result.gaps == []


@pytest.mark.asyncio
async def test_malformed_yaml_file_is_skipped_without_raising(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)
    _write(tmp_path / "broken.yaml", MALFORMED_YAML)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path)
    entities = AdapterEntities(technique_ids=["T1003"])

    # Must not raise despite the malformed file sitting alongside a valid one.
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    playbook_nodes = [n for n in result.nodes if n.type == "playbook"]
    assert len(playbook_nodes) == 1
    assert playbook_nodes[0].id == "playbook:test-playbook-one"


@pytest.mark.asyncio
async def test_evidence_gaps_surfaced_from_matched_playbook(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)
    _write(tmp_path / "test-playbook-two.yaml", NON_MATCHING_PLAYBOOK_YAML)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path)
    entities = AdapterEntities(technique_ids=["T1552"])
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    assert "No EDR telemetry confirming LSASS access source process" in result.gaps
    assert "Password rotation history unavailable" in result.gaps
    # Gap from the non-matching playbook must NOT be present.
    assert "Some unrelated gap" not in result.gaps


@pytest.mark.asyncio
async def test_empty_technique_ids_short_circuits(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path)
    entities = AdapterEntities(technique_ids=[])
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    assert result.nodes == []
    assert result.edges == []
    assert result.gaps == []


@pytest.mark.asyncio
async def test_missing_playbooks_dir_does_not_raise() -> None:
    adapter = LocalPlaybookAdapter(playbooks_dir=Path("/nonexistent/path/for/tests"))
    entities = AdapterEntities(technique_ids=["T1003"])

    result = await adapter.enrich(entities, AdapterConfig())

    assert result.nodes == []
    assert result.edges == []


# ── Intent-based LLM matching (optional `provider`) ──────────────────────────

SECOND_CANDIDATE_YAML = """\
id: test-playbook-three
name: Test Playbook Three
domain: identity
mitre_techniques:
  - T1003
description: >
  A second candidate playbook sharing a technique ID with test-playbook-one,
  used to exercise the intent-matching accept/reject split.
steps:
  - skill_slug: unrelated-step
    skill_category: identity-security
    technique_id: T1003
    technique_name: OS Credential Dumping
    rationale: Some rationale.
    evidence_focus: Some evidence focus.
    step_order: 1
evidence_gaps:
  - A gap specific to test-playbook-three
"""


class FakeLLMProvider(LLMProvider):
    """Records calls and returns a canned response, or raises/returns
    malformed text, per test. Never calls a real API."""

    def __init__(self, response: str | None = None, raise_exc: Exception | None = None) -> None:
        self.response = response
        self.raise_exc = raise_exc
        self.calls: list[dict] = []

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "max_tokens": max_tokens,
                "cacheable_system": cacheable_system,
            }
        )
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.response or "{}"


@pytest.mark.asyncio
async def test_llm_confirms_candidate_produces_match_reasoning(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    reasoning = "The evidence describes LSASS memory access consistent with credential dumping."
    response = json.dumps(
        {"matches": [{"playbook_id": "test-playbook-one", "match_reasoning": reasoning}]}
    )
    provider = FakeLLMProvider(response=response)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path, provider=provider)
    entities = AdapterEntities(technique_ids=["T1003"])
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    assert len(provider.calls) == 1  # candidates existed -> LLM was consulted

    playbook_nodes = [n for n in result.nodes if n.type == "playbook"]
    assert len(playbook_nodes) == 1
    assert playbook_nodes[0].id == "playbook:test-playbook-one"
    assert playbook_nodes[0].properties.get("match_reasoning") == reasoning

    # Steps for the confirmed playbook are still emitted as before.
    step_nodes = [n for n in result.nodes if n.type == "playbook_step"]
    assert len(step_nodes) == 2


@pytest.mark.asyncio
async def test_llm_rejects_candidate_drops_it_despite_technique_overlap(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)
    _write(tmp_path / "test-playbook-three.yaml", SECOND_CANDIDATE_YAML)

    # Both playbooks share T1003, so both are technique-ID candidates, but the
    # LLM only confirms test-playbook-one as a genuine intent match.
    response = json.dumps(
        {
            "matches": [
                {
                    "playbook_id": "test-playbook-one",
                    "match_reasoning": "Genuinely about credential dumping via LSASS.",
                }
            ]
        }
    )
    provider = FakeLLMProvider(response=response)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path, provider=provider)
    entities = AdapterEntities(technique_ids=["T1003"])
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    playbook_ids = {n.id for n in result.nodes if n.type == "playbook"}
    assert playbook_ids == {"playbook:test-playbook-one"}
    assert "playbook:test-playbook-three" not in playbook_ids

    # The rejected playbook's step/gap must not leak into the result either.
    step_ids = {n.id for n in result.nodes if n.type == "playbook_step"}
    assert not any(sid.startswith("playbook_step:test-playbook-three:") for sid in step_ids)
    assert "A gap specific to test-playbook-three" not in result.gaps


@pytest.mark.asyncio
async def test_malformed_llm_json_degrades_to_technique_id_candidate_pool(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    provider = FakeLLMProvider(response="this is not valid JSON at all {{{")

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path, provider=provider)
    entities = AdapterEntities(technique_ids=["T1003"])

    # Must not raise despite the provider returning garbage.
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    playbook_nodes = [n for n in result.nodes if n.type == "playbook"]
    assert len(playbook_nodes) == 1
    assert playbook_nodes[0].id == "playbook:test-playbook-one"
    # Degraded path: no LLM-sourced reasoning was attached.
    assert "match_reasoning" not in playbook_nodes[0].properties

    step_nodes = [n for n in result.nodes if n.type == "playbook_step"]
    assert len(step_nodes) == 2


@pytest.mark.asyncio
async def test_provider_raising_also_degrades_to_technique_id_candidate_pool(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    provider = FakeLLMProvider(raise_exc=RuntimeError("simulated provider failure"))

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path, provider=provider)
    entities = AdapterEntities(technique_ids=["T1003"])

    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    playbook_nodes = [n for n in result.nodes if n.type == "playbook"]
    assert len(playbook_nodes) == 1
    assert playbook_nodes[0].id == "playbook:test-playbook-one"
    assert "match_reasoning" not in playbook_nodes[0].properties


@pytest.mark.asyncio
async def test_zero_technique_id_candidates_never_calls_provider(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    provider = FakeLLMProvider(response=json.dumps({"matches": []}))

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path, provider=provider)
    entities = AdapterEntities(technique_ids=["T9999"])  # no playbook matches this technique
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    assert result.nodes == []
    assert result.edges == []
    assert result.gaps == []
    assert provider.calls == []  # short-circuited before ever consulting the LLM


@pytest.mark.asyncio
async def test_empty_technique_ids_never_calls_provider(tmp_path: Path) -> None:
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    provider = FakeLLMProvider(response=json.dumps({"matches": []}))

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path, provider=provider)
    entities = AdapterEntities(technique_ids=[])
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    assert result.nodes == []
    assert provider.calls == []


@pytest.mark.asyncio
async def test_no_provider_behavior_matches_technique_id_intersection_exactly(tmp_path: Path) -> None:
    """Sanity check that the default (provider=None) path is unchanged: same
    assertions as test_matching_playbook_produces_nodes_and_edges, just
    constructed via an explicit provider=None to document the contract."""
    _write(tmp_path / "test-playbook-one.yaml", VALID_PLAYBOOK_YAML)

    adapter = LocalPlaybookAdapter(playbooks_dir=tmp_path, provider=None)
    entities = AdapterEntities(technique_ids=["T1003"])
    result = await adapter.enrich(entities, AdapterConfig())

    assert result.error is None
    playbook_nodes = [n for n in result.nodes if n.type == "playbook"]
    assert len(playbook_nodes) == 1
    assert playbook_nodes[0].id == "playbook:test-playbook-one"
    assert "match_reasoning" not in playbook_nodes[0].properties
