"""Unit tests for casky_pipeline.pipeline — Section 3.4 of PHASE1_CONTRACT.md.

Uses a fake in-process LLMProvider; never calls a real API. Each pipeline
stage is routed a canned JSON response keyed off a distinctive substring in
that stage's static system prompt, so tests don't depend on call order to
know which response goes where.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from casky_pipeline.llm_providers import LLMProvider
from casky_pipeline.pipeline import (
    ClassifierInput,
    ClassifierOutput,
    EvidenceGap,
    PipelineEntities,
    SkillSelector,
    StepOrderer,
    TechniqueValidator,
    run_pipeline,
)

# Distinctive substrings identifying each stage's static system prompt.
STAGE_MARKERS = {
    "validator": "MITRE ATT&CK technique validator",
    "selector": "skill-selection agent",
    "orderer": "investigation-sequencing agent",
    "gap": "evidence-gap analyst",
}


class FakeLLMProvider(LLMProvider):
    """Records every call and returns a canned response per stage, looked up
    by a marker substring inside system_prompt. Optionally sleeps inside
    complete() so overlapping calls (real concurrency) are observable via
    recorded start/end timestamps."""

    def __init__(self, responses: dict[str, str], delay: float = 0.0) -> None:
        self.responses = responses
        self.delay = delay
        self.calls: list[dict] = []

    def _stage_for(self, system_prompt: str) -> str | None:
        for stage, marker in STAGE_MARKERS.items():
            if marker in system_prompt:
                return stage
        return None

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        stage = self._stage_for(system_prompt)
        start = time.monotonic()
        record = {
            "stage": stage,
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "max_tokens": max_tokens,
            "cacheable_system": cacheable_system,
            "start": start,
        }
        self.calls.append(record)
        if self.delay:
            await asyncio.sleep(self.delay)
        record["end"] = time.monotonic()
        return self.responses.get(stage, "{}")


def _happy_responses() -> dict[str, str]:
    validator = {
        "techniques": [
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "confidence": 0.9,
                "evidence_anchors": ["lsass.exe memory dump"],
                "rationale": "LSASS access observed.",
            }
        ],
        "evidence_gaps": ["No EDR telemetry confirming source process"],
    }
    selector = {
        "selected": [
            {
                "skill_slug": "mimikatz-detection",
                "skill_category": "identity-security",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "rationale": "Directly investigates LSASS credential dumping.",
                "evidence_focus": "LSASS process handles",
                "confidence": 0.8,
                "evidence_anchors": ["lsass.exe memory dump"],
            },
            {
                "skill_slug": "sam-hive-analysis",
                "skill_category": "identity-security",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "rationale": "Checks for SAM/SECURITY hive access.",
                "evidence_focus": "Registry hive reads",
                "confidence": 0.6,
                "evidence_anchors": [],
            },
        ],
        "evidence_gaps": [],
    }
    orderer = {
        "ordered": [
            {"skill_slug": "mimikatz-detection", "step_order": 1, "depends_on": []},
            {"skill_slug": "sam-hive-analysis", "step_order": 2, "depends_on": ["mimikatz-detection"]},
        ]
    }
    gap = {"gaps": ["Confirm the process that opened the LSASS handle"]}
    return {
        "validator": json.dumps(validator),
        "selector": json.dumps(selector),
        "orderer": json.dumps(orderer),
        "gap": json.dumps(gap),
    }


def _make_input() -> ClassifierInput:
    return ClassifierInput(
        evidence_text="Process lsass.exe memory dump observed at 03:14 on HOST-01.",
        entities=PipelineEntities(technique_ids=["T1003"]),
        skill_index=[
            {"name": "mimikatz-detection", "subdomain": "identity-security", "description": "Detect mimikatz usage"},
            {"name": "sam-hive-analysis", "subdomain": "identity-security", "description": "Analyze SAM/SECURITY hives"},
        ],
    )


# ── (1) stage order / genuine parallelism ────────────────────────────────────

@pytest.mark.asyncio
async def test_run_pipeline_calls_all_four_stages_in_order_with_real_parallelism():
    provider = FakeLLMProvider(_happy_responses(), delay=0.05)
    result = await run_pipeline(_make_input(), provider)

    assert isinstance(result, ClassifierOutput)
    stages_called = [c["stage"] for c in provider.calls]
    assert stages_called == ["validator", "selector", "orderer", "gap"] or (
        # orderer/gap dispatch order into asyncio.gather is deterministic (orderer first)
        # but assert set + prefix regardless of any future reordering safety margin
        stages_called[:2] == ["validator", "selector"]
        and set(stages_called[2:]) == {"orderer", "gap"}
    )

    by_stage = {c["stage"]: c for c in provider.calls}
    # validator must fully complete before selector starts (sequential dependency)
    assert by_stage["validator"]["end"] <= by_stage["selector"]["start"]
    # selector must fully complete before either parallel stage starts
    assert by_stage["selector"]["end"] <= by_stage["orderer"]["start"]
    assert by_stage["selector"]["end"] <= by_stage["gap"]["start"]

    # orderer and gap must genuinely overlap in wall-clock time (run concurrently
    # via asyncio.gather, not sequentially) — their intervals must intersect.
    orderer_interval = (by_stage["orderer"]["start"], by_stage["orderer"]["end"])
    gap_interval = (by_stage["gap"]["start"], by_stage["gap"]["end"])
    overlap = min(orderer_interval[1], gap_interval[1]) - max(orderer_interval[0], gap_interval[0])
    assert overlap > 0, "StepOrderer and EvidenceGap did not run concurrently"


@pytest.mark.asyncio
async def test_run_pipeline_wall_clock_time_reflects_parallel_stage3():
    # 4 sequential calls at `delay` each would take ~4*delay; with stage 3
    # parallelized it should take ~3*delay (validator + selector + max(orderer, gap)).
    delay = 0.05
    provider = FakeLLMProvider(_happy_responses(), delay=delay)
    started = time.monotonic()
    await run_pipeline(_make_input(), provider)
    elapsed = time.monotonic() - started
    assert elapsed < delay * 3.5


# ── (2) final step dict key set ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_final_steps_have_exact_key_set():
    provider = FakeLLMProvider(_happy_responses())
    result = await run_pipeline(_make_input(), provider)

    expected_keys = {
        "skill_slug",
        "skill_category",
        "technique_id",
        "technique_name",
        "rationale",
        "evidence_focus",
        "step_order",
        "confidence",
        "evidence_gaps",
    }
    assert len(result.steps) == 2
    for step in result.steps:
        assert set(step.keys()) == expected_keys


# ── (3) malformed JSON from one stage doesn't crash the pipeline ────────────

@pytest.mark.asyncio
async def test_malformed_json_from_one_stage_degrades_gracefully():
    responses = _happy_responses()
    responses["orderer"] = "this is not valid json at all {{{"
    provider = FakeLLMProvider(responses)

    result = await run_pipeline(_make_input(), provider)

    assert isinstance(result, ClassifierOutput)
    # SkillSelector's output still made it through untouched.
    assert len(result.steps) == 2
    # StepOrdererOutput degraded to empty -> order_by_slug falls back to i + 1.
    step_orders = sorted(s["step_order"] for s in result.steps)
    assert step_orders == [1, 2]


@pytest.mark.asyncio
async def test_malformed_json_from_technique_validator_still_lets_pipeline_finish():
    responses = _happy_responses()
    responses["validator"] = "<<<not json>>>"
    provider = FakeLLMProvider(responses)

    result = await run_pipeline(_make_input(), provider)

    assert isinstance(result, ClassifierOutput)
    # TechniqueValidatorOutput degrades to empty, but downstream stages still ran
    # with whatever the (fake) SkillSelector produced independently.
    assert isinstance(result.steps, list)


@pytest.mark.asyncio
async def test_all_stages_malformed_returns_empty_but_valid_output():
    provider = FakeLLMProvider({
        "validator": "nope",
        "selector": "nope",
        "orderer": "nope",
        "gap": "nope",
    })

    result = await run_pipeline(_make_input(), provider)

    assert result == ClassifierOutput(steps=[], evidence_gaps=[], confidence=0.0)


# ── (4) avg_confidence computed correctly ────────────────────────────────────

@pytest.mark.asyncio
async def test_avg_confidence_is_mean_of_selected_skill_confidences():
    provider = FakeLLMProvider(_happy_responses())
    result = await run_pipeline(_make_input(), provider)

    # selector fixture confidences: 0.8 and 0.6
    assert result.confidence == pytest.approx((0.8 + 0.6) / 2)


@pytest.mark.asyncio
async def test_avg_confidence_is_zero_when_nothing_selected():
    responses = _happy_responses()
    responses["selector"] = json.dumps({"selected": [], "evidence_gaps": []})
    provider = FakeLLMProvider(responses)

    result = await run_pipeline(_make_input(), provider)

    assert result.confidence == 0.0
    assert result.steps == []


# ── (5) every stage calls provider.complete with cacheable_system=True ──────

@pytest.mark.asyncio
async def test_every_stage_calls_provider_with_cacheable_system_true():
    provider = FakeLLMProvider(_happy_responses())
    await run_pipeline(_make_input(), provider)

    assert len(provider.calls) == 4
    stages_seen = {c["stage"] for c in provider.calls}
    assert stages_seen == {"validator", "selector", "orderer", "gap"}
    for call in provider.calls:
        assert call["cacheable_system"] is True


# ── Extra: SkillSelector never lets a hallucinated slug through ─────────────

@pytest.mark.asyncio
async def test_skill_selector_drops_slugs_not_in_skill_index():
    responses = _happy_responses()
    responses["selector"] = json.dumps({
        "selected": [
            {
                "skill_slug": "totally-made-up-skill",
                "skill_category": "identity-security",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "rationale": "hallucinated",
                "evidence_focus": "n/a",
                "confidence": 0.9,
                "evidence_anchors": [],
            },
            {
                "skill_slug": "mimikatz-detection",
                "skill_category": "identity-security",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "rationale": "real skill",
                "evidence_focus": "LSASS process handles",
                "confidence": 0.7,
                "evidence_anchors": [],
            },
        ],
        "evidence_gaps": [],
    })
    provider = FakeLLMProvider(responses)
    from casky_pipeline.pipeline import TechniqueValidatorOutput

    output = await SkillSelector().run(_make_input(), TechniqueValidatorOutput(), provider)

    slugs = {s.skill_slug for s in output.selected}
    assert slugs == {"mimikatz-detection"}


# ── Extra: SkillSelector backfills blank/garbled technique_id from the ──────
# validated list it was itself given (live-caught: 3 of 5 real steps shipped
# with technique_id == "" and a technique_name that was really just the
# skill slug repeated, because the LLM's per-selection JSON silently dropped
# the fields it had already been handed in its own prompt).

@pytest.mark.asyncio
async def test_skill_selector_backfills_blank_technique_id_from_technique_name():
    from casky_pipeline.pipeline import TechniqueValidatorOutput, ValidatedTechnique

    responses = _happy_responses()
    responses["selector"] = json.dumps({
        "selected": [
            {
                "skill_slug": "mimikatz-detection",
                "skill_category": "identity-security",
                "technique_id": "",  # LLM dropped this despite it being in its own prompt
                "technique_name": "Account Manipulation",
                "rationale": "real skill",
                "evidence_focus": "LSASS process handles",
                "confidence": 0.7,
                "evidence_anchors": [],
            },
        ],
        "evidence_gaps": [],
    })
    provider = FakeLLMProvider(responses)
    validated = TechniqueValidatorOutput(
        techniques=[
            ValidatedTechnique(
                technique_id="T1098",
                technique_name="Account Manipulation",
                confidence=0.8,
            ),
        ],
    )

    output = await SkillSelector().run(_make_input(), validated, provider)

    assert len(output.selected) == 1
    assert output.selected[0].technique_id == "T1098"
    assert output.selected[0].technique_name == "Account Manipulation"


# ── Extra: bare key:value pair inside evidence_anchors gets repaired ────────
#
# Live-caught on a real CloudTrail evidence run: despite the system prompt
# explicitly instructing "escape internal quotes into one valid string" (with a
# matching example), the model sometimes instead emits an unescaped, bare
# "key": "value" pair directly as an evidence_anchors array element —
# "evidence_anchors": [ "userAgent": "aws-cli/2.13.5 ..." ] — which broke JSON
# parsing and discarded the entire TechniqueValidator response (0 techniques,
# 0 steps, 0% confidence on an otherwise perfectly good investigation).

def test_repair_evidence_anchor_bare_kv_pairs_fixes_the_live_caught_shape():
    from casky_pipeline.pipeline import _repair_evidence_anchor_bare_kv_pairs

    broken = (
        '{"techniques": [{"technique_id": "T1021.004", '
        '"evidence_anchors": ["userAgent": "aws-cli/2.13.5 Python/3.11.4"], '
        '"rationale": "test"}]}'
    )
    repaired = _repair_evidence_anchor_bare_kv_pairs(broken)
    data = json.loads(repaired)  # must not raise
    assert data["techniques"][0]["evidence_anchors"] == ["userAgent: aws-cli/2.13.5 Python/3.11.4"]


def test_repair_evidence_anchor_bare_kv_pairs_handles_multiple_pairs():
    from casky_pipeline.pipeline import _repair_evidence_anchor_bare_kv_pairs

    broken = (
        '{"evidence_anchors": ['
        '"userAgent": "aws-cli", '
        '"eventName": "StartInstances"'
        ']}'
    )
    data = json.loads(_repair_evidence_anchor_bare_kv_pairs(broken))
    assert data["evidence_anchors"] == ["userAgent: aws-cli", "eventName: StartInstances"]


def test_repair_evidence_anchor_bare_kv_pairs_leaves_correctly_escaped_anchors_alone():
    from casky_pipeline.pipeline import _repair_evidence_anchor_bare_kv_pairs

    # This is the CORRECT shape the system prompt asks for — already one valid
    # string. Must parse as-is and must not be double-mangled by the repair pass.
    already_valid = '{"evidence_anchors": ["\\"eventName\\": \\"CreateUser\\""]}'
    json.loads(already_valid)  # sanity: the fixture itself is valid JSON
    repaired = _repair_evidence_anchor_bare_kv_pairs(already_valid)
    data = json.loads(repaired)
    assert data["evidence_anchors"] == ['"eventName": "CreateUser"']


def test_repair_evidence_anchor_bare_kv_pairs_never_touches_legitimate_object_fields():
    """Critical regression guard: two consecutive string fields in a normal object
    ("technique_id": "T1003", "technique_name": "...") have the exact same
    "quoted-string colon quoted-string" shape as the bug — but they live OUTSIDE
    evidence_anchors and must be left completely untouched."""
    from casky_pipeline.pipeline import _repair_evidence_anchor_bare_kv_pairs

    doc = (
        '{"techniques": [{"technique_id": "T1003", '
        '"technique_name": "OS Credential Dumping", "confidence": 0.85, '
        '"evidence_anchors": [], "rationale": "clean"}]}'
    )
    assert _repair_evidence_anchor_bare_kv_pairs(doc) == doc


@pytest.mark.asyncio
async def test_technique_validator_recovers_from_bare_kv_pair_via_full_run():
    """End-to-end through TechniqueValidator.run() itself, using the exact raw
    (fenced, malformed) shape observed in the wild — proves the repair is actually
    wired into the stage's parse path, not just unit-testable in isolation."""
    raw = (
        "```json\n"
        "{\n"
        '  "techniques": [\n'
        "    {\n"
        '      "technique_id": "T1021.004",\n'
        '      "technique_name": "Remote Services: SSH",\n'
        '      "confidence": 0.25,\n'
        '      "evidence_anchors": [\n'
        '        "userAgent": "aws-cli/2.13.5 Python/3.11.4"\n'
        "      ],\n"
        '      "rationale": "CLI usage suggests direct API access"\n'
        "    }\n"
        "  ],\n"
        '  "evidence_gaps": []\n'
        "}\n"
        "```"
    )
    provider = FakeLLMProvider({"validator": raw})

    output = await TechniqueValidator().run(_make_input(), provider)

    assert len(output.techniques) == 1
    assert output.techniques[0].technique_id == "T1021.004"
    assert output.techniques[0].evidence_anchors == ["userAgent: aws-cli/2.13.5 Python/3.11.4"]


# ── Extra: recovers from trailing "Extra data" after otherwise-valid JSON ───
#
# Live-caught on a real run: the model appended trailing content (in this case
# duplicated/extra text) after a complete, valid JSON object — a plain
# json.loads() rejects the *entire* response with "Extra data: line N column 1"
# even though the JSON value itself parses fine on its own. This is a different
# failure mode from the bare-kv-pair one above (that's malformed JSON *inside*
# the object; this is well-formed JSON with garbage *after* it) and needed its
# own recovery path (json.JSONDecoder().raw_decode()).

def test_parse_json_response_recovers_from_trailing_extra_data():
    from casky_pipeline.pipeline import _parse_json_response

    raw = '```json\n{"techniques": [{"technique_id": "T1531"}]}\nSome trailing model commentary.\n```'
    data = _parse_json_response(raw)
    assert data == {"techniques": [{"technique_id": "T1531"}]}


@pytest.mark.asyncio
async def test_technique_validator_recovers_from_trailing_extra_data_via_full_run():
    raw = (
        "```json\n"
        '{"techniques": [{"technique_id": "T1531", "technique_name": "Account Access Removal", '
        '"confidence": 0.45, "evidence_anchors": ["eventName: StopInstances"], "rationale": "r"}], '
        '"evidence_gaps": []}\n'
        "Here is some additional trailing commentary the model was not asked for.\n"
        "```"
    )
    provider = FakeLLMProvider({"validator": raw})

    output = await TechniqueValidator().run(_make_input(), provider)

    assert len(output.techniques) == 1
    assert output.techniques[0].technique_id == "T1531"


def test_parse_json_response_still_raises_on_genuinely_truncated_json():
    """Guard against raw_decode() silently masking a real truncation bug (e.g. a
    max_tokens cutoff mid-object) — it must only recover *trailing garbage after*
    a complete value, never accept an incomplete one."""
    from casky_pipeline.pipeline import _parse_json_response

    raw = '{"techniques": [{"technique_id": "T10'  # cut off mid-string, no valid prefix at all
    with pytest.raises(json.JSONDecodeError):
        _parse_json_response(raw)


@pytest.mark.asyncio
async def test_skill_selector_backfills_blank_technique_name_from_technique_id():
    from casky_pipeline.pipeline import TechniqueValidatorOutput, ValidatedTechnique

    responses = _happy_responses()
    responses["selector"] = json.dumps({
        "selected": [
            {
                "skill_slug": "mimikatz-detection",
                "skill_category": "identity-security",
                "technique_id": "T1098",
                "technique_name": "",
                "rationale": "real skill",
                "evidence_focus": "LSASS process handles",
                "confidence": 0.7,
                "evidence_anchors": [],
            },
        ],
        "evidence_gaps": [],
    })
    provider = FakeLLMProvider(responses)
    validated = TechniqueValidatorOutput(
        techniques=[
            ValidatedTechnique(technique_id="T1098", technique_name="Account Manipulation", confidence=0.8),
        ],
    )

    output = await SkillSelector().run(_make_input(), validated, provider)

    assert output.selected[0].technique_name == "Account Manipulation"


@pytest.mark.asyncio
async def test_skill_selector_leaves_both_blank_when_unresolvable(capsys):
    from casky_pipeline.pipeline import TechniqueValidatorOutput

    responses = _happy_responses()
    responses["selector"] = json.dumps({
        "selected": [
            {
                "skill_slug": "mimikatz-detection",
                "skill_category": "identity-security",
                "technique_id": "",
                "technique_name": "",
                "rationale": "real skill",
                "evidence_focus": "LSASS process handles",
                "confidence": 0.7,
                "evidence_anchors": [],
            },
        ],
        "evidence_gaps": [],
    })
    provider = FakeLLMProvider(responses)

    output = await SkillSelector().run(_make_input(), TechniqueValidatorOutput(), provider)

    assert output.selected[0].technique_id == ""
    assert output.selected[0].technique_name == ""
    assert "couldn't be backfilled" in capsys.readouterr().err


# ── MITRE-technique pre-filter for SkillSelector ─────────────────────────────
#
# SkillSelector used to send every skill in the index — name/subdomain/description,
# uncapped, uncached — into the LLM prompt on every investigation (~817 skills in the
# real registry, an estimated 16k-27k tokens). LocalPlaybookAdapter already solves
# this for its own 12 playbooks (a technique-ID-overlap candidate pool computed
# before any LLM call); these tests cover porting that same pattern to the much
# larger skill index via _narrow_skill_index_by_technique_overlap.

def _make_skill_entry(name: str, mitre_attack=None, subdomain: str = "identity-security", description: str = "A test skill.") -> dict:
    entry = {"name": name, "subdomain": subdomain, "description": description}
    if mitre_attack is not None:
        entry["mitre_attack"] = mitre_attack
    return entry


class TestNarrowSkillIndexByTechniqueOverlap:
    def test_empty_validated_techniques_falls_back_to_full_index(self):
        from casky_pipeline.pipeline import _narrow_skill_index_by_technique_overlap

        index = [_make_skill_entry("a", ["T1003"])]
        pool, reason = _narrow_skill_index_by_technique_overlap(index, set())

        assert pool is index
        assert reason is not None and "0 validated" in reason

    def test_overlap_below_threshold_falls_back_and_reports_count(self):
        from casky_pipeline.pipeline import _narrow_skill_index_by_technique_overlap

        index = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(5)]
        pool, reason = _narrow_skill_index_by_technique_overlap(index, {"T1003"}, min_candidates=15)

        assert pool is index
        assert reason is not None
        assert "5" in reason and "15" in reason

    def test_overlap_at_or_above_threshold_returns_narrowed_pool(self):
        from casky_pipeline.pipeline import _narrow_skill_index_by_technique_overlap

        matching = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(20)]
        non_matching = [_make_skill_entry(f"other-{i}", ["T9999"]) for i in range(20)]
        pool, reason = _narrow_skill_index_by_technique_overlap(
            matching + non_matching, {"T1003"}, min_candidates=15
        )

        assert reason is None
        assert {e["name"] for e in pool} == {e["name"] for e in matching}

    def test_missing_mitre_attack_field_treated_as_no_overlap_not_a_crash(self):
        from casky_pipeline.pipeline import _narrow_skill_index_by_technique_overlap

        matching = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(20)]
        no_field = [_make_skill_entry(f"unknown-{i}") for i in range(5)]  # no mitre_attack key at all
        pool, reason = _narrow_skill_index_by_technique_overlap(
            matching + no_field, {"T1003"}, min_candidates=15
        )

        assert reason is None
        assert all(e["name"].startswith("match-") for e in pool)

    def test_malformed_mitre_attack_treated_as_no_overlap_not_a_crash(self):
        from casky_pipeline.pipeline import _narrow_skill_index_by_technique_overlap

        matching = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(20)]
        malformed = [
            _make_skill_entry("string-field", "T1003"),   # str, not list
            _make_skill_entry("none-field", None),
        ]
        malformed[1].pop("mitre_attack", None)  # ensure genuinely absent, not literal None key
        pool, reason = _narrow_skill_index_by_technique_overlap(
            matching + malformed, {"T1003"}, min_candidates=15
        )

        assert reason is None
        assert all(e["name"].startswith("match-") for e in pool)

    def test_does_not_mutate_input_list_or_entries(self):
        from casky_pipeline.pipeline import _narrow_skill_index_by_technique_overlap

        index = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(20)]
        original = [dict(e) for e in index]

        _narrow_skill_index_by_technique_overlap(index, {"T1003"}, min_candidates=15)

        assert index == original

    def test_union_semantics_across_multiple_validated_techniques(self):
        from casky_pipeline.pipeline import _narrow_skill_index_by_technique_overlap

        only_a = [_make_skill_entry(f"a-{i}", ["T1003"]) for i in range(10)]
        only_b = [_make_skill_entry(f"b-{i}", ["T1078.004"]) for i in range(10)]
        pool, reason = _narrow_skill_index_by_technique_overlap(
            only_a + only_b, {"T1003", "T1078.004"}, min_candidates=15
        )

        assert reason is None
        assert {e["name"] for e in pool} == {e["name"] for e in only_a + only_b}


class TestFormatSkillIndexLine:
    def test_includes_mitre_tag_when_present(self):
        from casky_pipeline.pipeline import _format_skill_index_line

        line = _format_skill_index_line(_make_skill_entry("mimikatz-detection", ["T1003", "T1078.004"]))
        assert "[MITRE: T1003, T1078.004]" in line

    def test_omits_mitre_tag_when_absent_matches_original_format(self):
        from casky_pipeline.pipeline import _format_skill_index_line

        entry = {"name": "mimikatz-detection", "subdomain": "identity-security", "description": "Detect mimikatz usage"}
        line = _format_skill_index_line(entry)

        assert line == "mimikatz-detection (identity-security) — Detect mimikatz usage"
        assert "MITRE" not in line


# ── Integration: the narrowing actually reaches SkillSelector's real prompt ──

@pytest.mark.asyncio
async def test_skill_selector_prompt_excludes_non_overlapping_skills_when_pool_large_enough():
    from casky_pipeline.pipeline import TechniqueValidatorOutput, ValidatedTechnique

    matching = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(20)]
    non_matching = [_make_skill_entry(f"unrelated-{i}", ["T9999"]) for i in range(20)]
    input_ = ClassifierInput(
        evidence_text="lsass.exe memory dump observed",
        entities=PipelineEntities(),
        skill_index=matching + non_matching,
    )
    validated = TechniqueValidatorOutput(
        techniques=[ValidatedTechnique(technique_id="T1003", technique_name="OS Credential Dumping", confidence=0.9)],
    )
    responses = _happy_responses()
    responses["selector"] = json.dumps({"selected": [], "evidence_gaps": []})
    provider = FakeLLMProvider(responses)

    await SkillSelector().run(input_, validated, provider)

    prompt = next(c["user_prompt"] for c in provider.calls if c["stage"] == "selector")
    assert "match-0" in prompt
    assert "unrelated-0" not in prompt


@pytest.mark.asyncio
async def test_skill_selector_full_index_and_logs_fallback_when_no_validated_techniques(capsys):
    from casky_pipeline.pipeline import TechniqueValidatorOutput

    index = [_make_skill_entry(f"skill-{i}", ["T1003"]) for i in range(20)]
    input_ = ClassifierInput(evidence_text="e", entities=PipelineEntities(), skill_index=index)
    responses = _happy_responses()
    responses["selector"] = json.dumps({"selected": [], "evidence_gaps": []})
    provider = FakeLLMProvider(responses)

    await SkillSelector().run(input_, TechniqueValidatorOutput(), provider)

    prompt = next(c["user_prompt"] for c in provider.calls if c["stage"] == "selector")
    assert all(f"skill-{i}" in prompt for i in range(20))
    assert "0 validated" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_skill_selector_full_index_and_logs_fallback_when_overlap_below_threshold(capsys):
    from casky_pipeline.pipeline import TechniqueValidatorOutput, ValidatedTechnique

    matching = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(3)]  # below the 15 default
    non_matching = [_make_skill_entry(f"other-{i}", ["T9999"]) for i in range(20)]
    input_ = ClassifierInput(evidence_text="e", entities=PipelineEntities(), skill_index=matching + non_matching)
    validated = TechniqueValidatorOutput(
        techniques=[ValidatedTechnique(technique_id="T1003", technique_name="OS Credential Dumping", confidence=0.9)],
    )
    responses = _happy_responses()
    responses["selector"] = json.dumps({"selected": [], "evidence_gaps": []})
    provider = FakeLLMProvider(responses)

    await SkillSelector().run(input_, validated, provider)

    prompt = next(c["user_prompt"] for c in provider.calls if c["stage"] == "selector")
    assert "other-0" in prompt  # fell back to full index
    stderr = capsys.readouterr().err
    assert "3" in stderr


@pytest.mark.asyncio
async def test_hallucination_guard_validates_against_full_index_not_narrowed_pool():
    """A real slug that exists in skill_index but fell outside the narrowed pool
    (because its mitre_attack didn't overlap this investigation's validated
    techniques) must still be ACCEPTED if the model selects it — it's a false
    negative of the pre-filter, not a hallucination. Rejecting it would be strictly
    worse than the pre-change baseline."""
    from casky_pipeline.pipeline import TechniqueValidatorOutput, ValidatedTechnique

    matching = [_make_skill_entry(f"match-{i}", ["T1003"]) for i in range(20)]
    outside_pool = _make_skill_entry("real-but-outside-pool", ["T9999"])  # real slug, no T1003 overlap
    input_ = ClassifierInput(
        evidence_text="e", entities=PipelineEntities(), skill_index=matching + [outside_pool]
    )
    validated = TechniqueValidatorOutput(
        techniques=[ValidatedTechnique(technique_id="T1003", technique_name="OS Credential Dumping", confidence=0.9)],
    )
    responses = _happy_responses()
    responses["selector"] = json.dumps({
        "selected": [{
            "skill_slug": "real-but-outside-pool",
            "skill_category": "identity-security",
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "rationale": "r", "evidence_focus": "e", "confidence": 0.5, "evidence_anchors": [],
        }],
        "evidence_gaps": [],
    })
    provider = FakeLLMProvider(responses)

    output = await SkillSelector().run(input_, validated, provider)

    assert [s.skill_slug for s in output.selected] == ["real-but-outside-pool"]


@pytest.mark.asyncio
async def test_existing_two_entry_fixture_still_sends_full_index_via_fallback():
    """Explicit regression guard: _make_input()'s 2-entry index (no mitre_attack
    field at all) must always trigger the size-floor fallback and keep sending the
    full index, matching pre-change behavior byte-for-byte in intent."""
    from casky_pipeline.pipeline import TechniqueValidatorOutput

    provider = FakeLLMProvider(_happy_responses())

    await SkillSelector().run(_make_input(), TechniqueValidatorOutput(), provider)

    prompt = next(c["user_prompt"] for c in provider.calls if c["stage"] == "selector")
    assert "mimikatz-detection" in prompt
    assert "sam-hive-analysis" in prompt


@pytest.mark.asyncio
async def test_prefilter_reduces_prompt_length_substantially_on_realistic_sized_index():
    """Concrete, executable proof of the token-reduction claim — not just an
    estimate. Guards against a future accidental revert to input.skill_index in
    _build_user_prompt."""
    from casky_pipeline.pipeline import TechniqueValidatorOutput, ValidatedTechnique, _format_skill_index_line

    matching = [_make_skill_entry(f"match-{i}", ["T1003"], description="A" * 100) for i in range(40)]
    non_matching = [_make_skill_entry(f"other-{i}", ["T9999"], description="B" * 100) for i in range(760)]
    full_index = matching + non_matching
    validated = TechniqueValidatorOutput(
        techniques=[ValidatedTechnique(technique_id="T1003", technique_name="OS Credential Dumping", confidence=0.9)],
    )

    before_len = len("\n".join(_format_skill_index_line(e) for e in full_index))

    input_ = ClassifierInput(evidence_text="e", entities=PipelineEntities(), skill_index=full_index)
    responses = _happy_responses()
    responses["selector"] = json.dumps({"selected": [], "evidence_gaps": []})
    provider = FakeLLMProvider(responses)
    await SkillSelector().run(input_, validated, provider)
    after_prompt = next(c["user_prompt"] for c in provider.calls if c["stage"] == "selector")
    # after_prompt also contains the VALIDATED TECHNIQUES section; isolate the skill lines
    after_len = len(after_prompt.split("AVAILABLE SKILLS")[1])

    assert after_len < before_len * 0.2


# ── Stage classes are independently exercisable (not just via run_pipeline) ─

@pytest.mark.asyncio
async def test_technique_validator_parses_happy_path():
    provider = FakeLLMProvider(_happy_responses())
    out = await TechniqueValidator().run(_make_input(), provider)
    assert len(out.techniques) == 1
    assert out.techniques[0].technique_id == "T1003"
    assert out.techniques[0].evidence_anchors == ["lsass.exe memory dump"]


@pytest.mark.asyncio
async def test_step_orderer_parses_happy_path():
    provider = FakeLLMProvider(_happy_responses())
    selector_out = json.loads(_happy_responses()["selector"])
    from casky_pipeline.pipeline import SelectedSkill, SkillSelectorOutput

    selected = SkillSelectorOutput(
        selected=[
            SelectedSkill(
                skill_slug=s["skill_slug"],
                skill_category=s["skill_category"],
                technique_id=s["technique_id"],
                technique_name=s["technique_name"],
                rationale=s["rationale"],
                evidence_focus=s["evidence_focus"],
                confidence=s["confidence"],
            )
            for s in selector_out["selected"]
        ]
    )
    out = await StepOrderer().run(selected, provider)
    assert [o.skill_slug for o in out.ordered] == ["mimikatz-detection", "sam-hive-analysis"]
    assert out.ordered[1].depends_on == ["mimikatz-detection"]


@pytest.mark.asyncio
async def test_evidence_gap_parses_happy_path():
    provider = FakeLLMProvider(_happy_responses())
    from casky_pipeline.pipeline import SkillSelectorOutput

    out = await EvidenceGap().run(_make_input(), SkillSelectorOutput(), provider)
    assert out.gaps == ["Confirm the process that opened the LSASS handle"]
