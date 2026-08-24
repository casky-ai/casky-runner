"""4-stage classifier pipeline: TechniqueValidator -> SkillSelector ->
(StepOrderer parallel with EvidenceGap). Stub/mock the LLM calls against the
LLMProvider interface from casky_pipeline.llm_providers (Section 4) — do NOT
wire this into harness.py yet (that is the integration agent's job, Section 6)."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Callable

from casky_pipeline.adapters.base import GraphEdge, GraphNode
from casky_pipeline.llm_providers import LLMProvider

ProgressFn = Callable[[str], None]


def _log_stage_failure(stage: str, exc: Exception, raw: str) -> None:
    """Every stage's except-block routes here instead of failing silently.
    A degraded stage (empty output, pipeline continues) is a legitimate
    outcome — but it must never be an invisible one. Printed unconditionally
    (not gated behind on_progress) because this is an error signal, not a
    progress update."""
    preview = (raw or "").strip().replace("\n", " ")[:200]
    print(
        f"[casky_pipeline:pipeline] {stage} degraded to empty output — "
        f"{type(exc).__name__}: {exc} | raw_response_preview: {preview!r}",
        file=sys.stderr,
    )


# ── JSON parsing helper ──────────────────────────────────────────────────────

def _strip_code_fences(text: str) -> str:
    """Defensively strips a leading/trailing ``` fence, same pattern used by
    harness.py's classifier response handling (harness.py:416-420)."""
    output = (text or "").strip()
    if output.startswith("```"):
        output = "\n".join(output.split("\n")[1:])
    if output.endswith("```"):
        output = "\n".join(output.split("\n")[:-1])
    return output.strip()


# A pair of double-quoted strings joined by a raw ':' — the shape of a bare, never-
# escaped JSON key:value pair sitting where a single string array element belongs.
# The character class treats `\\.` (any backslash-escaped char) as one unit so a
# *correctly* escaped anchor like "\"eventName\": \"CreateUser\"" is matched as ONE
# string (no trailing `: "..."` left to match) and never touched.
_BARE_KV_PAIR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)"')


def _repair_evidence_anchor_bare_kv_pairs(text: str) -> str:
    """Best-effort repair for a recurring, live-caught LLM failure mode: instead of
    escaping a quote-containing evidence_anchor into one valid string (as the system
    prompt explicitly instructs, with a matching example), the model sometimes emits
    it as a bare, unescaped "key": "value" pair directly inside the evidence_anchors
    array — e.g. "evidence_anchors": [ "userAgent": "aws-cli/2.13.5 ..." ] — which
    breaks JSON parsing and previously discarded the entire stage response.

    Scoped deliberately narrow: only rewrites text *inside* an "evidence_anchors": [
    ... ] array body (found via a bracket-depth scan, not a flat regex), never
    touching the rest of the document. This matters because the exact same
    "quoted-string colon quoted-string" shape is also completely legitimate JSON
    elsewhere — e.g. two consecutive object fields like
    "technique_id": "T1003", "technique_name": "OS Credential Dumping" — and a
    context-blind regex would have mangled those instead of just the actual bug.
    """
    key_re = re.compile(r'"evidence_anchors"\s*:\s*\[')
    out: list[str] = []
    pos = 0
    for m in key_re.finditer(text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                i += 1
                while i < len(text) and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
                i += 1
                continue
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
            i += 1
        end = i - 1  # index of the closing ']'
        if end < start:
            continue  # unbalanced brackets — leave this span alone, let json.loads report it

        def _collapse(mm: "re.Match[str]") -> str:
            combined = f"{mm.group(1)}: {mm.group(2)}"
            escaped = combined.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'

        out.append(text[pos:start])
        out.append(_BARE_KV_PAIR_RE.sub(_collapse, text[start:end]))
        pos = end

    out.append(text[pos:])
    return "".join(out)


def _salvage_truncated_json(text: str) -> dict | None:
    """Best-effort recovery for a response that was cut off mid-JSON — hit
    max_tokens partway through writing an array element (live-caught: SkillSelector
    truncating mid-"technique_name" string on its 3rd/4th selection) — the shape
    neither of _parse_json_response's other two repairs address, since there's no
    malformed-but-complete JSON to fix here, just a document that stops partway
    through. Without this, one incomplete trailing element wiped out every
    complete selection that came before it, turning "3 validated techniques"
    into "0 investigation steps."

    Walks the text tracking bracket/brace/string state (backslash-escape aware)
    and remembers the last position where a nested structure ({ or [) just
    closed while something is still open above it — i.e. the last point a
    complete array element finished — along with what was still open *at that
    point* (not the final, more-deeply-nested stack once the incomplete
    trailing element started opening its own brackets). Truncates there and
    closes whatever was open at that point. Returns None (never raises) if no
    such point exists — e.g. the very first element never completed, or the
    text wasn't JSON at all — leaving the caller to raise the *original*
    JSONDecodeError instead of masking a genuinely broken response as an
    empty-but-valid one.

    Deliberately drops the trailing, incomplete element rather than trying to
    complete it — completing a half-written string/rationale would be
    fabricating model output, not recovering it."""
    stack: list[str] = []
    in_string = False
    escape = False
    last_safe = -1
    last_safe_stack: list[str] = []
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch in "{[":
            stack.append(ch)
            continue
        if ch in "}]":
            if not stack:
                return None  # malformed from the start — not a truncation
            stack.pop()
            if stack:
                last_safe = i + 1
                last_safe_stack = list(stack)
    if last_safe <= 0 or not stack:
        return None  # nothing complete to salvage, or text wasn't truncated
    closing = "".join("}" if c == "{" else "]" for c in reversed(last_safe_stack))
    try:
        return json.loads(text[:last_safe] + closing)
    except json.JSONDecodeError:
        return None


def _parse_json_response(raw: str) -> dict:
    """Shared parse path for every pipeline stage's raw LLM response. Strips code
    fences, then — only on a first parse failure — tries three independent
    recoveries before giving up: the bare-kv-pair repair (see
    _repair_evidence_anchor_bare_kv_pairs), json.JSONDecoder().raw_decode(), which
    recovers from a *different*, separately live-caught failure mode (the model
    appending trailing content after an otherwise complete, valid JSON object — a
    plain json.loads() rejects the whole response as "Extra data" even though the
    actual JSON value is perfectly fine; raw_decode() parses only the first
    complete value and ignores what follows), and _salvage_truncated_json, for a
    response cut off mid-element (a max_tokens cutoff) — see that function's
    docstring. Re-raises the *original* JSONDecodeError, not a recovery attempt's,
    if all fail, so callers' error logging still reflects the model's real raw
    output."""
    stripped = _strip_code_fences(raw)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        repaired = _repair_evidence_anchor_bare_kv_pairs(stripped)
        for candidate in (repaired, stripped):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass
            try:
                obj, _ = json.JSONDecoder().raw_decode(candidate)
                return obj
            except json.JSONDecodeError:
                pass
        salvaged = _salvage_truncated_json(stripped)
        if salvaged is not None:
            return salvaged
        raise exc from None


# ── Pipeline input ──────────────────────────────────────────────────────────

@dataclass
class PipelineEntities:
    """Same shape as casky_pipeline.adapters.base.AdapterEntities — duplicated
    here (not imported) so pipeline.py has no import-order dependency on
    adapters/. The integration agent passes the same values into both."""
    cve_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)


@dataclass
class ClassifierInput:
    evidence_text: str
    entities: PipelineEntities
    context_nodes: list[GraphNode] = field(default_factory=list)   # from run_adapters()
    context_edges: list[GraphEdge] = field(default_factory=list)   # from run_adapters()
    context_gaps: list[str] = field(default_factory=list)          # from run_adapters()
    skill_index: list[dict] = field(default_factory=list)          # LocalSkillsLibrary.load_index() (harness.py:225-234)


# ── Stage 1: TechniqueValidator ──────────────────────────────────────────────

@dataclass
class ValidatedTechnique:
    technique_id: str
    technique_name: str
    confidence: float
    evidence_anchors: list[str] = field(default_factory=list)   # verbatim substrings of evidence_text
    rationale: str = ""


@dataclass
class TechniqueValidatorOutput:
    techniques: list[ValidatedTechnique] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)


class TechniqueValidator:
    SYSTEM_PROMPT = """You are a MITRE ATT&CK technique validator inside a security investigation pipeline.

You will be given a block of raw security evidence (logs, alerts, tool output, analyst notes) and a \
list of MITRE ATT&CK technique IDs that a regex pass extracted from that evidence as *candidates* \
(they may include false positives — a technique ID mentioned in an unrelated context — and may be \
missing techniques the evidence clearly implies but never names by ID).

Your job:
1. For each candidate technique, decide whether the evidence text actually supports it. Keep only \
techniques the evidence genuinely substantiates; drop speculative or unsupported ones.
2. You may add techniques that are strongly implied by the evidence even if their ID was not in the \
candidate list, as long as you are confident.
3. For every technique you keep, extract "evidence_anchors": one or more VERBATIM substrings copied \
exactly, character-for-character, from the evidence text that justify the technique. Do not \
paraphrase or summarize — an anchor must be findable with a plain-text search inside the evidence.
4. Assign a "confidence" score between 0.0 and 1.0 reflecting how strongly the evidence supports the \
technique.
5. List "evidence_gaps": information that, if present in the evidence, would let you validate \
techniques with higher confidence.

CRITICAL — evidence_anchors and JSON validity: the evidence you're given is very often itself JSON \
(CloudTrail, GuardDuty, and most cloud/SIEM log formats are). When a verbatim anchor you copy \
contains a `"` character — e.g. copying the fragment `"eventName": "CreateUser"` out of a CloudTrail \
record — you MUST backslash-escape every `"` inside that anchor string so your OWN output stays \
valid JSON: write it as "\\"eventName\\": \\"CreateUser\\"", never as an unescaped "eventName": \
"CreateUser" sitting directly inside the array (that breaks JSON parsing and discards the entire \
response). If you are not fully confident you can escape a quote-containing anchor correctly, prefer \
a shorter anchor substring that avoids the quote character entirely rather than risk invalid JSON. \
Simplest safe option: drop the quote marks from the anchor text itself — write the anchor as \
eventName: CreateUser (no internal quotes to escape at all) rather than "eventName": "CreateUser". \
The anchor does not need to reproduce punctuation exactly, only the substantive content, findable in \
the evidence with a quote-insensitive search.

Respond with ONLY a JSON object — no prose, no markdown code fences — exactly this shape:
{
  "techniques": [
    {
      "technique_id": "T1003",
      "technique_name": "OS Credential Dumping",
      "confidence": 0.85,
      "evidence_anchors": [
        "exact substring copied from the evidence, no quotes to worry about",
        "\\"eventName\\": \\"CreateUser\\""
      ],
      "rationale": "one or two sentences on why the evidence supports this technique"
    }
  ],
  "evidence_gaps": ["specific missing evidence that would raise confidence"]
}"""

    async def run(self, input: ClassifierInput, provider: LLMProvider) -> TechniqueValidatorOutput:
        user_prompt = self._build_user_prompt(input)
        # Up to 8 techniques, each with multiple evidence_anchors + rationale — the
        # 2048 default can truncate mid-JSON on richer evidence; 3072 gives headroom.
        raw = await provider.complete(self.SYSTEM_PROMPT, user_prompt, max_tokens=3072, cacheable_system=True)
        try:
            data = _parse_json_response(raw)
            techniques = [
                ValidatedTechnique(
                    technique_id=t.get("technique_id", ""),
                    technique_name=t.get("technique_name", ""),
                    confidence=float(t.get("confidence", 0.0) or 0.0),
                    evidence_anchors=list(t.get("evidence_anchors", []) or []),
                    rationale=t.get("rationale", ""),
                )
                for t in (data.get("techniques", []) or [])
            ]
            evidence_gaps = list(data.get("evidence_gaps", []) or [])
            return TechniqueValidatorOutput(techniques=techniques, evidence_gaps=evidence_gaps)
        except Exception as exc:
            # A malformed/unparsable LLM response degrades this stage to an
            # empty result rather than crashing the whole pipeline — but that
            # degradation is always logged, never silent (see _log_stage_failure).
            _log_stage_failure("TechniqueValidator", exc, raw)
            return TechniqueValidatorOutput()

    @staticmethod
    def _build_user_prompt(input: ClassifierInput) -> str:
        candidate_ids = ", ".join(input.entities.technique_ids) or "(none extracted)"
        return (
            f"EVIDENCE:\n{input.evidence_text}\n\n"
            f"CANDIDATE TECHNIQUE IDS (regex-extracted, may be noisy/incomplete): {candidate_ids}"
        )


# ── Stage 2: SkillSelector ───────────────────────────────────────────────────

@dataclass
class SelectedSkill:
    skill_slug: str
    skill_category: str          # raw subdomain string — SUBDOMAIN_TO_CATEGORY mapping happens at
                                  # the harness.py integration call site (Section 6, item 7), NOT here
    technique_id: str
    technique_name: str
    rationale: str
    evidence_focus: str
    confidence: float
    evidence_anchors: list[str] = field(default_factory=list)


@dataclass
class SkillSelectorOutput:
    selected: list[SelectedSkill] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)


# Skills currently number in the hundreds (~817 in the real upstream registry), and
# SkillSelector used to send every single one — name/subdomain/description, uncapped,
# uncached — into the LLM prompt on every investigation (an estimated 16k-27k tokens).
# LocalPlaybookAdapter already solves exactly this for its own 12 playbooks (a
# technique-ID-overlap candidate pool computed before any LLM call, mirroring the
# upstream skills registry's own "frontmatter scan before full load" design) — this
# ports that same pattern to the much larger skill index. `mitre_attack` is already
# backfilled onto every index entry by scripts/enrich_skills_index.py; this makes
# that previously-fetched-but-unused field load-bearing.
DEFAULT_MIN_SKILL_CANDIDATE_POOL = 15


def _narrow_skill_index_by_technique_overlap(
    skill_index: list[dict],
    validated_technique_ids: set[str],
    min_candidates: int = DEFAULT_MIN_SKILL_CANDIDATE_POOL,
) -> tuple[list[dict], str | None]:
    """Narrows skill_index to entries whose 'mitre_attack' list shares at least one ID
    with validated_technique_ids (union overlap across all validated techniques, not
    per-technique intersection — mirrors LocalPlaybookAdapter's set(...) & wanted).

    Returns (candidate_pool, fallback_reason):
      - fallback_reason is None  -> narrowing succeeded; candidate_pool is a NEW list
        (skill_index itself is never mutated).
      - fallback_reason is a str -> narrowing was unsafe; candidate_pool is
        skill_index UNCHANGED (today's "send everything" baseline), and the string
        explains why, for the caller to log. Must never silently under-select
        relative to that baseline.

    Never raises: a missing/malformed 'mitre_attack' field on any entry (absent key,
    None, wrong type) is treated as "no techniques" for that entry, not an error.
    """
    if not validated_technique_ids:
        return skill_index, (
            "no validated technique IDs to filter by (0 validated techniques) "
            "— using full skill index"
        )

    candidates = [
        entry
        for entry in skill_index
        if isinstance(entry.get("mitre_attack"), list)
        and set(entry["mitre_attack"]) & validated_technique_ids
    ]

    if len(candidates) < min_candidates:
        return skill_index, (
            f"only {len(candidates)} skill(s) matched by MITRE technique-ID overlap "
            f"against {sorted(validated_technique_ids)} (min {min_candidates} "
            f"required) — using full skill index"
        )

    return candidates, None


def _format_skill_index_line(entry: dict) -> str:
    """Same 'name (subdomain) — description' shape as before, plus the skill's own
    MITRE technique IDs when present — cheap to include once the candidate pool is
    already bounded, and gives the LLM the same frontmatter-scan signal (tags/
    technique coverage) the upstream registry's own agent-loading pattern uses."""
    name = entry.get("name", "")
    subdomain = entry.get("subdomain", "")
    description = entry.get("description", "")
    mitre = entry.get("mitre_attack")
    tag = f" [MITRE: {', '.join(mitre)}]" if isinstance(mitre, list) and mitre else ""
    return f"{name} ({subdomain}){tag} — {description}"


class SkillSelector:
    SYSTEM_PROMPT = """You are a skill-selection agent inside a security investigation pipeline.

You will be given a list of MITRE ATT&CK techniques that have already been validated against the \
evidence, plus a "skill index" — the full catalog of investigation skills currently available to run. \
Each skill index entry has a "slug" (its unique identifier), a "subdomain" (a category string), and a \
"description".

Your job: for each validated technique, select the investigation skill(s) from the given skill index \
that are the best next step for investigating it further.

CRITICAL CONSTRAINT: you may ONLY select skill_slug values that literally appear in the provided skill \
index. Never invent, guess, or hallucinate a skill_slug that is not present in the index. If no skill \
in the index is a good fit for a technique, simply emit no selection for that technique rather than \
making one up. Copy skill_slug and skill_category exactly as they appear in the index entry you are \
selecting — do not alter capitalization, spelling, or punctuation.

For each selection, produce:
- skill_slug: copied verbatim from a skill index entry's slug
- skill_category: copied verbatim from that same index entry's subdomain
- technique_id / technique_name: the validated technique this selection addresses
- rationale: why this skill is a good next investigative step for this technique
- evidence_focus: what in the evidence this skill's investigation should focus on
- confidence: 0.0-1.0, how confident you are this skill is the right fit
- evidence_anchors: carry forward the technique's verbatim evidence anchors that motivated this pick

Respond with ONLY a JSON object — no prose, no markdown code fences — exactly this shape:
{
  "selected": [
    {
      "skill_slug": "mimikatz-detection",
      "skill_category": "identity-security",
      "technique_id": "T1003",
      "technique_name": "OS Credential Dumping",
      "rationale": "...",
      "evidence_focus": "...",
      "confidence": 0.8,
      "evidence_anchors": ["..."]
    }
  ],
  "evidence_gaps": ["gaps you notice while selecting skills, e.g. no skill in the index covers X"]
}"""

    async def run(
        self,
        input: ClassifierInput,
        validated: TechniqueValidatorOutput,
        provider: LLMProvider,
    ) -> SkillSelectorOutput:
        validated_ids = {t.technique_id for t in validated.techniques if t.technique_id}
        candidate_index, fallback_reason = _narrow_skill_index_by_technique_overlap(
            input.skill_index, validated_ids
        )
        if fallback_reason:
            print(
                f"[casky_pipeline:pipeline] SkillSelector: {fallback_reason}",
                file=sys.stderr,
            )
        user_prompt = self._build_user_prompt(input, validated, candidate_index)
        # Directly observed truncating mid-JSON at the 2048 default on real evidence
        # with 3+ validated techniques (multiple selections × rationale/evidence_focus/
        # evidence_anchors per selection adds up fast) — bumped to 4096, then
        # live-caught truncating *again* at 4096 on a 3-technique network-scan
        # investigation (cut off mid-string at char 14147, ~line 216 of the raw
        # response) — evidence_anchors are carried forward verbatim per selection,
        # so cost scales with techniques × selections × anchor text, not just
        # technique count. 6144 is the new empirical floor; _salvage_truncated_json
        # in _parse_json_response is the actual backstop if a response ever
        # outgrows this again — it recovers whatever selections completed instead
        # of discarding the whole response.
        raw = await provider.complete(self.SYSTEM_PROMPT, user_prompt, max_tokens=6144, cacheable_system=True)
        try:
            data = _parse_json_response(raw)
            valid_slugs = {
                str(entry.get("name") or entry.get("slug") or "")
                for entry in input.skill_index
            }
            valid_slugs.discard("")
            # The model is handed the fully validated technique_id/technique_name
            # pairs in its own prompt (see _build_user_prompt below) but is free to
            # omit or garble those fields per-selection in its JSON response — live-
            # observed as blank technique_id (and a technique_name that was really
            # just the skill slug) on 3 of 5 real steps. Rather than ship that
            # straight to the UI, backfill from the known-good validated list by
            # whichever field the model *did* return intact.
            techniques_by_id = {t.technique_id: t for t in validated.techniques if t.technique_id}
            techniques_by_name = {
                t.technique_name.strip().lower(): t for t in validated.techniques if t.technique_name
            }
            selected: list[SelectedSkill] = []
            rejected_slugs: list[str] = []
            unresolved_techniques: list[str] = []
            for s in (data.get("selected", []) or []):
                slug = s.get("skill_slug", "")
                # Defensive belt-and-braces: even though the prompt forbids it,
                # never let a hallucinated slug that isn't in skill_index through.
                if valid_slugs and slug not in valid_slugs:
                    rejected_slugs.append(slug)
                    continue
                technique_id = str(s.get("technique_id", "") or "").strip()
                technique_name = str(s.get("technique_name", "") or "").strip()
                if not technique_id and technique_name:
                    match = techniques_by_name.get(technique_name.lower())
                    if match:
                        technique_id = match.technique_id
                if technique_id and not technique_name:
                    match = techniques_by_id.get(technique_id)
                    if match:
                        technique_name = match.technique_name
                if not technique_id and not technique_name:
                    unresolved_techniques.append(slug)
                selected.append(
                    SelectedSkill(
                        skill_slug=slug,
                        skill_category=s.get("skill_category", ""),
                        technique_id=technique_id,
                        technique_name=technique_name,
                        rationale=s.get("rationale", ""),
                        evidence_focus=s.get("evidence_focus", ""),
                        confidence=float(s.get("confidence", 0.0) or 0.0),
                        evidence_anchors=list(s.get("evidence_anchors", []) or []),
                    )
                )
            if unresolved_techniques:
                print(
                    f"[casky_pipeline:pipeline] SkillSelector: {len(unresolved_techniques)} "
                    f"selection(s) shipped with no technique_id/technique_name and couldn't be "
                    f"backfilled from the validated list — slugs: {unresolved_techniques}",
                    file=sys.stderr,
                )
            if rejected_slugs and not selected:
                # The model proposed selections, but every single one used a
                # skill_slug that isn't in the real skill index — this is
                # exactly the silent-zero-steps failure mode: previously this
                # printed nothing at all, so a hallucination-driven empty plan
                # was indistinguishable from "genuinely no good skill fits."
                print(
                    f"[casky_pipeline:pipeline] SkillSelector: all {len(rejected_slugs)} "
                    f"proposed skill_slug(s) failed to match the skill index (hallucinated "
                    f"or misspelled) — rejected: {rejected_slugs}",
                    file=sys.stderr,
                )
            evidence_gaps = list(data.get("evidence_gaps", []) or [])
            return SkillSelectorOutput(selected=selected, evidence_gaps=evidence_gaps)
        except Exception as exc:
            _log_stage_failure("SkillSelector", exc, raw)
            return SkillSelectorOutput()

    @staticmethod
    def _build_user_prompt(
        input: ClassifierInput,
        validated: TechniqueValidatorOutput,
        candidate_index: list[dict],
    ) -> str:
        techniques_json = json.dumps(
            [
                {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "confidence": t.confidence,
                    "evidence_anchors": t.evidence_anchors,
                    "rationale": t.rationale,
                }
                for t in validated.techniques
            ],
            indent=2,
        )
        skill_index_lines = "\n".join(
            _format_skill_index_line(entry) for entry in candidate_index
        ) or "(skill index is empty)"
        return (
            f"VALIDATED TECHNIQUES:\n{techniques_json}\n\n"
            f"AVAILABLE SKILLS (slug (subdomain) — description):\n{skill_index_lines}"
        )


# ── Stage 3a: StepOrderer (runs parallel with EvidenceGap) ──────────────────

@dataclass
class OrderedStep:
    skill_slug: str
    step_order: int
    depends_on: list[str] = field(default_factory=list)   # skill_slugs this step should follow


@dataclass
class StepOrdererOutput:
    ordered: list[OrderedStep] = field(default_factory=list)


class StepOrderer:
    SYSTEM_PROMPT = """You are an investigation-sequencing agent inside a security investigation \
pipeline.

You will be given a list of selected investigation skills (each tied to a MITRE ATT&CK technique) for \
a single security investigation. Your job is to order them into the most effective investigation \
sequence.

Sequencing principles to apply:
- Establish scope and confirm initial access / entry point before diving into deep forensics.
- Prefer skills that gather broad context or confirm the presence of a technique before skills that \
require the technique's presence to already be confirmed.
- Group naturally related steps (same asset, same kill-chain stage) adjacently.
- If a step's usefulness depends on the findings/output of another step, record that dependency in \
"depends_on" using the other step's skill_slug.
- Steps with no ordering dependency should be sequenced by investigative priority — the step most \
likely to produce actionable findings first.

Respond with ONLY a JSON object — no prose, no markdown code fences — exactly this shape:
{
  "ordered": [
    {"skill_slug": "initial-access-triage", "step_order": 1, "depends_on": []},
    {"skill_slug": "mimikatz-detection", "step_order": 2, "depends_on": ["initial-access-triage"]}
  ]
}
Every skill_slug given to you in the input must appear exactly once in "ordered", numbered starting \
at 1 with no gaps or repeats."""

    async def run(self, selected: SkillSelectorOutput, provider: LLMProvider) -> StepOrdererOutput:
        user_prompt = self._build_user_prompt(selected)
        raw = await provider.complete(self.SYSTEM_PROMPT, user_prompt, cacheable_system=True)
        try:
            data = _parse_json_response(raw)
            ordered = [
                OrderedStep(
                    skill_slug=o.get("skill_slug", ""),
                    step_order=int(o.get("step_order", 0) or 0),
                    depends_on=list(o.get("depends_on", []) or []),
                )
                for o in (data.get("ordered", []) or [])
            ]
            return StepOrdererOutput(ordered=ordered)
        except Exception as exc:
            _log_stage_failure("StepOrderer", exc, raw)
            return StepOrdererOutput()

    @staticmethod
    def _build_user_prompt(selected: SkillSelectorOutput) -> str:
        selected_json = json.dumps(
            [
                {
                    "skill_slug": s.skill_slug,
                    "skill_category": s.skill_category,
                    "technique_id": s.technique_id,
                    "technique_name": s.technique_name,
                    "rationale": s.rationale,
                    "evidence_focus": s.evidence_focus,
                }
                for s in selected.selected
            ],
            indent=2,
        )
        return f"SELECTED SKILLS TO ORDER:\n{selected_json}"


# ── Stage 3b: EvidenceGap (runs parallel with StepOrderer) ──────────────────

@dataclass
class EvidenceGapOutput:
    gaps: list[str] = field(default_factory=list)


class EvidenceGap:
    SYSTEM_PROMPT = """You are an evidence-gap analyst inside a security investigation pipeline.

You will be given the original evidence text and the set of investigation skills/techniques selected \
so far. Your job is to identify what additional evidence — logs, artifacts, telemetry, or context — \
would most strengthen or refute the current findings if it were collected next.

Focus on:
- Evidence that would confirm or rule out a selected technique with higher confidence.
- Evidence sources implied by a selected technique but absent from the evidence given (e.g. a \
technique that usually correlates with EDR/process telemetry, but none is present).
- Missing scope information (time range, number of affected assets, related identities) that limits \
how the investigation should be prioritized.

Respond with ONLY a JSON object — no prose, no markdown code fences — exactly this shape:
{
  "gaps": ["specific, concrete, actionable missing-evidence description"]
}
Keep each gap concrete — describe the specific missing evidence, not a generic statement like "more \
evidence needed"."""

    async def run(
        self,
        input: ClassifierInput,
        selected: SkillSelectorOutput,
        provider: LLMProvider,
    ) -> EvidenceGapOutput:
        user_prompt = self._build_user_prompt(input, selected)
        raw = await provider.complete(self.SYSTEM_PROMPT, user_prompt, cacheable_system=True)
        try:
            data = _parse_json_response(raw)
            gaps = list(data.get("gaps", []) or [])
            return EvidenceGapOutput(gaps=gaps)
        except Exception as exc:
            _log_stage_failure("EvidenceGap", exc, raw)
            return EvidenceGapOutput()

    @staticmethod
    def _build_user_prompt(input: ClassifierInput, selected: SkillSelectorOutput) -> str:
        selected_json = json.dumps(
            [
                {
                    "skill_slug": s.skill_slug,
                    "technique_id": s.technique_id,
                    "technique_name": s.technique_name,
                    "evidence_focus": s.evidence_focus,
                }
                for s in selected.selected
            ],
            indent=2,
        )
        return (
            f"EVIDENCE:\n{input.evidence_text}\n\n"
            f"SELECTED SKILLS/TECHNIQUES SO FAR:\n{selected_json}"
        )


# ── Final pipeline output — the exact shape generate_local_plan() consumes ──

@dataclass
class ClassifierOutput:
    """Mirrors the JSON-array item shape the current single Haiku call
    produces (harness.py:394-404 prompt spec, parsed at harness.py:422-453):
    each dict in `steps` has keys skill_slug, skill_category, technique_id,
    technique_name, rationale, evidence_focus, step_order, confidence,
    evidence_gaps — so the integration agent's diff at the harness.py call
    site is small (Section 6, item 1)."""
    steps: list[dict] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    confidence: float = 0.0


async def run_pipeline(
    input: ClassifierInput,
    provider: LLMProvider,
    on_progress: ProgressFn | None = None,
) -> ClassifierOutput:
    """on_progress, if given, is called with a short human-readable string
    before each stage starts — e.g. harness.py wires this to console.print()
    so a real terminal session sees per-stage feedback instead of one long
    silence between 'Phase D: Running classifier pipeline…' and the result.
    Optional and side-effect-free by default so callers (and tests) that
    don't care about progress output don't need to pass anything."""
    def progress(msg: str) -> None:
        if on_progress is not None:
            on_progress(msg)

    progress("Validating MITRE techniques against evidence…")
    validated = await TechniqueValidator().run(input, provider)

    progress(f"Selecting skills for {len(validated.techniques)} validated technique(s)…")
    selected = await SkillSelector().run(input, validated, provider)

    progress(f"Ordering {len(selected.selected)} selected skill(s) and checking evidence gaps…")
    step_order_result, gap_result = await asyncio.gather(
        StepOrderer().run(selected, provider),
        EvidenceGap().run(input, selected, provider),
    )
    order_by_slug = {o.skill_slug: o.step_order for o in step_order_result.ordered}
    steps = [
        {
            "skill_slug": s.skill_slug,
            "skill_category": s.skill_category,
            "technique_id": s.technique_id,
            "technique_name": s.technique_name,
            "rationale": s.rationale,
            "evidence_focus": s.evidence_focus,
            "step_order": order_by_slug.get(s.skill_slug, i + 1),
            "confidence": s.confidence,
            "evidence_gaps": [],
        }
        for i, s in enumerate(selected.selected)
    ]
    all_gaps = list(dict.fromkeys(
        validated.evidence_gaps + selected.evidence_gaps + gap_result.gaps + input.context_gaps
    ))
    confidences = [s.confidence for s in selected.selected]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    return ClassifierOutput(steps=steps, evidence_gaps=all_gaps, confidence=avg_confidence)
