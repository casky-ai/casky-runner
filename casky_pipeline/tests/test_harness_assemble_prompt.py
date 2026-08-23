"""Tests for harness.py's assemble_prompt() — specifically the agent.py-leverage
behavior added alongside the live-target investigation mode work.

Context: casky.sh's own ENV_SECTION tells the agent that every skill under
/opt/skills-library/skills/<slug>/scripts/agent.py is a tested implementation to
prefer over hand-written commands, but it only knows the broad category (e.g.
"web-app"), not which of the 753 skills a given step is. assemble_prompt() knows
the exact step.skill_slug, so it surfaces the concrete agent.py path up front —
these tests assert that injection happens when the script exists and is skipped
cleanly when it doesn't (not every skill ships one).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import harness  # noqa: E402  (path insert must happen first)


def _make_step(skill_slug: str) -> harness.Step:
    return harness.Step(
        id="step-1",
        skill_slug=skill_slug,
        skill_category="web-app",
        skill_document="# Some Skill\n\nDo the thing.\n",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        rationale="Evidence suggests this technique applies.",
        evidence_focus="HTTP access logs",
        step_order=1,
    )


def _make_plan() -> harness.Plan:
    return harness.Plan(
        id="plan-1",
        domain="web-app",
        evidence_text="Suspicious POST requests with SQL-looking payloads.",
        status="pending",
    )


@pytest.fixture
def skills_library_with_agent(tmp_path: Path, monkeypatch) -> Path:
    lib = tmp_path / "skills-library"
    skill_dir = lib / "skills" / "exploiting-sql-injection-vulnerabilities" / "scripts"
    skill_dir.mkdir(parents=True)
    (skill_dir / "agent.py").write_text("#!/usr/bin/env python3\n# stub agent.py\n")
    monkeypatch.setattr(harness.config, "skills_library_path", lib)
    return lib


@pytest.fixture
def skills_library_without_agent(tmp_path: Path, monkeypatch) -> Path:
    lib = tmp_path / "skills-library"
    # Skill directory exists (has SKILL.md) but no scripts/agent.py — some skills
    # genuinely don't ship one.
    skill_dir = lib / "skills" / "auditing-aws-s3-bucket-permissions"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# S3 Bucket Audit\n\nCheck bucket ACLs.\n")
    monkeypatch.setattr(harness.config, "skills_library_path", lib)
    return lib


def test_assemble_prompt_includes_agent_py_path_when_it_exists(skills_library_with_agent):
    step = _make_step("exploiting-sql-injection-vulnerabilities")
    prompt = harness.assemble_prompt(_make_plan(), step)

    expected_path = skills_library_with_agent / "skills" / step.skill_slug / "scripts" / "agent.py"
    assert str(expected_path) in prompt
    assert "This skill's own implementation" in prompt
    assert "Prefer running this over improvising" in prompt
    # The skill document itself is still included — this is additive, not a replacement.
    assert "Do the thing." in prompt


def test_assemble_prompt_skips_agent_py_note_when_absent(skills_library_without_agent):
    step = _make_step("auditing-aws-s3-bucket-permissions")
    prompt = harness.assemble_prompt(_make_plan(), step)

    assert "This skill's own implementation" not in prompt
    assert "agent.py" not in prompt
    # The skill document is still there — absence of agent.py shouldn't drop it.
    assert "Do the thing." in prompt


def test_assemble_prompt_handles_unknown_skill_slug_gracefully(tmp_path, monkeypatch):
    """A skill_slug with no matching directory at all (e.g. index/library drift)
    must not crash assemble_prompt — get_agent_script() just builds a path that
    happens not to exist, same code path as skills_library_without_agent above."""
    lib = tmp_path / "skills-library"
    lib.mkdir()
    monkeypatch.setattr(harness.config, "skills_library_path", lib)

    step = _make_step("some-skill-not-in-the-library")
    prompt = harness.assemble_prompt(_make_plan(), step)

    assert "This skill's own implementation" not in prompt
    assert "Do the thing." in prompt
