"""Tests for harness.py's assemble_prompt() — leveraging each skill's full set of
shipped artifacts (script, references/, assets/template.md), not just SKILL.md.

Context: casky.sh's own ENV_SECTION tells the agent that every skill under
/opt/skills-library/skills/<slug>/ ships tested code plus reference material, but
it only knows the broad category (e.g. "web-app"), not which of the 817 skills a
given step is. assemble_prompt() knows the exact step.skill_slug, so it surfaces
everything concretely: LocalSkillsLibrary.get_executable_script() (agent.py OR
process.py — the library's two script-naming conventions, confirmed via the real
mounted image: 809 skills use agent.py, 282 use process.py, every skill has at
least one), get_reference_files() (references/*.md — standards.md, workflows.md,
api-reference.md, whatever a skill ships), and get_report_template()
(assets/template.md, only 287/817 skills ship one). These tests assert each
injection happens when the artifact exists and is skipped cleanly when it
doesn't, without ever crashing or dropping the underlying skill_document.
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


def _point_at_library(tmp_path: Path, monkeypatch) -> Path:
    lib = tmp_path / "skills-library"
    lib.mkdir()
    monkeypatch.setattr(harness.config, "skills_library_path", lib)
    return lib


# ── get_executable_script(): agent.py vs process.py ────────────────────────────

def test_assemble_prompt_includes_agent_py_when_it_exists(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    scripts = lib / "skills" / "exploiting-sql-injection-vulnerabilities" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "agent.py").write_text("# stub\n")

    prompt = harness.assemble_prompt(_make_plan(), _make_step("exploiting-sql-injection-vulnerabilities"))

    assert str(scripts / "agent.py") in prompt
    assert "This skill's own implementation" in prompt
    assert "Prefer running this over improvising" in prompt
    assert "Do the thing." in prompt  # additive, not a replacement


def test_assemble_prompt_falls_back_to_process_py_when_no_agent_py(tmp_path, monkeypatch):
    """282 of 817 skills use process.py instead of agent.py — must not be treated
    as 'this skill has no script'."""
    lib = _point_at_library(tmp_path, monkeypatch)
    scripts = lib / "skills" / "achieving-cmmc-level-2-compliance" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "process.py").write_text("# stub\n")

    prompt = harness.assemble_prompt(_make_plan(), _make_step("achieving-cmmc-level-2-compliance"))

    assert str(scripts / "process.py") in prompt
    assert "This skill's own implementation" in prompt


def test_assemble_prompt_prefers_agent_py_when_both_exist(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    scripts = lib / "skills" / "some-skill" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "agent.py").write_text("# stub agent\n")
    (scripts / "process.py").write_text("# stub process\n")

    prompt = harness.assemble_prompt(_make_plan(), _make_step("some-skill"))

    assert str(scripts / "agent.py") in prompt
    assert str(scripts / "process.py") not in prompt


def test_assemble_prompt_skips_script_note_when_neither_exists(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    skill_dir = lib / "skills" / "auditing-aws-s3-bucket-permissions"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# S3 Bucket Audit\n\nCheck bucket ACLs.\n")

    prompt = harness.assemble_prompt(_make_plan(), _make_step("auditing-aws-s3-bucket-permissions"))

    assert "This skill's own implementation" not in prompt
    assert "Do the thing." in prompt  # skill_document still included


# ── get_reference_files(): references/*.md ─────────────────────────────────────

def test_assemble_prompt_lists_all_reference_files_when_present(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    refs = lib / "skills" / "performing-memory-forensics-with-volatility3" / "references"
    refs.mkdir(parents=True)
    (refs / "standards.md").write_text("# Standards\n")
    (refs / "workflows.md").write_text("# Workflows\n")

    prompt = harness.assemble_prompt(_make_plan(), _make_step("performing-memory-forensics-with-volatility3"))

    assert "Reference material for this skill" in prompt
    assert str(refs / "standards.md") in prompt
    assert str(refs / "workflows.md") in prompt


def test_assemble_prompt_skips_reference_section_when_absent(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    (lib / "skills" / "some-skill").mkdir(parents=True)

    prompt = harness.assemble_prompt(_make_plan(), _make_step("some-skill"))

    assert "Reference material for this skill" not in prompt


# ── get_report_template(): assets/template.md ───────────────────────────────────

def test_assemble_prompt_includes_report_template_when_present(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    assets = lib / "skills" / "some-skill" / "assets"
    assets.mkdir(parents=True)
    (assets / "template.md").write_text("# Finding Template\n")

    prompt = harness.assemble_prompt(_make_plan(), _make_step("some-skill"))

    assert "Report template for this skill" in prompt
    assert str(assets / "template.md") in prompt


def test_assemble_prompt_skips_report_template_when_absent(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    (lib / "skills" / "some-skill").mkdir(parents=True)

    prompt = harness.assemble_prompt(_make_plan(), _make_step("some-skill"))

    assert "Report template for this skill" not in prompt


# ── Full skill (all four artifacts) and drift/unknown-slug safety ──────────────

def test_assemble_prompt_full_skill_includes_everything(tmp_path, monkeypatch):
    lib = _point_at_library(tmp_path, monkeypatch)
    skill_dir = lib / "skills" / "performing-memory-forensics-with-volatility3"
    (skill_dir / "scripts").mkdir(parents=True)
    (skill_dir / "scripts" / "process.py").write_text("# stub\n")
    (skill_dir / "references").mkdir()
    (skill_dir / "references" / "standards.md").write_text("# Standards\n")
    (skill_dir / "assets").mkdir()
    (skill_dir / "assets" / "template.md").write_text("# Template\n")

    prompt = harness.assemble_prompt(_make_plan(), _make_step("performing-memory-forensics-with-volatility3"))

    assert "This skill's own implementation" in prompt
    assert "Reference material for this skill" in prompt
    assert "Report template for this skill" in prompt
    assert "Do the thing." in prompt


def test_assemble_prompt_handles_unknown_skill_slug_gracefully(tmp_path, monkeypatch):
    """A skill_slug with no matching directory at all (e.g. index/library drift)
    must not crash assemble_prompt — every getter just resolves a path that
    happens not to exist."""
    _point_at_library(tmp_path, monkeypatch)

    prompt = harness.assemble_prompt(_make_plan(), _make_step("some-skill-not-in-the-library"))

    assert "This skill's own implementation" not in prompt
    assert "Reference material for this skill" not in prompt
    assert "Report template for this skill" not in prompt
    assert "Do the thing." in prompt
