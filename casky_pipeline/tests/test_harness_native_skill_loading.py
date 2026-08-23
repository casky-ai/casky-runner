"""Tests for LocalSkillsLibrary.symlink_for_native_loading() — the ~/.claude/skills/
symlinking added alongside assemble_prompt()'s prompt-injected guidance.

Context: 'claude --print' (what casky.sh's run) case invokes) discovers skills
natively from ~/.claude/skills/<slug>/ — confirmed empirically against the real
runner container, and the same mechanism the upstream project's own Black Hat
Arsenal deployment uses (BHUSA-Anthropic-CyberSecurity-Skills/setup-skills.sh),
there via a static day-before symlink step for 10 hand-picked skills. Here it's
done per classifier-selected step in AgentWorker.execute(), since SkillSelector
already narrows the 817-skill library to a handful per plan. This must be
best-effort: a failure here must never block the actual investigation, since
assemble_prompt()'s prompt-level guidance already works without it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import harness  # noqa: E402  (path insert must happen first)


def _make_library(tmp_path: Path) -> tuple[harness.LocalSkillsLibrary, Path]:
    lib_path = tmp_path / "skills-library"
    lib_path.mkdir()
    return harness.LocalSkillsLibrary(path=lib_path), lib_path


def _fake_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home" / "casky"
    monkeypatch.setattr(harness.Path, "home", staticmethod(lambda: home))
    return home


def test_symlinks_skill_into_claude_skills_dir(tmp_path, monkeypatch):
    library, lib_path = _make_library(tmp_path)
    home = _fake_home(tmp_path, monkeypatch)
    skill_dir = lib_path / "skills" / "exploiting-sql-injection-vulnerabilities"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# SQLi\n")

    library.symlink_for_native_loading("exploiting-sql-injection-vulnerabilities")

    link = home / ".claude" / "skills" / "exploiting-sql-injection-vulnerabilities"
    assert link.is_symlink()
    assert link.resolve() == skill_dir.resolve()
    assert (link / "SKILL.md").read_text() == "# SQLi\n"  # readable through the symlink


def test_noop_when_skill_not_in_library(tmp_path, monkeypatch):
    library, _lib_path = _make_library(tmp_path)
    home = _fake_home(tmp_path, monkeypatch)

    # Must not raise, and must not create ~/.claude/skills/ at all for a
    # skill that doesn't exist on disk.
    library.symlink_for_native_loading("some-skill-not-in-the-library")

    assert not (home / ".claude" / "skills").exists()


def test_idempotent_when_called_twice(tmp_path, monkeypatch):
    library, lib_path = _make_library(tmp_path)
    home = _fake_home(tmp_path, monkeypatch)
    skill_dir = lib_path / "skills" / "some-skill"
    skill_dir.mkdir(parents=True)

    library.symlink_for_native_loading("some-skill")
    library.symlink_for_native_loading("some-skill")  # must not raise

    link = home / ".claude" / "skills" / "some-skill"
    assert link.is_symlink()
    assert link.resolve() == skill_dir.resolve()


def test_relinks_when_existing_symlink_points_elsewhere(tmp_path, monkeypatch):
    """Simulates a stale symlink (e.g. skills-library path changed between
    container rebuilds) — must repoint to the current, correct target."""
    library, lib_path = _make_library(tmp_path)
    home = _fake_home(tmp_path, monkeypatch)
    skill_dir = lib_path / "skills" / "some-skill"
    skill_dir.mkdir(parents=True)

    stale_target = tmp_path / "stale-target"
    stale_target.mkdir()
    claude_skills = home / ".claude" / "skills"
    claude_skills.mkdir(parents=True)
    (claude_skills / "some-skill").symlink_to(stale_target)

    library.symlink_for_native_loading("some-skill")

    link = claude_skills / "some-skill"
    assert link.resolve() == skill_dir.resolve()


def test_does_not_clobber_a_real_directory_at_the_same_name(tmp_path, monkeypatch):
    """If something non-symlink already occupies ~/.claude/skills/<slug> (e.g. a
    user-authored custom skill with the same name), leave it alone rather than
    silently overwriting it."""
    library, lib_path = _make_library(tmp_path)
    home = _fake_home(tmp_path, monkeypatch)
    skill_dir = lib_path / "skills" / "some-skill"
    skill_dir.mkdir(parents=True)

    claude_skills = home / ".claude" / "skills"
    real_dir = claude_skills / "some-skill"
    real_dir.mkdir(parents=True)
    (real_dir / "SKILL.md").write_text("# A real, user-authored skill\n")

    library.symlink_for_native_loading("some-skill")

    assert not real_dir.is_symlink()
    assert (real_dir / "SKILL.md").read_text() == "# A real, user-authored skill\n"


def test_never_raises_on_home_permission_error(tmp_path, monkeypatch):
    """Best-effort: a failure creating ~/.claude/skills (permissions, read-only
    HOME, etc.) must be swallowed, not raised — it must never block the actual
    investigation, since assemble_prompt()'s prompt-level guidance still works
    without this."""
    library, lib_path = _make_library(tmp_path)
    skill_dir = lib_path / "skills" / "some-skill"
    skill_dir.mkdir(parents=True)

    def _raise_home():
        raise OSError("simulated: HOME not writable")

    monkeypatch.setattr(harness.Path, "home", staticmethod(_raise_home))

    # Must not raise.
    library.symlink_for_native_loading("some-skill")
