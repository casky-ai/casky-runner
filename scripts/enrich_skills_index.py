#!/usr/bin/env python3
"""Enrich the skills library index with data that exists in every individual
SKILL.md's frontmatter but is missing from the flat index.json shipped in the
ghcr.io/casky-ai/skills-library image (confirmed: that index.json only has
name/description/domain/path — no subdomain, despite every SKILL.md having a
real `subdomain:` field).

This matters beyond `casky skills list <subdomain>` (which is fully broken
without it — every filter returns zero results): harness.py's classifier
prompt shows every skill's subdomain to the LLM as grouping context, and the
SUBDOMAIN_TO_CATEGORY mapping that determines each investigation Step's
skill_category depends on it entirely. Without this fix, every locally
generated plan's skill_category silently falls back to "recon" for
everything, regardless of the skill's real category — that's the source of
every "unknown subdomain '', using 'recon'" warning seen in testing.

The library volume is mounted read-only (`casky-skills-data:/opt/skills-library:ro`
in docker-compose.yml), so this writes to a separate, writable location rather
than modifying the original index.json in place.

Usage: enrich_skills_index.py <skills_library_path> <output_path>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml


def enrich(skills_library_path: Path, output_path: Path) -> None:
    index_file = skills_library_path / "index.json"
    if not index_file.exists():
        print(f"[enrich_skills_index] no index.json at {index_file} — nothing to enrich", file=sys.stderr)
        return

    with open(index_file) as f:
        index = json.load(f)

    skills = index.get("skills", [])
    enriched_count = 0
    for skill in skills:
        name = skill.get("name", "")
        skill_md = skills_library_path / "skills" / name / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            text = skill_md.read_text()
            if not text.startswith("---"):
                continue
            frontmatter = yaml.safe_load(text.split("---", 2)[1])
        except Exception as exc:
            # One malformed SKILL.md must never break enrichment for the
            # other 753 — same graceful-degradation contract as everything
            # else in this codebase (see casky_pipeline/adapters/base.py).
            print(f"[enrich_skills_index] skipping {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        if not isinstance(frontmatter, dict):
            continue
        # Only fill in what the flat index is actually missing — never
        # overwrite fields the original index already had correct.
        for key in ("subdomain", "tags", "mitre_attack", "nist_csf"):
            if key in frontmatter and not skill.get(key):
                skill[key] = frontmatter[key]
        if skill.get("subdomain"):
            enriched_count += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(index))
    print(
        f"[enrich_skills_index] enriched {enriched_count}/{len(skills)} skills with "
        f"subdomain data -> {output_path}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: enrich_skills_index.py <skills_library_path> <output_path>", file=sys.stderr)
        sys.exit(1)
    enrich(Path(sys.argv[1]), Path(sys.argv[2]))
