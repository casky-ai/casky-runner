# Contributing to Casky Box (`casky-runner`)

Thanks for considering a contribution. This repo is the open-source investigation runtime —
harness, classifier pipeline, context adapters, and starter playbooks. The security tool images
and vulnerable practice targets it consumes live in two sibling repos:
[`casky-ai/skill-images`](https://github.com/casky-ai/skill-images) and
[`casky-ai/skill-targets`](https://github.com/casky-ai/skill-targets) — contributions to the tool
set or new practice targets belong there, not here. The underlying skill *content*
(`SKILL.md` files) comes from the upstream
[`Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
registry, synced in automatically — see its own `CONTRIBUTING.md` for adding a new skill.

## What you can contribute here

### A new starter playbook

Playbooks live in `casky_pipeline/playbooks/*.yaml` and give `LocalPlaybookAdapter` a known-good
pattern to match evidence against. See any existing file for the shape (`id`, `name`, `domain`,
`mitre_techniques`, `steps` with `skill_slug`/`technique_id`/`rationale`/`evidence_focus`,
`evidence_gaps`). Keep it real: MITRE technique IDs that actually apply, `skill_slug` values that
exist in the real skills library, and a rationale that would make sense to an analyst reading it —
not filler text. No proprietary content (nothing referencing casky.ai's internal systems,
customer data, or the closed platform's proprietary curated playbook library).

### A new BYO-LLM provider

`casky_pipeline/llm_providers.py`'s `LLMProvider` ABC has two implementations
(`AnthropicProvider`, `OpenAICompatibleProvider`). If you need a genuinely different wire protocol
(not just a new OpenAI-compatible base URL — that already works via `.env`'s `CASKY_MODEL_*`
vars), implement the ABC and add it to `build_provider_from_env()`. Include tests using the same
mocked-provider pattern as the existing `casky_pipeline/tests/test_llm_providers.py`.

### A new BYO-Agent

`casky.sh`'s `run` command dispatches to `--agent claude|gemini|copilot|custom`. A genuinely new
first-class agent integration (not just `--agent custom --agent-cmd "<binary>"`, which already
covers "any CLI that reads a prompt on stdin") needs a new `case` branch there — see the existing
`copilot` branch for the pattern.

### Bug fixes

This codebase has a strong bias toward *live-verified* fixes — nearly every fix in this repo's
history was caught by actually running the affected code path against a real running stack, not
just reasoning about it. If you're fixing something, a regression test that reproduces the real
failure (not just the fixed behavior) is the expected shape of a PR here — see
`casky_pipeline/tests/test_harness_integration.py`'s `_extract_commands_from_skill_doc` tests for
examples of this pattern applied to several real, live-caught bugs.

## Running tests

```bash
cd casky-runner
python3 -m venv .venv && .venv/bin/pip install pytest pytest-asyncio anthropic requests pyyaml rich mcp
.venv/bin/python -m pytest casky_pipeline/tests/ -v   # or: make pytest

make test              # pytest + image-level tests (requires Docker)
make test-compose-lab  # full docker-compose stack, lab profile included
```

## Submitting a change

1. Fork, branch, make your change with tests.
2. `make pytest` (and `make test` if your change touches the Docker image or `casky.sh`) — all
   green before opening a PR.
3. Open a PR describing what you changed and, if it's a bug fix, how you verified the fix (a
   passing test alone is good; a live repro is better).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree
to uphold it.

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0 (see
`LICENSE`).
