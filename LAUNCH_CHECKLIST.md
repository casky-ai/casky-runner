# Casky Box — public launch checklist

This is a checklist to run through **when you decide to make this public**, not something that
happens automatically as part of any code change. Nothing here has been executed — every box is
unchecked deliberately. Each of these is outward-facing and/or hard to reverse, so they belong to
an explicit decision, not a side effect of a doc pass.

## Before merging `phase1-harness-port` to `main`

- [ ] Review the branch's commit (`45f4ace` at time of writing) — either as a PR
      (`github.com/casky-ai/casky-runner/pull/new/phase1-harness-port`) or a direct merge
- [ ] Confirm no coordination conflict with any other active work on `casky-runner`'s `main`
- [ ] Decide the `evidence-pack` GHCR-visibility discrepancy (documented private, currently pulls
      anonymously) — either correct the `skill-targets` README or lock down the package visibility
      to match; don't leave it ambiguous before launch

## Fresh-clone verification (the actual Phase 4 exit condition)

Do this on a machine that has never touched this repo before — ideally not yours. This is what
"Box-standalone verification" in `plans/039` actually means:

- [ ] `git clone https://github.com/casky-ai/casky-runner.git && cd casky-runner`
- [ ] `cp .env.example .env`, set only `ANTHROPIC_API_KEY` — no other config
- [ ] `docker build -f docker/skills/Dockerfile -t ghcr.io/casky-ai/skills-library:latest .` (only
      needed pre-publish — once `build-skills.yml`/`sync-skills.yml` have run against `main`, this
      step goes away and `docker compose pull casky-skills` just works)
- [ ] `docker compose up casky-skills` — confirms a real skill count, not zero
- [ ] `make lab TARGET=dvwa`
- [ ] `docker exec -it casky-runner casky run web-app` — confirms BYO-Agent dispatch works
- [ ] `docker exec -it casky-runner casky harness` — paste real evidence, confirm a real plan comes
      back with correct technique IDs and real per-step commands (not the generic 2-line fallback)
- [ ] Repeat the `casky harness` step with `-i /var/casky/evidence/<file>` instead of pasting
- [ ] `make lab TARGET=pcap-server` — confirms the `SKILL_IMAGE` fix: `tshark`/`tcpdump`/`masscan`
      should be present, not just web-app's tools
- [ ] `make pytest` — 99/99 (or whatever the current count is) passing on a completely clean checkout

If any of these fail on a genuinely fresh clone (not this session's already-warmed-up environment),
that's a real gap — fix it before announcing, don't discover it from a user's bug report.

## GHCR / image publishing

- [ ] Confirm `build-skills.yml`/`sync-skills.yml` actually ran successfully against `main` after
      merge and `ghcr.io/casky-ai/skills-library:latest` is real and pullable (not just locally
      built, as it was throughout this testing session)
- [ ] Spot-check a few of the 18 skill-images and 12 skill-targets are still current (they're
      independently maintained repos with their own CI — confirm nothing drifted)

## Repo hygiene

- [ ] GitHub repo description set (something concrete — "self-hosted, open-source security
      investigation runtime" style, not marketing copy)
- [ ] GitHub topics added (`security`, `mitre-attack`, `llm`, `docker`, whatever's accurate —
      topics are how people find this via search/browse)
- [ ] README's badges (if any) actually resolve (CI status, license, etc.)
- [ ] `SECURITY.md`'s private-advisory link (`github.com/casky-ai/casky-runner/security/advisories/new`)
      resolves once the repo's Security tab is enabled
- [ ] `CODE_OF_CONDUCT.md`'s `conduct@casky.ai` is a real, monitored address before launch (it's a
      placeholder pattern, not verified as live during this session)

## Cross-linking

- [ ] Link from `casky.ai` marketing/docs to the new open-source repo
- [ ] Link from `claude-skills-security`'s own README (the closed platform repo) to `casky-runner`,
      per the Box → Pro → MSSP framing — the open repo should be discoverable from the closed one,
      not just the reverse
- [ ] Update any stale "Casky-in-a-Box" naming left over from earlier plans (per Phase 0's naming
      sign-off item in `plans/039`) — confirm "Casky Box" is the final name used everywhere before
      announcing

## Announcement

- [ ] Draft announcement copy (blog post / social / wherever) — not written as part of this
      checklist; a separate content task
- [ ] Confirm the announcement doesn't overclaim Phase 2/3 (persistence, UI, scheduler) as shipped —
      they aren't. Be explicit that this is Phase 1: evidence-in, MITRE-mapped-plan-out, BYO
      everything, no platform account required — not the full Box → Pro → MSSP vision yet

## After launch

- [ ] Watch the repo's issues/discussions for the first real external contributions/bug reports —
      the first ones from genuinely outside the team are the actual test of whether the
      "no crippled trial mode, everything runs standalone" claim in the README holds up
