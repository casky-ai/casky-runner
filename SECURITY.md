# Security Policy

## What this tool is, and the trust model that follows from it

Casky Box runs real offensive/investigative security tools (nmap, sqlmap, Metasploit, etc.) inside
containers, with `/var/run/docker.sock` mounted into the `runner` container so it can orchestrate
`skill-lab`. That socket mount is powerful by design — treat any machine running `casky-runner` the
same way you'd treat a machine with root Docker access, and never run this against infrastructure
you don't have explicit authorization to test.

By default, live tool execution (`casky run`/`make lab`) only ever touches `skill-lab`, which has
**no internet egress** (`docker-compose.yml`'s `casky-lab` network is `internal: true`) — it can
only reach the disposable lab target on that same isolated network. Pointing tools at a real,
externally-reachable target is a separate, explicitly opt-in mode (`make live` / `casky run
--live-target <host|url> --i-have-authorization`, using `skill-live` instead) — see README's
"Live, authorized real-target investigations" section. The authorization requirement above applies
in full to that mode: only use it against infrastructure you have explicit authorization to test.

## Supported components

| Component | Supported |
|---|---|
| `harness.py`, `casky_pipeline/` (classifier pipeline, adapters) | Yes |
| `casky.sh` (agent dispatch) | Yes |
| `docker-compose.yml`, `Dockerfile`, `docker/skill-lab/Dockerfile` | Yes |
| Skill tool images (`ghcr.io/casky-ai/skills/*`) | Report to [`casky-ai/skill-images`](https://github.com/casky-ai/skill-images/security/advisories/new) |
| Practice target images (`ghcr.io/casky-ai/targets/*`) | Report to [`casky-ai/skill-targets`](https://github.com/casky-ai/skill-targets/security/advisories/new) |
| Skill content (`SKILL.md` files) | Report to [`Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/security/advisories/new) |

## Reporting a vulnerability

1. **Do not** open a public issue for anything exploitable.
2. Use GitHub's private security advisory: [Report a vulnerability](https://github.com/casky-ai/casky-runner/security/advisories/new).
3. Include: affected file/component, nature of the issue, potential impact, reproduction steps,
   and a suggested fix if you have one.

**Response timeline:** acknowledgment within 48 hours, triage within 1 week, fix or mitigation
timeline communicated based on severity.

## Specific areas we take seriously

- **Secrets handling.** `.env` (API keys, `CASKY_API_KEY`, `DATABASE_URL`) is gitignored and must
  never be committed. If you find a code path that logs, echoes, or otherwise leaks a secret from
  `.env` or the environment, that's a real finding — please report it.
- **Evidence size / prompt injection into the classifier.** `evidence_text` (pasted, or via
  `-i`/`--input-file`) is embedded directly into every LLM prompt in the 4-stage pipeline. There's
  a size guard (`MAX_EVIDENCE_CHARS` in `harness.py`) against oversized submissions, but evidence
  content itself is inherently untrusted — the classifier's output (skill selection, suggested
  commands) should always be reviewed by a human before execution, which is why `casky harness`'s
  default flow shows the plan and lets you choose which steps to run rather than auto-executing.
- **Non-root execution.** The `runner` container starts as root only long enough for
  `entrypoint.sh` to detect the mounted `docker.sock`'s actual GID (this varies by platform) and
  grant the non-root `casky` user access to it, then drops privilege before running anything else.
  `casky.sh` itself also drops root on every invocation path (`docker run`, `docker exec`, or
  entrypoint's own re-exec) — see the comment block in `entrypoint.sh` for the full reasoning. A
  regression here (something ending up running as root that shouldn't) is a real finding.
- **Image supply chain.** The skill and target images this repo depends on are signed with cosign
  (keyless OIDC) and shipped with an SBOM — see `skill-images`' README for verification commands.
  If you can demonstrate an unsigned or tampered image being pulled instead of the real one,
  that's in scope here even though the image itself lives in a different repo.
- **BYO-Agent command injection.** `casky.sh --agent custom --agent-cmd "<binary>"` runs an
  arbitrary user-specified binary — this is intentional (it's the whole point of the escape
  hatch), not a vulnerability in itself. What *would* be in scope: a way for evidence content or
  skill documentation to inject commands into the `--agent claude|gemini|copilot` first-party
  dispatch paths beyond what those agents' own prompt/tool-use safety already governs.

## Recognition

We credit responsible disclosures (unless you prefer to remain anonymous).
