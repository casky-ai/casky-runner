# casky-runner

The AI runner image for the [Casky](https://casky.ai) platform. Ships Claude Code and Gemini CLI in a minimal Ubuntu container. Drives security exercises by issuing commands into a skill container via `docker exec`, against a target container on the same isolated Docker network.

```
Docker host (your laptop or CI runner)
│
├── casky-lab  ─── isolated bridge network
│   ├── skill container    ghcr.io/casky-ai/skills/<name>:latest   ← security tools
│   └── target container   ghcr.io/casky-ai/targets/<name>:latest  ← vulnerable app
│
└── casky-runner           ghcr.io/casky-ai/box/runner:latest
        │  has Claude Code + Gemini CLI
        │  reaches skill container via Docker socket (docker exec)
        └──► POSTs findings to Casky platform over internet
```

## Runner image

```
ghcr.io/casky-ai/box/runner:latest
```

## Quick start

```bash
# 1. Create the isolated lab network (once)
docker network create casky-lab

# 2. Start the target for your exercise (example: DVWA for web-app skill)
docker run -d --name target \
  --network casky-lab \
  ghcr.io/casky-ai/targets/dvwa:latest

# 3. Start the skill container
docker run -d --name skill-lab \
  --network casky-lab \
  ghcr.io/casky-ai/skills/web-app:latest

# 4. Run the AI agent
docker run --rm \
  -e ANTHROPIC_API_KEY="<your-key>" \
  -e CASKY_RUN_ID="<run-id>" \
  -e CASKY_TOKEN="<token>" \
  -e SKILL_LAB_NAME=skill-lab \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/casky-ai/box/runner:latest \
  casky run web-app
```

## Commands

| Command | Description |
|---|---|
| `casky run <skill>` | Run a skill exercise with Claude (default) |
| `casky run <skill> --agent gemini` | Run with Gemini CLI instead |
| `casky verify <skill>` | Check that the skill container has all required tools |

## Environment variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Claude Code API key |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Gemini CLI API key |
| `SKILL_LAB_NAME` | Name of the running skill container (default: `skill-lab`) |
| `CASKY_RUN_ID` | Links findings to a Casky platform run (optional) |
| `CASKY_TOKEN` | JWT for POSTing findings to the platform (optional) |
| `CASKY_APP_URL` | Override platform URL (default: `https://app.casky.ai`) |

## Skills

Each skill maps 1-to-1 to an image in [casky-ai/skill-images](https://github.com/casky-ai/skill-images).

| Skill name | Skill image | Paired targets |
|---|---|---|
| `forensics` | `ghcr.io/casky-ai/skills/forensics` | `evidence-pack` |
| `malware` | `ghcr.io/casky-ai/skills/malware` | `sample-pack` |
| `threat-intel` | `ghcr.io/casky-ai/skills/threat-intel` | — |
| `threat-hunting` | `ghcr.io/casky-ai/skills/threat-hunting` | `evidence-pack` |
| `network` | `ghcr.io/casky-ai/skills/network` | `pcap-server` |
| `cloud` | `ghcr.io/casky-ai/skills/cloud` | `localstack` |
| `web-app` | `ghcr.io/casky-ai/skills/web-app` | `dvwa`, `juice-shop` |
| `vuln-scan` | `ghcr.io/casky-ai/skills/vuln-scan` | `vulnstack` |
| `exploitation` | `ghcr.io/casky-ai/skills/exploitation` | `metasploitable`, `vulnservices` |
| `post-exploit` | `ghcr.io/casky-ai/skills/post-exploit` | `linux-pivot` |
| `incident-response` | `ghcr.io/casky-ai/skills/incident-response` | `evidence-pack` |
| `detection` | `ghcr.io/casky-ai/skills/detection` | — |
| `osint` | `ghcr.io/casky-ai/skills/osint` | — |
| `recon` | `ghcr.io/casky-ai/skills/recon` | `vulnstack` |
| `identity` | `ghcr.io/casky-ai/skills/identity` | `minidc` |
| `active-directory` | `ghcr.io/casky-ai/skills/active-directory` | `minidc` |
| `appsec` | `ghcr.io/casky-ai/skills/appsec` | `vulncode` |
| `devsecops` | `ghcr.io/casky-ai/skills/devsecops` | — |

Target images are published from [casky-ai/skill-targets](https://github.com/casky-ai/skill-targets) to `ghcr.io/casky-ai/targets/<name>:latest`.

## Local development

```bash
make build    # build runner image (casky-runner:dev)
make scan     # Trivy HIGH/CRITICAL scan
make lint     # shellcheck casky.sh
make test     # run the integration test harness
make shell    # bash shell inside the runner

# Run a skill (requires a running skill-lab container)
make run SKILL=web-app AGENT=claude

# Verify tools are present in the skill container
make verify SKILL=web-app
```

## How it works

1. The runner, skill, and target containers all start on the `casky-lab` Docker network.
2. `casky run <category>` reads the skill prompt from **stdin** — paste any `SKILL.md` from the [753-skill registry](https://github.com/casky-ai/casky-runner), then press `Ctrl+D`. The runner appends environment context (which containers are running, how to exec into the skill container) and pipes the combined prompt to Claude Code or Gemini CLI.
3. The AI agent runs tool commands via `docker exec <skill-container> <cmd>` — it never enters either container interactively.
4. If `CASKY_RUN_ID` and `CASKY_TOKEN` are set, the agent POSTs findings back to the Casky platform API on completion.
5. `casky verify <category>` checks every tool listed in `/etc/casky/skills/<category>.tools` exists in the skill container — used in CI to confirm skill images ship the expected toolchain.

## CI

- **build.yml** — builds the runner image, runs Trivy (HIGH/CRITICAL exit-code 1), pushes to GHCR on `main`. Trivy always scans the locally built image, not a stale GHCR tag.
- **test.yml** — matrix over all 18 skills; pulls the corresponding `ghcr.io/casky-ai/skills/<name>:latest` image, starts it as `skill-lab`, runs `casky verify <skill>`. Skips gracefully if the skill image isn't published yet.

## License

MIT
