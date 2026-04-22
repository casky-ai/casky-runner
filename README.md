# casky-runner

The AI runner image for the [Casky](https://casky.ai) platform. It ships Claude Code and Gemini CLI inside a minimal Ubuntu container, connects to a running skill-lab container over Docker, and drives security exercises autonomously.

## Image

```
ghcr.io/casky-ai/box/runner:latest
```

## Quick start

```bash
# 1. Start the skill-lab container for your exercise
docker run -d --name skill-lab --network casky-lab \
  ghcr.io/casky-ai/box/web-application-testing:latest

# 2. Start the runner and execute the skill
docker run -d --name casky-runner \
  -e ANTHROPIC_API_KEY="<your-key>" \
  -e CASKY_RUN_ID="<run-id>" \
  -e CASKY_TOKEN="<token>" \
  --network casky-lab \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/casky-ai/box/runner:latest

docker exec casky-runner casky run web-application-testing
```

## Commands

| Command | Description |
|---|---|
| `casky run <skill>` | Run a skill exercise with Claude (default) |
| `casky run <skill> --agent gemini` | Run with Gemini CLI instead |
| `casky verify <skill>` | Check that skill-lab has all required tools |

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | For Claude | Claude Code API key |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | For Gemini | Gemini CLI API key |
| `CASKY_RUN_ID` | Optional | Links output to a Casky platform run |
| `CASKY_TOKEN` | Optional | JWT for posting findings to the platform |
| `CASKY_APP_URL` | Optional | Override platform URL (default: `https://app.casky.ai`) |

## Skills

Each skill subdomain has a `.tools` manifest listing the tools expected in the skill-lab container, and a `.md` prompt that is fed to the AI agent.

| Subdomain | Tools manifest |
|---|---|
| `digital-forensics` | [skills/digital-forensics.tools](skills/digital-forensics.tools) |
| `malware-analysis` | [skills/malware-analysis.tools](skills/malware-analysis.tools) |
| `network-analysis` | [skills/network-analysis.tools](skills/network-analysis.tools) |
| `web-application-testing` | [skills/web-application-testing.tools](skills/web-application-testing.tools) |
| `vulnerability-scanning` | [skills/vulnerability-scanning.tools](skills/vulnerability-scanning.tools) |
| `exploitation` | [skills/exploitation.tools](skills/exploitation.tools) |
| `post-exploitation` | [skills/post-exploitation.tools](skills/post-exploitation.tools) |
| `cloud-security` | [skills/cloud-security.tools](skills/cloud-security.tools) |
| `active-directory-attacks` | [skills/active-directory-attacks.tools](skills/active-directory-attacks.tools) |
| `identity-security` | [skills/identity-security.tools](skills/identity-security.tools) |
| `application-security` | [skills/application-security.tools](skills/application-security.tools) |
| `cryptography` | [skills/cryptography.tools](skills/cryptography.tools) |
| `osint` | [skills/osint.tools](skills/osint.tools) |
| `wireless-security` | [skills/wireless-security.tools](skills/wireless-security.tools) |
| `reverse-engineering` | [skills/reverse-engineering.tools](skills/reverse-engineering.tools) |
| `mobile-security` | [skills/mobile-security.tools](skills/mobile-security.tools) |
| `red-team-operations` | [skills/red-team-operations.tools](skills/red-team-operations.tools) |
| `container-security` | [skills/container-security.tools](skills/container-security.tools) |

## How it works

1. The runner container starts alongside the skill-lab container on a shared Docker network.
2. `casky run <skill>` reads the skill prompt from `/etc/casky/skills/<skill>.md`, appends environment context, and pipes the combined prompt to Claude Code (or Gemini).
3. The AI agent runs tool commands via `docker exec skill-lab <cmd>` — it never enters the container interactively.
4. If `CASKY_RUN_ID` and `CASKY_TOKEN` are set, the agent POSTs findings back to the Casky platform API on completion.

## CI

- **build.yml** — builds the image, runs Trivy (HIGH/CRITICAL exit-code 1), pushes to GHCR on `main`.
- **test.yml** — for each skill, spins up the skill-lab image and runs `casky verify <skill>` to confirm all required tools are present.

## License

MIT
