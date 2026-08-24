LOCAL_IMAGE  ?= casky-runner:dev
REMOTE_IMAGE ?= ghcr.io/casky-ai/box/runner:latest
SKILL        ?= web-app
AGENT        ?= claude

.DEFAULT_GOAL := help

.PHONY: help build scan lint test pytest test-compose test-compose-lab shell run verify push clean lab live smoke smoke-full

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the runner image locally
	docker build --progress=plain -t $(LOCAL_IMAGE) .

pytest: ## Run the casky_pipeline + casky_db unit test suites (adapters, pipeline, llm_providers, persistence)
	@if [ ! -d .venv ]; then \
	  echo "Creating .venv for casky_pipeline/casky_db tests..."; \
	  python3 -m venv .venv; \
	  .venv/bin/pip install --quiet pytest pytest-asyncio anthropic requests pyyaml rich mcp "psycopg[binary]"; \
	fi
	# casky_db/tests/ requires a reachable Postgres (DATABASE_URL) and skips
	# cleanly without one — see casky_db/tests/conftest.py.
	.venv/bin/python -m pytest casky_pipeline/tests/ casky_db/tests/ -v

scan: build ## Run Trivy HIGH/CRITICAL scan (requires Docker)
	docker run --rm \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  aquasec/trivy:latest image \
	  --severity HIGH,CRITICAL --exit-code 1 \
	  $(LOCAL_IMAGE)

lint: ## Shellcheck casky.sh (requires Docker)
	docker run --rm \
	  -v "$(CURDIR):/mnt:ro" \
	  koalaman/shellcheck:stable /mnt/casky.sh

test: build pytest ## Run the full test harness — casky_pipeline unit tests + image-level tests
	./tests/run-tests.sh $(LOCAL_IMAGE)

test-compose: ## Test the full docker-compose stack using .env.local
	./tests/compose-test.sh

test-compose-lab: ## Test compose stack + lab profile (skill-lab + target)
	./tests/compose-test.sh --lab

shell: build ## Open a bash shell inside the runner
	docker run --rm -it \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  $(LOCAL_IMAGE) bash

run: ## Run a skill against the running compose stack (SKILL=web-app AGENT=claude) — needs `docker compose up -d` first
	@if ! docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx runner; then \
	  echo "casky-runner isn't up. Start the stack first:"; \
	  echo "  docker compose up -d"; \
	  exit 1; \
	fi
	docker compose exec -it runner casky run $(SKILL) --agent $(AGENT)

verify: ## Verify skill-lab has required tools  (SKILL=web-app)
	@PASS=0; FAIL=0; \
	while IFS= read -r tool; do \
	  [ -z "$$tool" ] && continue; \
	  case "$$tool" in \#*) continue ;; esac; \
	  if docker exec skill-lab which "$$tool" > /dev/null 2>&1; then \
	    echo "  ✓ $$tool"; PASS=$$((PASS + 1)); \
	  else \
	    echo "  ✗ $$tool — NOT FOUND"; FAIL=$$((FAIL + 1)); \
	  fi; \
	done < "skills/$(SKILL).tools"; \
	echo ""; \
	if [ "$$FAIL" -gt 0 ]; then \
	  echo "FAIL: $$FAIL tool(s) missing from skill-lab"; exit 1; \
	fi; \
	echo "PASS: all $$PASS tools present in skill-lab ($(SKILL))"

lab: ## Start a lab target + matching skill-lab tools (TARGET=vulnstack|metasploitable|vulnservices|linux-pivot|minidc|pcap-server|localstack|vulncode|evidence-pack|sample-pack|dvwa|juice-shop|custom)
	@case "$(TARGET)" in \
	  dvwa)           SKILL_IMAGE=ghcr.io/casky-ai/skills/web-app:latest ;; \
	  juice-shop)     SKILL_IMAGE=ghcr.io/casky-ai/skills/web-app:latest ;; \
	  vulnstack)      SKILL_IMAGE=ghcr.io/casky-ai/skills/vuln-scan:latest ;; \
	  metasploitable) SKILL_IMAGE=ghcr.io/casky-ai/skills/exploitation:latest ;; \
	  vulnservices)   SKILL_IMAGE=ghcr.io/casky-ai/skills/exploitation:latest ;; \
	  linux-pivot)    SKILL_IMAGE=ghcr.io/casky-ai/skills/post-exploit:latest ;; \
	  minidc)         SKILL_IMAGE=ghcr.io/casky-ai/skills/active-directory:latest ;; \
	  pcap-server)    SKILL_IMAGE=ghcr.io/casky-ai/skills/network:latest ;; \
	  localstack)     SKILL_IMAGE=ghcr.io/casky-ai/skills/cloud:latest ;; \
	  vulncode)       SKILL_IMAGE=ghcr.io/casky-ai/skills/appsec:latest ;; \
	  evidence-pack)  SKILL_IMAGE=ghcr.io/casky-ai/skills/forensics:latest; \
	                  echo "NOTE: targets/evidence-pack — see README's known-limitations note on its GHCR visibility." ;; \
	  sample-pack)    SKILL_IMAGE=ghcr.io/casky-ai/skills/malware:latest; \
	                  echo "NOTE: targets/sample-pack is PRIVATE on GHCR — run 'docker login ghcr.io' with org access first." ;; \
	  custom)         SKILL_IMAGE=ghcr.io/casky-ai/skills/web-app:latest; \
	                  echo "NOTE: override SKILL_IMAGE=... yourself if your custom target needs different tools." ;; \
	  "")             echo "Usage: make lab TARGET=<dvwa|juice-shop|vulnstack|metasploitable|vulnservices|linux-pivot|minidc|pcap-server|localstack|vulncode|evidence-pack|sample-pack|custom>"; exit 1 ;; \
	  *)              echo "Unknown TARGET '$(TARGET)' — see 'make help'"; exit 1 ;; \
	esac; \
	echo "Starting lab-$(TARGET) — skill-lab built from $$SKILL_IMAGE"; \
	SKILL_IMAGE=$$SKILL_IMAGE docker compose --profile lab-$(TARGET) up -d --build

live: ## Investigate a REAL, authorized target (LIVE_TARGET=<host|url> AUTHORIZED=yes SKILL=web-app AGENT=claude [NETWORK_ACCESS=yes])
	@if [ "$(AUTHORIZED)" != "yes" ] || [ -z "$(LIVE_TARGET)" ]; then \
	  echo "Live-target mode investigates a real system. By default (no NETWORK_ACCESS) it"; \
	  echo "produces a RUNBOOK — commands for a human to run themselves, no execution, uses"; \
	  echo "the sandboxed skill-lab. Add NETWORK_ACCESS=yes to have this container execute"; \
	  echo "tools directly instead, over skill-live's real internet egress."; \
	  echo "Only use this against infrastructure you have explicit authorization to test."; \
	  echo "See SECURITY.md and README's 'Live, authorized real-target investigations' section."; \
	  echo ""; \
	  echo "Usage: make live LIVE_TARGET=<host-or-url> AUTHORIZED=yes SKILL=web-app AGENT=claude [NETWORK_ACCESS=yes]"; \
	  exit 1; \
	fi
	@if [ "$(NETWORK_ACCESS)" = "yes" ]; then \
	  SKILL_IMAGE=ghcr.io/casky-ai/skills/$(SKILL):latest docker compose --profile live up -d --build skill-live; \
	  docker compose exec -it runner casky run $(SKILL) --agent $(AGENT) --live-target $(LIVE_TARGET) --i-have-authorization --i-have-network-access; \
	else \
	  SKILL_IMAGE=ghcr.io/casky-ai/skills/$(SKILL):latest docker compose --profile lab up -d --build skill-lab; \
	  docker compose exec -it runner casky run $(SKILL) --agent $(AGENT) --live-target $(LIVE_TARGET) --i-have-authorization; \
	fi

smoke: ## Fast smoke test — casky_pipeline/casky_db unit tests + casky-ui tests/typecheck/build (no Docker Postgres needed)
	./scripts/smoke-test.sh

smoke-full: ## Full smoke test — smoke, plus a real Postgres + casky-ui end-to-end verification (needs Docker)
	./scripts/smoke-test.sh --full

push: build ## Tag and push to GHCR
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

clean: ## Remove local test containers and the dev image
	docker rm -f casky-test-skill-lab 2>/dev/null || true
	docker rmi $(LOCAL_IMAGE) 2>/dev/null || true
