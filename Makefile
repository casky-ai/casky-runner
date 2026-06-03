LOCAL_IMAGE  ?= casky-runner:dev
REMOTE_IMAGE ?= ghcr.io/casky-ai/box/runner:latest
SKILL        ?= web-app
AGENT        ?= claude

.DEFAULT_GOAL := help

.PHONY: help build scan lint test test-compose test-compose-lab shell run verify push clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the runner image locally
	docker build --progress=plain -t $(LOCAL_IMAGE) .

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

test: build ## Run the full test harness (image-only, no compose)
	./tests/run-tests.sh $(LOCAL_IMAGE)

test-compose: ## Test the full docker-compose stack using .env.local
	./tests/compose-test.sh

test-compose-lab: ## Test compose stack + lab profile (skill-lab + target)
	./tests/compose-test.sh --lab

shell: build ## Open a bash shell inside the runner
	docker run --rm -it \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  $(LOCAL_IMAGE) bash

run: build ## Run a skill  (SKILL=web-application-testing AGENT=claude)
	docker run --rm \
	  -e ANTHROPIC_API_KEY \
	  -e GOOGLE_API_KEY \
	  -e GEMINI_API_KEY \
	  -e CASKY_RUN_ID \
	  -e CASKY_TOKEN \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  $(LOCAL_IMAGE) \
	  casky run $(SKILL) --agent $(AGENT)

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

push: build ## Tag and push to GHCR
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

clean: ## Remove local test containers and the dev image
	docker rm -f casky-test-skill-lab 2>/dev/null || true
	docker rmi $(LOCAL_IMAGE) 2>/dev/null || true
