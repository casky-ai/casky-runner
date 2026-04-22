LOCAL_IMAGE  ?= casky-runner:dev
REMOTE_IMAGE ?= ghcr.io/casky-ai/box/runner:latest
SKILL        ?= web-application-testing
AGENT        ?= claude

.DEFAULT_GOAL := help

.PHONY: help build scan lint test shell run verify push clean

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

test: build ## Run the full test harness
	./tests/run-tests.sh $(LOCAL_IMAGE)

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

verify: build ## Verify skill-lab has required tools  (SKILL=web-application-testing)
	docker run --rm \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  $(LOCAL_IMAGE) \
	  casky verify $(SKILL)

push: build ## Tag and push to GHCR
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

clean: ## Remove local test containers and the dev image
	docker rm -f casky-test-skill-lab 2>/dev/null || true
	docker rmi $(LOCAL_IMAGE) 2>/dev/null || true
