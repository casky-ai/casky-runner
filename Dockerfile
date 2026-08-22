FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# System deps + Docker CLI (no daemon) + Node.js LTS
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg lsb-release jq git python3 python3-pip python3-venv \
    && curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
       | gpg --dearmor -o /usr/share/keyrings/docker.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] \
       https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# CVE MCP Server — installed in a venv to avoid pip version constraints on Ubuntu 22.04
# (Ubuntu 22.04 ships pip 22 which doesn't support --break-system-packages)
RUN python3 -m venv /opt/cve-mcp \
    && /opt/cve-mcp/bin/pip install --no-cache-dir \
       "git+https://github.com/mukul975/cve-mcp-server.git"

# AI agent CLIs — install via package.json so 'overrides' pins vulnerable
# transitive deps (minimatch, picomatch, tar) to their patched versions.
# @github/copilot added in Phase 1 to back casky.sh's `--agent copilot` (the
# dispatch branch existed before this without the binary actually installed).
COPY package.json /opt/casky-tools/package.json
RUN cd /opt/casky-tools \
    && npm install --omit=dev \
    && ln -sf /opt/casky-tools/node_modules/.bin/claude /usr/local/bin/claude \
    && ln -sf /opt/casky-tools/node_modules/.bin/gemini /usr/local/bin/gemini \
    && ln -sf /opt/casky-tools/node_modules/.bin/copilot /usr/local/bin/copilot

# Non-root user with docker socket access
RUN groupadd --gid 1001 casky \
    && useradd --uid 1001 --gid casky --shell /bin/bash --create-home casky \
    && groupadd -f docker \
    && usermod -aG docker casky

# Agentic harness — Python venv with rich + requests + mcp + anthropic + pyyaml + psycopg
# (pyyaml added in Phase 1 for casky_pipeline's LocalPlaybookAdapter, which parses
# the starter playbook YAML set; psycopg[binary] added in Part B for casky_db's
# Postgres persistence layer — [binary] bundles libpq so no extra apt packages
# are needed for the C extension to build/load)
RUN python3 -m venv /opt/casky-console \
    && /opt/casky-console/bin/pip install --no-cache-dir rich requests mcp anthropic pyyaml "psycopg[binary]"

# Report output directory (persisted via volume mount in docker-compose).
# /var/casky itself also needs to be writable by the non-root 'casky' user
# (not just reports/) — the skills-index enrichment step below writes
# /var/casky/skills-index-enriched.json directly into this directory.
RUN mkdir -p /var/casky/reports && chmod 777 /var/casky /var/casky/reports

# casky wrapper + harness + skill tool manifests + MCP entrypoint
COPY casky.sh /usr/local/bin/casky
COPY harness.py /usr/local/bin/casky-harness
COPY entrypoint.sh /usr/local/bin/casky-entrypoint
RUN chmod +x /usr/local/bin/casky /usr/local/bin/casky-harness /usr/local/bin/casky-entrypoint
COPY skills/ /etc/casky/skills/

# Phase 1 pipeline package (context adapters, 4-stage classifier, BYO-LLM
# provider layer, starter playbooks) — harness.py does `import casky_pipeline`,
# so it needs to resolve on the venv interpreter's path.
COPY casky_pipeline/ /opt/casky-console/lib/casky_pipeline/
# Part B persistence layer (migrations, migrate.py, store.py, json_import.py)
# — harness.py does `from casky_db import store`, and casky.sh's `db`
# subcommand runs it as `python3 -m casky_db.migrate` / `casky_db.json_import`,
# so it needs to resolve on the same PYTHONPATH as casky_pipeline above.
COPY casky_db/ /opt/casky-console/lib/casky_db/
# Skills index enrichment — fills in the subdomain/tags/mitre_attack data
# missing from the flat index.json shipped in the skills-library image (see
# scripts/enrich_skills_index.py for the full explanation). Run by
# entrypoint.sh at container startup, not at build time, since the skills
# library volume isn't mounted yet during the image build.
COPY scripts/enrich_skills_index.py /opt/casky-console/lib/enrich_skills_index.py
ENV PYTHONPATH=/opt/casky-console/lib
# Force unbuffered stdout/stderr — belt-and-braces for any invocation where
# Python doesn't detect a TTY (docker exec without -it, healthchecks, future
# casky-agent scheduled runs) so progress output never sits in a block buffer.
ENV PYTHONUNBUFFERED=1

# Deliberately NOT dropping to USER casky here. The container starts as root
# so casky-entrypoint can detect the real docker.sock GID at runtime (it varies
# by platform — Docker Desktop for Mac/Windows commonly mounts the socket as
# GID 0, which the build-time 'docker' group above can never match) and grant
# 'casky' access to whatever GID actually owns it, before dropping privilege
# itself and exec'ing everything else as 'casky'. See entrypoint.sh.
WORKDIR /home/casky
ENTRYPOINT ["casky-entrypoint"]
CMD ["sleep", "infinity"]

LABEL org.opencontainers.image.source="https://github.com/casky-ai/casky-runner"
