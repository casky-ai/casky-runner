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
COPY package.json /opt/casky-tools/package.json
RUN cd /opt/casky-tools \
    && npm install --omit=dev \
    && ln -sf /opt/casky-tools/node_modules/.bin/claude /usr/local/bin/claude \
    && ln -sf /opt/casky-tools/node_modules/.bin/gemini /usr/local/bin/gemini

# Non-root user with docker socket access
RUN groupadd --gid 1001 casky \
    && useradd --uid 1001 --gid casky --shell /bin/bash --create-home casky \
    && groupadd -f docker \
    && usermod -aG docker casky

# Agentic harness — Python venv with rich + requests for the terminal UI
RUN python3 -m venv /opt/casky-console \
    && /opt/casky-console/bin/pip install --no-cache-dir rich requests

# Report output directory (persisted via volume mount in docker-compose)
RUN mkdir -p /var/casky/reports && chmod 777 /var/casky/reports

# casky wrapper + harness + skill tool manifests + MCP entrypoint
COPY casky.sh /usr/local/bin/casky
COPY harness.py /usr/local/bin/casky-harness
COPY entrypoint.sh /usr/local/bin/casky-entrypoint
RUN chmod +x /usr/local/bin/casky /usr/local/bin/casky-harness /usr/local/bin/casky-entrypoint
COPY skills/ /etc/casky/skills/

USER casky
WORKDIR /home/casky
ENTRYPOINT ["casky-entrypoint"]
CMD ["sleep", "infinity"]

LABEL org.opencontainers.image.source="https://github.com/casky-ai/casky-runner"
