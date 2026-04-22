FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# System deps + Docker CLI (no daemon) + Node.js LTS
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg lsb-release jq git \
    && curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
       | gpg --dearmor -o /usr/share/keyrings/docker.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] \
       https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# AI agent CLIs
RUN npm install -g @anthropic-ai/claude-code @google/gemini-cli

# Non-root user
RUN groupadd --gid 1001 casky \
    && useradd --uid 1001 --gid casky --shell /bin/bash --create-home casky

# casky wrapper + skill tool manifests
COPY casky.sh /usr/local/bin/casky
RUN chmod +x /usr/local/bin/casky
COPY skills/ /etc/casky/skills/

USER casky
WORKDIR /home/casky
CMD ["sleep", "infinity"]

LABEL org.opencontainers.image.source="https://github.com/casky-ai/casky-runner"
