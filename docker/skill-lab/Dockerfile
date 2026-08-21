# SKILL_IMAGE selects which of the 18 real, published, hardened skill images
# (github.com/casky-ai/skill-images -> ghcr.io/casky-ai/skills/<category>:latest)
# this skill-lab container is built from. Previously hardcoded to web-app
# regardless of what category you actually wanted to run — e.g. `casky run
# network` would still only ever have web-app's tools (nmap/nikto/sqlmap/ffuf/
# nuclei), never tshark/tcpdump/zeek/masscan. Set SKILL_IMAGE in .env (or pass
# --build-arg) and rebuild to switch categories — see docker-compose.yml and
# README.md's target/category pairing table.
ARG SKILL_IMAGE=ghcr.io/casky-ai/skills/web-app:latest
FROM ${SKILL_IMAGE}

# Ensure root and fix apt directory permissions
USER root
RUN mkdir -p /var/lib/apt/lists/partial && chmod 755 /var/lib/apt/lists

# Add commonly used security tools
RUN apt-get update --allow-unauthenticated && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    jq \
    git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Verify tools are installed
RUN which nmap && nmap --version && echo "✓ nmap installed"
