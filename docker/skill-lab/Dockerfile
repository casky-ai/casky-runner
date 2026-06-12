FROM ghcr.io/casky-ai/skills/web-app:latest

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
