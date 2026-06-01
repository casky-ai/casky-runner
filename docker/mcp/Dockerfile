FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_PORT=8080 \
    MCP_HOST=0.0.0.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install CVE MCP Server from GitHub
# Source: https://github.com/mukul975/cve-mcp-server
# TODO: pin to a release tag once stable (currently installs latest main)
RUN pip install --no-cache-dir \
    "git+https://github.com/mukul975/cve-mcp-server.git" \
    && pip cache purge

RUN groupadd --gid 1001 mcp \
    && useradd --uid 1001 --gid mcp --shell /bin/sh --no-create-home mcp

USER mcp

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import socket; socket.create_connection(('localhost', 8080), timeout=3)" 2>/dev/null || exit 1

# Starts the CVE MCP server in SSE mode so casky-runner can reach it over HTTP.
# mcp.run(transport='sse') is supported by mcp[cli]>=1.7.0 (a direct dependency).
CMD ["python", "-c", "from cve_mcp.server import mcp; mcp.run(transport='sse', host='0.0.0.0', port=8080)"]

LABEL org.opencontainers.image.source="https://github.com/casky-ai/casky-runner" \
      org.opencontainers.image.title="casky-mcp" \
      org.opencontainers.image.description="CVE MCP Server for Casky Box"
