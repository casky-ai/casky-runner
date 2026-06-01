#!/bin/bash
set -e

# Auto-register the CVE MCP server in Claude Code's config if MCP_SERVER_URL is set.
# This runs once at container startup so every subsequent `claude` invocation
# inside the container already has threat-intel tools available.
if [ -n "${MCP_SERVER_URL}" ]; then
  mkdir -p "${HOME}/.claude"
  cat > "${HOME}/.claude/claude_desktop_config.json" <<EOF
{
  "mcpServers": {
    "casky-cve": {
      "type": "sse",
      "url": "${MCP_SERVER_URL}/sse"
    }
  }
}
EOF
  echo "[casky] CVE MCP registered at ${MCP_SERVER_URL}"
fi

exec "$@"
