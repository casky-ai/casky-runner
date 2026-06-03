#!/bin/bash
set -e

# Register the CVE MCP server with Claude Code at container startup.
# Claude Code will launch it as a subprocess (stdio transport) on first use.
# All API keys (NVD_API_KEY, SHODAN_KEY, etc.) are inherited from the container environment.
mkdir -p "${HOME}/.claude"
cat > "${HOME}/.claude/claude_desktop_config.json" <<'EOF'
{
  "mcpServers": {
    "casky-cve": {
      "command": "/opt/cve-mcp/bin/python3",
      "args": ["-m", "cve_mcp.server"]
    }
  }
}
EOF
echo "[casky] CVE MCP registered (stdio · /opt/cve-mcp/bin/python3 -m cve_mcp.server)"

exec "$@"
