#!/bin/bash
set -e

# The container starts as root (see Dockerfile — USER casky was removed so this
# script can run first) specifically to solve one problem: the host's docker.sock
# GID is not knowable at image-build time and varies by platform.
#
#   - Native Linux Docker: the socket is usually owned by a 'docker' group with
#     a host-specific GID.
#   - Docker Desktop for Mac/Windows: the socket, as seen from inside a
#     container, is commonly owned by GID 0 (root) — NOT a distinct docker
#     group — which the image's build-time 'docker' group (GID 1002) can never
#     match no matter what GID is hardcoded at build time.
#
# So: detect the real GID at container startup, make sure 'casky' is a member
# of *that* GID (creating a group for it if none exists yet), then drop to the
# 'casky' user for everything else. This is the standard docker-socket-access
# pattern for images that need docker CLI access without running as root.
if [[ "$(id -u)" == "0" ]]; then
  SOCK=/var/run/docker.sock
  if [[ -S "$SOCK" ]]; then
    SOCK_GID="$(stat -c '%g' "$SOCK")"
    if ! getent group "$SOCK_GID" >/dev/null 2>&1; then
      groupadd -g "$SOCK_GID" dockersock 2>/dev/null || true
    fi
    GROUP_NAME="$(getent group "$SOCK_GID" | cut -d: -f1)"
    usermod -aG "$GROUP_NAME" casky 2>/dev/null || true
  fi
  # Re-exec this same script as 'casky' — everything below this block then
  # runs unprivileged, including the final "exec $@".
  exec su casky -c "$(printf '%q ' "$0" "$@")"
fi

# From here down we are always running as 'casky' (either the container
# started that way with no docker.sock mounted, or we just dropped to it above).

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

# Enrich the (read-only-mounted, subdomain-less) skills index with the real
# subdomain/tags/mitre_attack data that exists in every SKILL.md's own
# frontmatter but got dropped when the flat index.json was generated. Without
# this, `casky skills list <subdomain>` returns nothing for every possible
# filter, and every classifier-generated plan step's skill_category silently
# falls back to "recon" (see scripts/enrich_skills_index.py for the full
# explanation). Writes to /var/casky, not the read-only library mount.
SKILLS_LIBRARY_PATH="${SKILLS_LIBRARY_PATH:-/opt/skills-library}"
if [[ -f "${SKILLS_LIBRARY_PATH}/index.json" ]]; then
  # Must use the venv interpreter (has pyyaml) — bare `python3` on PATH is the
  # bare system install with no dependencies installed.
  /opt/casky-console/bin/python3 /opt/casky-console/lib/enrich_skills_index.py \
    "${SKILLS_LIBRARY_PATH}" "/var/casky/skills-index-enriched.json" || \
    echo "[casky] Warning: skills index enrichment failed — subdomain-based features degrade to raw index" >&2
else
  echo "[casky] Skills library not mounted at ${SKILLS_LIBRARY_PATH} — skipping index enrichment" >&2
fi

exec "$@"
