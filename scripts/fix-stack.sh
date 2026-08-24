#!/usr/bin/env bash
# fix-stack.sh — clears the stale-container/ghost-network state that makes
# `docker compose up -d` fail with:
#   "Error response from daemon: failed to set up container networking:
#    network <id> not found"
#
# Live-caught cause: an exited container (casky-skills, a one-shot init
# container — normal for it to be Exited(0) after a successful run) can end up
# holding a reference to an OLD network ID if the project's network got
# recreated since that container last ran (a `docker compose down` elsewhere,
# a Docker Desktop restart, manual network pruning, etc.). The network itself
# is fine and exists under its normal name — it's the exited container's
# stale internal reference to the numeric ID that's gone. Compose can't
# restart that container against a network ID that no longer exists.
#
# Fix: remove exited containers belonging to THIS compose project only (scoped
# by the com.docker.compose.project=casky-box label — never touches
# kali-tollbooth, casky-lab targets, or anything from another project on this
# machine), then bring the stack back up so Compose recreates them fresh
# against the current network. Safe to run anytime, including when nothing is
# actually wrong — with no exited containers, it's a no-op straight to
# `docker compose up -d`.
#
# Usage:
#   ./scripts/fix-stack.sh

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PROJECT="casky-box"

echo "== Exited containers in project '$PROJECT' =="
exited="$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --filter "status=exited" --format '{{.Names}}')"
if [ -z "$exited" ]; then
  echo "  none — nothing stale to clear"
else
  echo "$exited" | while IFS= read -r name; do
    docker rm "$name" >/dev/null && echo "  removed: $name (will be recreated by 'docker compose up -d' below)"
  done
fi

echo
echo "== docker compose up -d =="
docker compose up -d
UP_EXIT=$?

echo
echo "== Final stack status =="
docker compose ps

if [ "$UP_EXIT" -ne 0 ]; then
  echo
  echo "Still failing after clearing exited containers — this is a different problem than the"
  echo "one this script fixes. Check 'docker network ls' and 'docker compose logs' directly."
  exit 1
fi
