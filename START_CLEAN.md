# Start Clean — Docker Compose Reset

When you need to start fresh (no ghost containers, no stale volumes):

## Quick One-Liner (Recommended)

```bash
docker rm -f casky-target casky-runner casky-skills casky-db skill-lab casky-mcp 2>/dev/null; docker compose down -v; docker compose --profile lab-dvwa --env-file .env.local up -d
```

## Step-by-Step

### 1. Force-remove all casky containers

```bash
docker rm -f casky-target casky-runner casky-skills casky-db skill-lab casky-mcp
```

This removes any lingering containers even if they're partially running. The `2>/dev/null` suppresses "not found" errors if some containers don't exist.

### 2. Tear down compose (networks + volumes)

```bash
docker compose down -v
```

The `-v` flag removes volumes too, so you get a completely fresh state. If you want to keep volumes (rare), omit `-v`.

### 3. Start fresh

```bash
docker compose --profile lab-dvwa --env-file .env.local up -d
```

Or choose your target:
```bash
docker compose --profile lab-juice-shop --env-file .env.local up -d
docker compose --profile lab-custom --env-file .env.local up -d
```

### 4. Verify everything is up

```bash
docker compose ps
```

All services should show `Up`.

---

## Why This Happens

- **Ghost containers:** If a previous `docker compose up` was killed (Ctrl+C), containers stay around
- **Stale volumes:** Old investigation data can interfere with fresh tests
- **Network conflicts:** Old networks prevent new ones from being created

## When to Start Clean

| Situation | Action |
|-----------|--------|
| Testing from scratch | Always start clean |
| Resuming after error | Start clean |
| Switching targets (dvwa → juice-shop) | Start clean |
| Updating docker-compose.yml | Start clean |
| After git pull | Start clean (volumes might be stale) |

## Shortcuts

**Alias for your shell** (add to `~/.zshrc` or `~/.bashrc`):

```bash
alias casky-clean='docker rm -f casky-target casky-runner casky-skills casky-db skill-lab casky-mcp 2>/dev/null; docker compose down -v'
```

Then just:
```bash
casky-clean
docker compose --profile lab-dvwa --env-file .env.local up -d
```

**Or create a helper script** (save as `start-clean.sh`):

```bash
#!/bin/bash
set -e
echo "Cleaning up old containers and volumes..."
docker rm -f casky-target casky-runner casky-skills casky-db skill-lab casky-mcp 2>/dev/null || true
docker compose down -v

PROFILE=${1:-lab-dvwa}
echo "Starting fresh with profile: $PROFILE"
docker compose --profile "$PROFILE" --env-file .env.local up -d

echo "Waiting for services to be ready..."
sleep 10
docker compose ps

echo "✅ Ready to investigate!"
```

Make it executable:
```bash
chmod +x start-clean.sh
./start-clean.sh lab-dvwa
```

---

## Troubleshooting

**"container already in use"** after docker compose down:
```bash
# More aggressive:
docker system prune -f
docker compose --profile lab-dvwa --env-file .env.local up -d
```

**Volumes won't delete:**
```bash
docker volume rm casky-box_casky-skills-data casky-box_casky-db-data 2>/dev/null || true
docker compose down -v
```

**All casky services stuck:**
```bash
docker compose kill  # Force-stop all services
docker compose down -v  # Remove everything
# Then start fresh
```

---

## Your Standard Workflow

Always follow this pattern:

```bash
cd /Users/rajesh/code/casky-runner

# 1. Clean
docker rm -f casky-target casky-runner casky-skills casky-db skill-lab casky-mcp 2>/dev/null
docker compose down -v

# 2. Start
docker compose --profile lab-dvwa --env-file .env.local up -d

# 3. Verify
docker compose ps

# 4. Investigate
docker exec -it casky-runner casky run web-app
```
