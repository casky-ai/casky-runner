# Casky Runner Skills Library Integration — Testing Guide

Run these commands in order from the casky-runner directory.

## Test 1: Build the skills library image (local testing)

Build with local test tag:
```bash
docker build -f docker/skills/Dockerfile -t casky-skills:test .
```

Or build with the production image name (recommended for full testing):
```bash
docker build -f docker/skills/Dockerfile -t ghcr.io/casky-ai/skills-library:latest .
```

**Expected output:**
```
...
[stage-1 4/4] WORKDIR /opt/skills-library
#11 naming to docker.io/library/casky-skills:test
#11 naming to docker.io/library/casky-skills:test done
```

**Verify:**
```bash
docker images | grep casky-skills
# Should show: casky-skills:test
```

---

## Test 2: Run the init container to populate a volume

```bash
docker run --rm -v casky-skills-test:/opt/skills-library casky-skills:test
```

**Expected output:**
```
Skills library ready: 754 skills
```

**Verify the volume:**
```bash
docker run --rm -v casky-skills-test:/data alpine ls /data/skills | wc -l
# Should show: 754
```

---

## Test 3: Check the skills library index

```bash
docker run --rm -v casky-skills-test:/opt/skills-library alpine head -c 200 /opt/skills-library/index.json
```

**Expected output:**
```json
{"version":"1.1.0","generated_at":"2026-06-01T10:15:47Z","repository":"https://github.com/mukul975/Anthropic-Cybersecurity-Skills","domain":"cybersecurity","total_skills":754,...
```

---

## Test 4: Verify casky.sh skills subcommands

### 4a. List all skills (using a container with the volume mounted)

First, build the image:
```bash
docker build -f docker/skills/Dockerfile -t ghcr.io/casky-ai/skills-library:latest .
```

Then test using docker run to mount the test volume:
```bash
docker run --rm -v casky-skills-test:/opt/skills-library \
  -v $(pwd):/work alpine:latest sh -c \
  'SKILLS_LIBRARY_PATH=/opt/skills-library /work/casky.sh skills list | head -5'
```

**Expected output:**
```
acquiring-disk-image-with-dd-and-dcfldd (digital-forensics) — Create forensically sound bit-for-bit disk images using dd and dcfldd
analyzing-active-directory-acl-abuse (identity-security) — Detect dangerous ACL misconfigurations in Active Directory using ldap3
analyzing-android-malware-with-apktool (malware-analysis) — Perform static analysis of Android APK malware samples using apktool
analyzing-api-gateway-access-logs (api-security) — Parses API Gateway access logs (AWS API Gateway, Kong, Nginx) to detect
analyzing-apt-group-with-mitre-navigator (threat-intelligence) — Analyze advanced persistent threat (APT) group techniques using MITRE
```

### 4b. Show help with SKILLS_LIBRARY_PATH documented

```bash
bash casky.sh help | grep -A 10 "Env vars:"
```

**Expected output:** (includes SKILLS_LIBRARY_PATH variable documentation)

### 4c. Show a specific skill

```bash
docker run --rm -v casky-skills-test:/opt/skills-library alpine sh -c 'head -30 /opt/skills-library/skills/analyzing-active-directory-acl-abuse/SKILL.md'
```

**Expected output:**
```
---
name: analyzing-active-directory-acl-abuse
description: Detect dangerous ACL misconfigurations in Active Directory using ldap3
domain: cybersecurity
subdomain: identity-security
...
```

---

## Test 5: Verify docker-compose configuration

### 5a. Check service definitions

```bash
docker compose config --services | grep -E "(casky-skills|runner)"
```

**Expected output:**
```
casky-skills
runner
```

### 5b. Check volume configuration

```bash
docker compose config | grep -A 3 "casky-skills-data"
```

**Expected output:**
```
casky-skills-data:
```

### 5c. Check dependencies

```bash
docker compose config | grep -A 10 "depends_on:" | head -15
```

**Expected output:**
```
depends_on:
  casky-skills:
    condition: service_completed_successfully
    required: true
  db:
    condition: service_healthy
```

---

## Test 6: Verify Python harness.py

```bash
python3 -m py_compile harness.py && echo "✓ harness.py syntax OK"
```

**Expected output:**
```
✓ harness.py syntax OK
```

---

## Test 7: Production build (uses real ghcr.io image)

When ready to use the real workflow:

### 7a. Build runner image

```bash
docker build -t casky-runner:latest .
```

### 7b. Pull/build skills library

```bash
# Option 1: Use pre-built image from GitHub
docker pull ghcr.io/casky-ai/skills-library:latest

# Option 2: Build locally
docker build -f docker/skills/Dockerfile -t ghcr.io/casky-ai/skills-library:latest .
```

### 7c. Update docker-compose.yml image reference (if using local build)

Edit docker-compose.yml:
```yaml
casky-skills:
  image: ghcr.io/casky-ai/skills-library:latest  # or your local tag
```

### 7d. Start the stack

```bash
# First, build the image locally
docker build -f docker/skills/Dockerfile -t ghcr.io/casky-ai/skills-library:latest .

# Setup environment
cp .env.example .env.local
# Edit .env.local and add ANTHROPIC_API_KEY if you want to test plan generation

# Start just the skills init container
docker compose up casky-skills
# Wait for: "Skills library ready: 754 skills"
# Exit with Ctrl+C

# Verify the volume was populated
docker volume inspect casky-box_casky-skills-data | grep -A 2 Mountpoint

# Now you can start the runner
docker compose up runner -d  # Run in background
docker compose logs runner -f  # Watch logs

# Test skills commands inside the runner
docker exec casky-runner casky skills list | head -5
```

---

## Expected Integration Points

✅ **casky-skills init container**
- Clones the 754-skill security library from GitHub
- Populates casky-skills-data volume
- Exits successfully when complete

✅ **runner depends on casky-skills**
- Won't start until skills library is populated
- Mounts casky-skills-data at /opt/skills-library (read-only)

✅ **skill-lab container** (when profile is active)
- Also mounts casky-skills-data at /opt/skills-library
- Can execute scripts/agent.py from the mounted library

✅ **harness.py**
- LocalSkillsLibrary class loads index.json
- generate_local_plan() function calls Haiku classifier
- 50+ subdomain-to-category mappings convert skill categories

✅ **casky.sh skills subcommand**
- `casky skills list [subdomain]` — browse available skills
- `casky skills show <slug>` — view skill documentation
- `casky skills verify <slug>` — check agent.py accessibility

✅ **Documentation updates**
- QUICKSTART.md: Added skills library setup step
- INVESTIGATION_GUIDE.md: Added Phase 0 plan generation

---

## Troubleshooting

**"Skills library ready: 0 skills"**
- Check docker build output for git clone errors
- Verify /tmp/skills-src directory was created in the Dockerfile

**"docker compose: service_completed_successfully not supported"**
- Update Docker Compose to v2.16+: `docker compose version`

**"Skills library not found at /opt/skills-library"**
- Verify casky-skills container ran successfully
- Check volume was created: `docker volume ls | grep skills`
- Ensure runner depends on casky-skills

**Can't find skills with casky skills list**
- Check SKILLS_LIBRARY_PATH environment variable
- Verify jq is available for JSON parsing in the shell

---

## What's Next (Future Phases)

After these tests pass:

1. **Interactive execution** — Update AgentWorker to call agent.py scripts instead of casky run
2. **Step-by-step prompts** — Add human input collection before each step
3. **Real deployment** — Push skills library image to ghcr.io/casky-ai/skills-library
4. **CI/CD** — `.github/workflows/build-skills.yml` automatically builds and pushes on commits
