# Phase 2: Interactive Guided Investigation Workflow

Complete end-to-end guide showing how the 4-phase CVE enrichment pipeline + interactive runbook work together.

---

## Overview

**Phase 2** consists of:
- **Phase A:** Entity extraction (CVEs, techniques, IPs, hostnames)
- **Phase B:** CVE enrichment (CVSS, KEV status)
- **Phase C:** Context assembly (similar plans, playbooks)
- **Phase D:** Haiku classification (select 5-8 relevant skills)

Then **investigator-controlled execution**:
- Harness prints a runbook with step-by-step commands
- Investigator opens `docker exec -it skill-lab bash` in their own terminal
- Investigator runs commands and pastes output back to Claude
- Claude analyzes findings and synthesizes report

---

## Start to Finish Example

### Step 1: Generate Investigation Plan

```bash
# Ensure .env.local has empty CASKY_API_KEY for local mode
export CASKY_API_KEY=""

# Start the harness
docker exec -it casky-runner casky harness
```

**Expected output:**
```
╭──────────────────────────────────────────────────────────────────╮
│ Casky.AI Agentic Harness                                         │
│ LOCAL MODE                                                        │
╰──────────────────────────────────────────────────────────────────╯

Plan Source
  g  Generate new plan from evidence (requires skills library)
  p  Load plan from platform
  l  Load local plan file

Choose [g/p/l] (l):
```

### Step 2: Generate Plan from Evidence

Choose `g`:

```
g

Enter evidence text (Ctrl+D when done):
```

Paste your evidence:

```
Web application security assessment - DVWA target

Findings:
- Apache httpd 2.4.67 on port 80
- PHP 8.5.4 detected
- No authentication required on admin panel
- SQL injection possible in login form
- Cross-site scripting (XSS) detected in search field
- Default credentials admin/password suspected

Target: http://casky-target
```

Then press `Ctrl+D` to submit.

**Expected: 4-phase pipeline runs**

```
Phase A: Extracting entities…
Phase B: Enriching with CVE data…
Phase C: Finding similar plans & playbooks…
Phase D: Classifying with Haiku…
Confidence: 87.3%
Evidence gaps: Authentication bypass validation, XSS payload variations
Plan saved: /root/.casky/plans/12345abc-def0-1234-5678-90abcdef1234.json
```

### Step 3: Select Investigation Steps

The harness displays the plan and asks you to select steps:

```
Investigation Steps — Target Summary
┏━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━┓
┃ # ┃ Technique         ┃ Skill          ┃ Category ┃ Status  ┃
┡━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━┩
│ 1 │ T1595 Scanning    │ nmap-web-recon │ web-app │ pending │
│ 2 │ T1592 Gathering   │ httpx-headers  │ web-app │ pending │
│ 3 │ T1190 Exploit     │ sqlmap-inject  │ web-app │ pending │
│ 4 │ T1059 Command     │ testing-rce    │ web-app │ pending │
└───┴───────────────────┴────────────────┴─────────┴─────────┘

Enter step numbers to run (e.g. 1,3) or press Enter to run all
Steps (all):
```

Press Enter to run all, or select specific steps (e.g., `1,2,3`).

### Step 4: View Interactive Runbook

**Instead of spawning subprocesses**, the harness prints:

```
╔════════════════════════════════════════════════════════════════╗
║ Interactive Investigation Runbook                               ║
║ Open a skill-lab shell in a new terminal:                       ║
║   docker exec -it skill-lab bash                                ║
║ Then follow each step below. Paste the output back here.        ║
╚════════════════════════════════════════════════════════════════╝

Step 1: nmap-web-recon (T1595 — Active Scanning)
Goal: Discover open ports and services on target
Target: casky-target (http://casky-target)

Run in skill-lab:
  curl -s -I http://casky-target/ | head -10
  httpx -u http://casky-target -silent
  nuclei -u http://casky-target -silent -severity medium

Look for in output: HTTP headers, server banner, version info

───────────────────────────────────────────────────────────────────

Step 2: httpx-headers (T1592.004 — Gather Victim Identity Info)
Goal: Extract HTTP headers and metadata
Target: casky-target (http://casky-target)

Run in skill-lab:
  curl -s -v http://casky-target/ 2>&1 | grep -E "Server|X-|Set-Cookie"
  httpx -u http://casky-target -json -silent

Look for in output: Server version, cookies, security headers, redirects

───────────────────────────────────────────────────────────────────

Step 3: sqlmap-inject (T1190 — Exploit Public-Facing Application)
Goal: Test for SQL injection vulnerabilities
Target: casky-target (http://casky-target/login.php)

Run in skill-lab:
  curl -s http://casky-target/login.php | grep -E "input|form"
  sqlmap -u http://casky-target/login.php --dbs --batch

Look for in output: SQL error messages, injectable parameters, database names

───────────────────────────────────────────────────────────────────

Step 4: testing-rce (T1059 — Command and Scripting Interpreter)
Goal: Test for command injection and RCE
Target: casky-target

Run in skill-lab:
  curl -s http://casky-target/vulnerable.php?cmd=id
  nuclei -u http://casky-target -tags rce -silent

Look for in output: Command output (uid=...), code execution evidence

───────────────────────────────────────────────────────────────────

✓ Paste the output from each step back to this window.
✓ Provide context about what you found and what it means.
✓ Claude will analyze and synthesize findings into a report.
```

### Step 5: Execute Commands in Parallel Terminal

Open a NEW terminal and run:

```bash
docker exec -it skill-lab bash
```

You're now in the skill-lab container. Run the commands from Step 1:

```bash
root@abc123:/# curl -s -I http://casky-target/ | head -10
HTTP/1.1 302 Found
Date: Fri, 12 Jun 2026 23:35:10 GMT
Server: Apache/2.4.67 (Debian)
X-Powered-By: PHP/8.5.4
Set-Cookie: security=low; path=/; HttpOnly
Set-Cookie: PHPSESSID=abc123def456; path=/; HttpOnly
Location: login.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8

root@abc123:/# httpx -u http://casky-target -silent
http://casky-target [302] [Apache/2.4.67 (Debian)] [PHP/8.5.4]

root@abc123:/# nuclei -u http://casky-target -silent -severity medium
[technology-detection] [info] http://casky-target - Detected Apache/2.4.67 (Debian)
[misconfig-csp] [medium] http://casky-target - Missing CSP headers
[missing-security-headers] [medium] http://casky-target - Missing HSTS, X-Frame-Options
```

### Step 6: Paste Output Back to Claude

Copy the output and paste it back into the Claude window where the harness is waiting:

```
# Step 1 Output

## HTTP Headers
HTTP/1.1 302 Found
Server: Apache/2.4.67 (Debian)
X-Powered-By: PHP/8.5.4
Set-Cookie: security=low; path=/; HttpOnly
Location: login.php

## httpx Results
http://casky-target [302] [Apache/2.4.67 (Debian)] [PHP/8.5.4]

## Nuclei Results
[technology-detection] [info] http://casky-target - Detected Apache/2.4.67
[misconfig-csp] [medium] http://casky-target - Missing CSP headers
[missing-security-headers] [medium] http://casky-target - Missing HSTS, X-Frame-Options

## Analysis
Found Apache 2.4.67 and PHP 8.5.4. Security level set to 'low' (indicating intentionally vulnerable DVWA). Missing security headers is expected. Redirects to login.php.
```

Claude will analyze this and ask for the next step's output.

### Step 7: Claude Synthesizes Findings

After all steps are complete and outputs pasted, Claude synthesizes:

```
✓ Parsed 4 steps
✓ Extracted 12 confirmed findings
✓ Mapped to T1595, T1592, T1190, T1059
✓ Computed risk: HIGH

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 CISO REPORT — Ready to share
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Executive Summary
DVWA (Damn Vulnerable Web Application) contains intentional vulnerabilities
for training purposes. In a production environment, these findings would be
CRITICAL. Immediate remediation required.

Risk Rating: 🔴 HIGH (TEST ENVIRONMENT)

Confirmed Findings
1. Authentication Bypass (T1078)
   Evidence: No login required to access admin panel
   Severity: CRITICAL
   Remediation: Implement authentication controls

2. SQL Injection (T1190)
   Evidence: Unvalidated input in login form
   Severity: CRITICAL
   Remediation: Use parameterized queries

... [more findings]

Affected Assets
- DVWA Web Application (http://casky-target)
- Apache httpd 2.4.67
- PHP 8.5.4

Recommended Actions
1. [P0] Implement authentication and authorization
2. [P0] Patch Apache and PHP
3. [P1] Add security headers (HSTS, CSP, X-Frame-Options)
4. [P2] Enable WAF rules
```

---

## Advanced: Using `--auto` Mode (Power Users)

If you want Claude to autonomously execute skills (old behavior):

```bash
docker exec -it casky-runner casky harness --auto
```

Claude will:
- Spawn subprocess for each step
- Execute commands inside skill-lab automatically
- Collect findings
- Generate report

**Note:** This requires approval for each `docker exec` call in Claude Code sandbox.

---

## Testing with Sample Data

### Example 1: Web App (DVWA)

```bash
docker exec -it casky-runner casky harness
# Choose: g
# Paste evidence about DVWA
# Run the interactive runbook
```

### Example 2: Network Security (NetFlow Analysis)

```bash
# Copy sample data to skill-lab
docker cp docker/samples/netflow_sample.json skill-lab:/tmp/

# In skill-lab, run the agent
cd /root/.casky/plans/YOUR_PLAN_ID/
python scripts/agent.py --flow-file /tmp/netflow_sample.json --output report.json
cat report.json
```

Output shows:
- Port scanning detected (192.168.1.100 → 5 ports on 192.168.1.1)
- Data exfiltration (10.0.0.50 → 5GB transfer to 203.0.113.45)
- Beaconing patterns (172.16.0.25 → periodic C2 connections)

---

## Why Interactive Guided is Default

| Aspect | Interactive Guided | Autonomous (--auto) |
|--------|-------------------|-------------------|
| **Credentials** | You paste in your own shell | Routed through Claude subprocess |
| **API keys** | Stays on your machine | Visible to Claude |
| **Control** | You decide what to run | Claude decides what to run |
| **Security** | Higher (credentials never leave your control) | Weaker (requires sandbox trust) |
| **Use case** | Production investigations | Safe lab testing |

---

## Troubleshooting

**"nmap not available"** → skill-lab Dockerfile builds with nmap. Rebuild:
```bash
docker compose --profile lab-dvwa build --no-cache skill-lab
```

**"Command not found"** → Available tools in skill-lab:
```bash
docker exec skill-lab which nuclei ffuf sqlmap nikto zaproxy httpx nmap curl
```

**DVWA connection fails** → Check MySQL:
```bash
docker compose logs target-db | tail -20
```

**Runbook not printing** → Make sure `CASKY_API_KEY=""` (local mode):
```bash
docker exec -it casky-runner bash -c 'CASKY_API_KEY="" casky harness'
```

---

## Next Steps

1. ✅ Test interactive runbook with DVWA example
2. ✅ Run network security skill with sample NetFlow data
3. ✅ Test `--auto` mode (advanced)
4. Deploy to production with real targets
5. Phase 3: Implement team workspaces + platform sync
