# Casky Box — Investigator's Getting Started Guide

A step-by-step guide for security professionals using Casky Box to conduct structured security investigations.

---

## Overview

Casky Box is a **human-in-the-loop investigation platform** where you guide the AI through security skills, then automatically synthesize findings into a CISO-ready report.

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: Evidence Gathering (You)                                │
│ • Reconnaissance on target (nmap, curl, basic fingerprinting)   │
│ • Paste raw output or upload logs                               │
└────────────────┬────────────────────────────────────────────────┘
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Interactive Skill Execution (You + Claude, Sequential)  │
│ • Claude suggests Skill #1 and the exact command to run        │
│ • You execute: docker exec skill-lab [command]                 │
│ • You paste output back to Claude                              │
│ • Claude analyzes and suggests Skill #2                        │
│ • Repeat for all applicable skills (you're in control)         │
└────────────────┬────────────────────────────────────────────────┘
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3-5: Automated Synthesis (Claude, Parallel)                │
│ • Parse all skill outputs in parallel                           │
│ • Extract confirmed vulnerabilities (proof-based only)         │
│ • Map to MITRE ATT&CK techniques                                │
│ • Generate risk ratings (CRITICAL/HIGH/MEDIUM/LOW)             │
│ • Create remediation actions with effort/impact                │
│ • Synthesize CISO report with executive summary                │
│                                                                 │
│ Live console streaming with progress indicator:                │
│ ✓ Parsing findings (23/42 skills complete)                     │
│ ✓ Mapping MITRE techniques (18/23 techniques)                   │
│ ✓ Computing risk ratings...                                     │
│ ✓ Generating remediation actions...                             │
│ ✓ Synthesizing CISO report...                                   │
└────────────────┬────────────────────────────────────────────────┘
                 ▼
         📋 CISO REPORT
         (Email-ready, severity-sorted findings)
```

---

## Pre-Investigation Setup

### Required: Set your ANTHROPIC_API_KEY

Before starting any investigations, you must configure your Claude API key:

```bash
cd casky-runner

# Create .env.local if not already done
cp .env.example .env.local

# Edit with your editor (nano, vi, VSCode, etc.)
nano .env.local
```

Add this line:
```
ANTHROPIC_API_KEY=sk-ant-v3-YOUR_KEY_HERE
```

Save and close the file. All subsequent `docker compose` commands should use:
```bash
docker compose --env-file .env.local up runner -d
```

Or set it directly:
```bash
export ANTHROPIC_API_KEY=sk-ant-v3-YOUR_KEY_HERE
docker compose up runner -d
```

---

## Step 0: Generate a Plan from Evidence (2-5 minutes, optional)

If you prefer to let the Haiku classifier select skills for you, you can generate an investigation plan automatically:

### 0a. Start the harness in plan generation mode

```bash
docker exec -it casky-runner casky harness
```

The harness will display a welcome screen and ask:
```
Plan Source
  g  Generate new plan from evidence (requires skills library)
  p  Load plan from platform
  l  Load local plan file

Choose [default: l]:
```

Choose `g` to generate a new plan.

### 0b. Paste your evidence

```
Paste your reconnaissance output or describe what you found.
For example:

Target: OWASP Juice Shop
Evidence:
- Server: Node.js / Express
- Framework headers: X-Powered-By: Express
- No WAF detected
- Default credentials suspected
- SQL injection endpoints identified

(Press Ctrl+D when done)
```

The harness will:
1. Call the Haiku classifier with the evidence + 754-skill library summary
2. Automatically select 5-8 relevant skills
3. Load the full SKILL.md documentation for each skill
4. Save the plan as a JSON file in `~/.casky/plans/`
5. Display the plan for your approval

### 0c. Review and select steps

After generation, you'll see a table of selected steps (skills):
```
Investigation Steps — Target Summary
# | Technique                 | Skill                    | Category  | Status
1 | T1595 Active Scanning     | nmap-web-recon           | web-app   | pending
2 | T1595.003 Wordlist Scan   | ffuf-directory-enumerat. | web-app   | pending
...
```

Press `Enter` to run all steps, or enter step numbers (e.g., `1,3,5`) to run specific steps.

---

## Step 1: Evidence Gathering (5 minutes)

### 1a. Start the lab environment

```bash
cd casky-runner

# Choose your target:
docker compose --profile lab-juice-shop up -d    # OWASP Juice Shop (recommended)
# OR
docker compose --profile lab-dvwa up -d          # DVWA (if MySQL is available)

sleep 15
docker ps | grep casky
```

### 1b. Gather preliminary reconnaissance

Run basic recon to understand the target:

```bash
# Get target IP
TARGET_IP=$(docker inspect casky-target | grep -A 8 '"casky-lab"' | grep IPAddress | awk '{print $2}' | tr -d '",')

# Basic recon
docker exec skill-lab sh -c "
echo '=== HTTP Headers ==='; curl -s -I http://$TARGET_IP:3000/
echo '=== Server Info ==='; curl -s -I http://$TARGET_IP:3000/ | grep -iE 'server|x-powered'
echo '=== Home Page ==='; curl -s http://$TARGET_IP:3000/ | head -30
"
```

**Capture the output** — you'll paste this into Claude in Step 2.

---

## Step 2: Interactive Skill Execution (15-30 minutes)

This is where **you and Claude collaborate interactively** to run security skills one at a time.

### 2a. Start Claude as your investigation guide

```bash
docker exec -it casky-runner casky run web-app
```

### 2b. Paste your evidence + investigation prompt

```
# Interactive Security Investigation

## Evidence
[Paste your reconnaissance output here]

## Task
Guide me through a security assessment:

1. **Identify applicable skills** — what techniques apply to this target?
2. **For each skill, provide:**
   - What MITRE techniques it covers
   - Exact command to run in the skill container
   - What to look for in the output
3. **Sequential execution:**
   - I'll run: docker exec skill-lab [your command]
   - Paste output back to you
   - You suggest next skill
4. **After all skills:**
   - Synthesize findings into a structured report
   - Map to MITRE ATT&CK
   - Provide risk ratings + remediation

Let's start: What's Skill #1 and its command?
```

### 2c. Interactive loop (for each skill)

1. **Claude suggests Skill #1** with exact command (e.g., `docker exec skill-lab curl ...`)
2. **You run it** in another terminal:
   ```bash
   docker exec skill-lab [command Claude provided]
   ```
3. **Paste the full output** back to Claude
4. **Claude analyzes** and:
   - Identifies findings (with proof)
   - Flags severity level
   - Suggests **Skill #2** with its command
5. **Repeat** until all skills are complete

### 2d. Example skill progression

Typical order (recon → access → exploit → report):

| Skill | Techniques | Examples |
|-------|-----------|----------|
| **1. Recon** | T1595 Active Scanning | nmap, curl headers, version fingerprinting |
| **2. Content Discovery** | T1595.003 Wordlist Scanning | ffuf, common paths (/admin, /api, etc.) |
| **3. Authentication** | T1110 Brute Force, T1078 Valid Accounts | default creds, weak passwords |
| **4. SQL Injection** | T1190 Exploit Public-Facing App | sqlmap, manual testing |
| **5. Command Injection** | T1059 Command & Scripting | payload injection, RCE testing |
| **6. File Upload** | T1505.003 Web Shell | upload bypass, shell execution |
| **7. XSS** | T1059.007 JavaScript | reflected, stored, DOM-based XSS |
| **8. CSRF** | T1539 Steal Session Cookie | token bypass, forgery |
| **9. Session** | T1185 Browser Session | weak session IDs, fixation |

### 2e. When to stop

You control when to stop. Options:
- **Stop after finding critical vulnerabilities** (e.g., after Skill #2 finds unauth admin panel)
- **Continue through all skills** for comprehensive assessment
- **Deep-dive on one finding** (e.g., run 5 SQLi variations if the first one succeeds)

---

## Step 3-5: Automated Synthesis (5 minutes)

Once you approve the skill outputs, Claude **automatically**:

### 3. Parse findings
- Extract confirmed vulnerabilities (proof-based only)
- Discard unconfirmed claims
- Live console shows progress:
  ```
  ✓ Parsed Skill #1 (Recon)
  ✓ Parsed Skill #2 (Content Discovery)
  ✓ Parsed Skill #3 (Authentication)
  ...
  ✓ 8/9 skills parsed
  ```

### 4. Map to MITRE ATT&CK
- Assign T-codes per finding
- Group by technique
- Live console:
  ```
  ✓ Mapped T1595 (Active Scanning)
  ✓ Mapped T1190 (Exploit Public-Facing App)
  ✓ Mapped T1087 (Account Discovery)
  ...
  ✓ 23 techniques mapped
  ```

### 5. Synthesize CISO Report
- **Executive Summary** (2-3 sentences for the board)
- **Risk Rating** (CRITICAL/HIGH/MEDIUM/LOW, color-coded)
- **Confirmed Vulnerabilities** (table: severity, title, finding, proof, MITRE)
- **Remediation Actions** (table: priority, action, effort, impact)
- **Immediate Next Steps** (what to do in the next 24h)
- **Affected Assets** (domains, IPs, users, services)

Live console:
```
✓ Generating executive summary...
✓ Computing risk rating: CRITICAL
✓ Building vulnerability table (8 findings)...
✓ Prioritizing remediation actions...
✓ Final CISO report ready!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 CISO REPORT — Ready to share
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Current Gaps & Future Improvements

### What's working now ✅
- Multi-target support (Juice Shop, DVWA, custom)
- Interactive skill-by-skill guidance (Claude suggests commands)
- Manual evidence pasting and output analysis
- Findings extraction with MITRE mapping

### What needs improvement 🔧

| Gap | Impact | Priority |
|-----|--------|----------|
| **No saved investigation state** | Can't resume if connection drops | HIGH |
| **Manual output pasting** | Tedious, error-prone | HIGH |
| **No live console streaming** | Can't see progress during synthesis | HIGH |
| **No CISO report template** | Hand-crafted reports lack consistency | MEDIUM |
| **No skill library** | Commands are ad-hoc per target | MEDIUM |
| **No evidence file upload** | Only paste-based evidence | MEDIUM |
| **No findings database** | Can't track findings across investigations | LOW |

### Recommended improvements (Roadmap)

**Phase 1 (v1.1 MVP):**
- [ ] Evidence file upload support (.log, .json, .csv, .xml)
- [ ] Skill library with per-target templates
- [ ] Live console progress during Steps 3-5
- [ ] CISO report template (email-ready HTML)
- [ ] Save investigation session (resume capability)

**Phase 2 (v1.2):**
- [ ] Integration with Casky platform API (push findings)
- [ ] Multi-user workspaces (team investigations)
- [ ] Finding deduplication (same vuln, multiple skills)
- [ ] Automated retest (re-run skills to confirm fixes)

**Phase 3 (v1.3+):**
- [ ] Evidence library (pre-curated logs for practice)
- [ ] Skill marketplace (community-submitted skills)
- [ ] Integration with external tools (Burp API, Nessus API)
- [ ] Scheduled investigations (cron-based)

---

## Example: Full Investigation (Juice Shop)

### Evidence gathering
```
Reconnaissance output:
- Server: Node.js-based SPA
- Admin panel accessible at /admin (no auth)
- CORS: Access-Control-Allow-Origin: *
- CSP: Missing
```

### Interactive skills
```
Skill #1: Recon
$ docker exec skill-lab curl -sI http://172.19.0.2:3000/
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
...

[Claude analyzes] Finding: CORS overly permissive (HIGH)

Skill #2: Content Discovery
$ docker exec skill-lab sh -c "for path in admin api/admin profile; do 
  echo -n \"$path: \"; curl -o /dev/null -w \"%{http_code}\" http://172.19.0.2:3000/$path
done"
admin: 200
api/admin: 500
profile: 500

[Claude analyzes] Finding: Unauthenticated admin panel (CRITICAL)

Skill #3: Authentication
[... continues until critical findings confirmed ...]
```

### Automated synthesis
```
✓ Parsed 3 skills
✓ Extracted 2 confirmed findings
✓ Mapped to T1087, T1657, T1190
✓ Computed risk: CRITICAL

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 CISO REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Executive Summary
The target application contains 2 critical vulnerabilities...

Risk Rating: 🔴 CRITICAL

Confirmed Findings
1. Unauthenticated Admin Panel (T1087)
   Evidence: HTTP 200 on /admin without login
   
2. CORS Overly Permissive (T1657)
   Evidence: Access-Control-Allow-Origin: * in all responses

Remediation Actions
P0: Implement authentication on /admin endpoints
P1: Restrict CORS to specific origins

Affected Assets
- Juice Shop application (172.19.0.2:3000)
```

---

## Troubleshooting

**Q: How do I know which skills to run?**
A: Claude will suggest them based on your evidence. Or follow the typical progression (Recon → Content Discovery → Auth → Exploit).

**Q: Can I skip skills?**
A: Yes! You control the flow. If you confirm a CRITICAL vulnerability early, you can stop.

**Q: What if a command fails?**
A: Paste the error back to Claude. It will adjust the command (e.g., different API endpoint, different payload encoding).

**Q: How do I save the investigation?**
A: Currently: screenshot the report. Roadmap: SQLite database to persist findings.

---

## Next Steps

1. **Start an investigation** using the guide above
2. **Report issues** on GitHub (missing commands, unclear steps, etc.)
3. **Suggest skills** you'd like added to the library
4. **Share findings** — we're collecting evidence on what works best for each target type

---

*Casky Box v1.1 — Investigation platform for security professionals*
