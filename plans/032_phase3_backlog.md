# Phase 3 Backlog — Enhanced Investigations, Persistence & Marketplace

**Created:** 2026-06-12  
**Status:** Planning  
**Scope:** Post-Phase 2 (CVE enrichment complete)

This document captures all Phase 3 opportunities to avoid losing ideas. These are **not** committed features — candidates for prioritization.

---

## Backlog Categories

### Category A: Enhanced Plan Execution (Streaming & Evidence)

**A1: Live Dashboard Streaming During Plan Generation**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: UX — users see Phase A-D progress in real-time
- Details:
  - Stream Phase progress to stdout/websocket (Phase A: 34% → 50% → 100%)
  - Show entities extracted per phase
  - Show CVE enrichment count
  - Show playbook matches in real-time
  - Final dashboard with plan summary before approval
- Implementation:
  - Add progress callbacks to extract_entities, enrich_with_cve_mcp, etc.
  - Use rich.progress for live bars
  - Or websocket to web UI for real-time updates

**A2: Evidence File Upload Support**
- Status: 🔲 Backlog
- Effort: Medium (2 days)
- Impact: UX — no more copy-paste, drag & drop files
- Supported formats: .log, .json, .csv, .txt, .xml, .pcap
- Details:
  - Add file upload handler to casky harness
  - Parse common log formats (CloudTrail, syslog, nginx, etc.)
  - Auto-detect file type and extract key fields
  - Combine multiple files into unified evidence text
- Implementation:
  - File size limit: 50 MB per file, 200 MB total
  - MIME type validation
  - Auto-parser for CloudTrail/syslog/nginx logs
  - Fallback: treat unknown formats as raw text

**A3: Multi-Target Parallel Investigations**
- Status: 🔲 Backlog
- Effort: High (5 days)
- Impact: Capability — test multiple targets (DVWA + Juice Shop) in one run
- Details:
  - Select multiple targets before investigation starts
  - Generate separate plan per target
  - Run all plans in parallel (respecting concurrency limit)
  - Aggregate findings across targets
  - Unified CISO report with cross-target risk
- Implementation:
  - Extend docker-compose to support N targets
  - CaskyHarness accepts list[Plan] instead of single Plan
  - Results aggregation: dedup similar findings across targets
  - Risk computation: cross-target cascade (e.g., shared credential = higher risk)

**A4: Automated Retest (Verification & Regression)**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: Capability — re-run investigation to verify fixes
- Details:
  - Save baseline plan + findings
  - Schedule retest for T+7, T+30 days
  - Run same skills against target again
  - Compare results: finding resolved? New findings?
  - Auto-remediation validation
- Implementation:
  - Store baseline (plan_id, findings list, timestamps)
  - Retest plan: use same skill selection, same evidence format
  - Diff engine: old findings vs new findings
  - Report: remediation_status, regression_risk, new_findings
  - Integration: casky schedule retest <plan-id> --days 7

---

### Category B: Team & Persistence (State, History, Access Control)

**B1: Investigation Session Persistence**
- Status: 🔲 Backlog
- Effort: High (4 days)
- Impact: Capability — survive connection drops, resume investigations
- Details:
  - Save investigation state after each phase
  - Checkpoint after each skill execution
  - Allow resume from last checkpoint
  - Preserve all intermediate outputs (entities, enrichment, etc.)
- Storage:
  - SQLite for local mode (file: ~/.casky/investigations.db)
  - Supabase `investigation_sessions` table for platform mode
- Implementation:
  - Schema: session_id, plan_id, phase_completed, last_checkpoint_step, status, created_at, updated_at
  - On interrupt (Ctrl+C): save state, prompt "Resume? y/n"
  - On resume: load state, continue from last step
  - Cleanup: auto-delete sessions older than 30 days

**B2: Investigation History & Replay**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: UX — see past investigations, replay same evidence
- Details:
  - Index all completed investigations
  - Search by date, target, findings count, risk rating
  - Replay: re-run same plan against updated target
  - Compare: baseline findings vs current findings
- Commands:
  - `casky history` — list past investigations
  - `casky history --search "SQL injection"` — find by finding title
  - `casky replay <investigation-id>` — re-run same plan
- Implementation:
  - Supabase table: investigations (id, plan_id, target, domain, risk_rating, findings_count, created_at)
  - Full-text search on findings (title + description)
  - Replay: load investigation by ID, re-execute plan with current code

**B3: Team Workspaces & Role-Based Access**
- Status: 🔲 Backlog
- Effort: High (5 days)
- Impact: Capability — multi-user, team investigations with audit trail
- Details:
  - Workspace: collection of investigations + team members
  - Roles: admin (create/delete workspace), investigator (run investigations), viewer (read-only)
  - Audit log: who ran what, when, what changed
  - Shared findings: one investigator's finding visible to all workspace members
- Implementation:
  - Supabase tables: workspaces, workspace_members, workspace_audit_log
  - Auth: workspace_id check in all harness APIs
  - Harness runs under workspace context (CASKY_WORKSPACE_ID env var)
  - UI: workspace selector before investigation starts

**B4: Finding Deduplication & Merging**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: Quality — don't report same vuln multiple times across skills
- Details:
  - After all skills execute, cluster similar findings
  - Same CVE detected by 2 skills = 1 finding with 2 sources
  - Merge confidence: boost confidence if multiple skills confirm same vuln
  - De-dup rules: by CVE ID, title similarity, CWE, CVSS
- Implementation:
  - Similarity function: Levenshtein distance on title + CWE match + CVSS proximity
  - Clustering: group findings by similarity score > 0.8
  - Merge strategy: keep highest confidence, combine evidence from all sources
  - Output: findings_merged list with source_skill_ids array per finding

---

### Category C: Skill Marketplace (Discovery, Community, Versioning)

**C1: Community Skill Submission & Rating**
- Status: 🔲 Backlog
- Effort: High (6 days)
- Impact: Ecosystem — crowdsource skill creation
- Details:
  - Skill authors submit via `casky submit-skill --path ./my-skill/`
  - Community votes: helpful / not-helpful / report
  - Rating system: avg score, review count, trending
  - Featured skills: top-rated this month
- Implementation:
  - Supabase table: community_skills (id, author_id, name, description, rating, review_count, created_at)
  - Submission form: skill name, description, category (domain, subdomain), preview
  - Review pipeline: 2 admins approve before public
  - Rating: 1-5 stars, optional review text

**C2: Skill Discovery Marketplace**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: UX — browse, search, preview skills before running
- Details:
  - Marketplace UI: search, filter by domain/subdomain/rating
  - Skill cards: name, description, rating, use_count, author
  - Preview: show first 20 lines of SKILL.md
  - One-click install: add to local library or use from platform
- Commands:
  - `casky marketplace search "sql injection"`
  - `casky marketplace browse --domain web-app`
  - `casky marketplace install <skill-id>`
- Implementation:
  - Platform UI: React marketplace page (ghcr.io/casky-ai/marketplace)
  - CLI: add marketplace commands to casky.sh
  - Backend: fetch from community_skills table, sort by rating/use_count

**C3: Custom Skill Integration Hooks**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: Capability — users define custom investigation hooks
- Details:
  - Pre-investigation hook: validate evidence format before plan generation
  - Post-investigation hook: auto-remediation or ticket creation
  - Custom parsers: parse proprietary log formats into standard evidence
- Examples:
  - Pre: check that evidence contains CVE IDs (fail if not)
  - Post: create Jira ticket with findings if risk_rating >= HIGH
  - Parser: convert Splunk export to standard log format
- Implementation:
  - Hook directory: ~/.casky/hooks/ with standard interfaces
  - Hook types: pre_investigation, post_investigation, custom_parser
  - Documentation: hook interface spec + examples
  - Error handling: hook failure logs warning but doesn't block investigation

**C4: Skill Versioning & Dependency Tracking**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: Reliability — skills can declare dependencies, versions pin correctly
- Details:
  - SKILL.md metadata: version, depends_on, min_casky_version
  - Dependency resolution: install transitive dependencies
  - Version pinning: investigations record skill versions used
  - Upgrade path: warn if skill version differs from baseline
- Implementation:
  - Schema: skill versions in index.json
  - Dependency resolver: topological sort, detect cycles
  - Storage: investigation metadata includes skill_versions array
  - Check: on replay, alert if skills have been updated

---

### Category D: Advanced Orchestration (Intelligent Execution)

**D1: Intelligent Step Sequencing (Dependency-Aware Execution)**
- Status: 🔲 Backlog
- Effort: High (4 days)
- Impact: Quality — run dependent skills in correct order
- Details:
  - Skills declare prerequisites (e.g., "recon before exploitation")
  - Classifier respects prerequisites when selecting skills
  - Execution order: topological sort, not arbitrary
  - Fallback: if recon fails, auto-skip exploitation
- Implementation:
  - SKILL.md metadata: prerequisites: ["nmap-recon", "port-scanning"]
  - Dependency graph: build from all selected skills
  - Execution: topo-sort, detect cycles, validate prerequisites pass
  - AgentWorker: check status of prerequisites before running step

**D2: Parallel Execution with Result Aggregation**
- Status: 🔲 Backlog
- Effort: Medium (2 days)
- Impact: Performance — run independent skills in parallel (already done, enhance)
- Details:
  - Current: asyncio semaphore limits to N parallel workers
  - Enhance: smart batching based on skill dependencies
  - If skills have no prereqs: run all at once (up to limit)
  - If dependent: run batch, wait, run next batch
  - Aggregation: merge findings after each batch
- Implementation:
  - Build DAG from skill prerequisites
  - Layer detection: skills with no deps = layer 1, etc.
  - Execute layers sequentially, skills within layer parallel
  - Result aggregation: after each layer, check for early-exit conditions

**D3: Skill Fallback Chains**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: Reliability — if primary skill fails, try alternative
- Details:
  - Metadata: fallback_skills: ["tool-b-recon", "tool-c-recon"]
  - If tool-a-recon returns 0 findings, try tool-b-recon with same evidence
  - Preserve all outputs: report which tools were tried
- Implementation:
  - SKILL.md metadata: fallback_skills array
  - AgentWorker: on zero findings, check fallback_skills
  - Retry loop: try primary, then each fallback in order
  - Report: include attempted_skills array

**D4: Cost Optimization (Speed-First Skill Selection)**
- Status: 🔲 Backlog
- Effort: High (4 days)
- Impact: Performance — minimize investigation runtime
- Details:
  - Skills have metadata: avg_runtime, cpu_cost, memory_cost
  - Classifier: prefer skills with low runtime for same coverage
  - Trade-off: can select slower-but-more-thorough skill if user requests
  - Explain: "This plan will take ~15 min (quick) vs 45 min (thorough)"
- Implementation:
  - SKILL.md metadata: estimated_runtime_seconds, resource_profile
  - Classifier prompt: include runtime info
  - Plan metadata: total_estimated_runtime, confidence, thorough_flag
  - User choice: "quick scan" vs "comprehensive assessment"

---

### Category E: Integration & Automation (External Tools, Workflows)

**E1: Burp Suite API Integration**
- Status: 🔲 Backlog
- Effort: High (4 days)
- Impact: Capability — pull findings from Burp into investigation
- Details:
  - Connect to Burp Pro API
  - Import active/passive scan results
  - Map Burp findings to casky findings
  - Verify: casky confirms Burp findings with additional skills
- Implementation:
  - Burp API client: authenticate, fetch issues
  - Mapper: Burp issue type → MITRE technique + severity
  - Integration: optional evidence source, runs before plan generation

**E2: Nessus API Integration**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: Capability — pull vulnerability scan results
- Details:
  - Connect to Nessus API
  - Fetch latest scan results for target
  - Extract CVEs, severity, proof text
  - Feed to casky enrichment pipeline
- Implementation:
  - Nessus client: authenticate, list/fetch scans
  - Parser: extract CVEs and plugin text
  - Integration: fetch_nessus_vulns() called in Phase B

**E3: Slack Integration (Findings Notifications)**
- Status: 🔲 Backlog
- Effort: Medium (2 days)
- Impact: UX — post findings to Slack as they arrive
- Details:
  - On investigation complete, POST findings to Slack channel
  - Rich formatting: severity badges, MITRE links, remediation
  - Threaded: one message per finding
  - Configurable: risk_rating threshold before posting
- Implementation:
  - Env var: SLACK_WEBHOOK_URL
  - Post on investigation complete or real-time per finding
  - Format: JSON to Slack Block Kit for rich messages

**E4: GitHub/GitLab Issue Automation**
- Status: 🔲 Backlog
- Effort: Medium (3 days)
- Impact: Capability — auto-create issues for findings
- Details:
  - On investigation complete, create one GitHub issue per finding
  - Issue title: "[CRITICAL] SQL Injection in /api/users"
  - Issue body: finding description + remediation steps + links to MITRE/CWE
  - Labels: severity, technique ID, auto-assign to team
- Implementation:
  - GitHub API client: authenticate, create issues
  - Template: issue title/body/labels
  - Env vars: GITHUB_REPO, GITHUB_TOKEN, GITHUB_LABELS_MAPPING

---

### Category F: Advanced Analytics (Patterns, Trends, Intelligence)

**F1: Finding Patterns & Risk Trends**
- Status: 🔲 Backlog
- Effort: High (5 days)
- Impact: Intelligence — detect patterns in findings over time
- Details:
  - Trend dashboard: show findings per domain over time
  - Pattern detection: same CVE reappearing = patch regression?
  - Risk trajectory: is overall risk trending up or down?
  - Correlation: skills that often find same types of vulns
- Implementation:
  - Supabase table: findings_by_day (date, domain, finding_count, avg_severity)
  - Analytics: daily aggregation job
  - Dashboard: time-series graphs, heat maps

**F2: Threat Intelligence Feed Integration**
- Status: 🔲 Backlog
- Effort: High (4 days)
- Impact: Intelligence — enrich investigations with threat context
- Details:
  - Subscribe to threat feeds: CVE alerts, ransomware trends, TTPs
  - On plan generation: check if detected CVEs are currently exploited
  - Alert: "CVE-2024-3400 is actively exploited (last 7 days, 234 reports)"
  - Playbook matching: use threat context to prioritize techniques
- Implementation:
  - Feed integration: AlienVault OTX, GreyNoise, Censys
  - Supabase table: threat_intel_cache (cve_id, active_exploitation, last_seen, source)
  - Daily sync: update threat status for known CVEs
  - Classifier prompt: include threat context

**F3: Automated Reporting & Executive Briefings**
- Status: 🔲 Backlog
- Effort: High (4 days)
- Impact: UX — generate formatted reports (PDF, Word, HTML)
- Details:
  - CISO report format: executive summary, risk rating, top findings, remediation roadmap
  - Optional: include trend charts, affected assets map, threat landscape
  - Export formats: PDF (styled), Word (.docx), HTML (interactive), Markdown
  - Scheduling: auto-generate weekly reports for team
- Implementation:
  - Template engine: Jinja2 for report generation
  - PDF: weasyprint or wkhtmltopdf
  - Word: python-docx
  - Scheduling: casky schedule report --frequency weekly --team-email security@company.com

---

## Phase 3 Prioritization Matrix

### Tier 1: High-Impact, Medium-Effort (Do First)

- A1: Live Dashboard Streaming
- A2: Evidence File Upload
- B1: Investigation Session Persistence
- D1: Intelligent Step Sequencing
- F1: Finding Patterns & Risk Trends

### Tier 2: Medium-Impact, Medium-Effort (Do Second)

- A4: Automated Retest
- B2: Investigation History & Replay
- B4: Finding Deduplication
- D3: Skill Fallback Chains
- E3: Slack Integration

### Tier 3: High-Impact, High-Effort (Do Later)

- A3: Multi-Target Parallel Investigations
- B3: Team Workspaces
- C1-C4: Skill Marketplace (full suite)
- D2: Advanced Parallel Orchestration
- D4: Cost Optimization
- E1-E2: Burp/Nessus Integration
- F2-F3: Advanced Analytics & Reporting

---

## Implementation Sequencing

**Phase 3a (2 weeks): Streaming & Persistence**
1. A1: Live Dashboard (foundation for other improvements)
2. B1: Session Persistence (unblock resume capability)
3. A2: File Upload (reduce copy-paste friction)

**Phase 3b (2 weeks): Reliability & Dedup**
1. D1: Dependency-Aware Sequencing (enable correct execution order)
2. B4: Finding Deduplication (reduce noise in reports)
3. D3: Fallback Chains (improve resilience)

**Phase 3c (2 weeks): Team & History**
1. B2: History & Replay (enable learning from past investigations)
2. E3: Slack Integration (team notifications)
3. B3: Team Workspaces (enable collaboration)

**Phase 3d (3 weeks): Marketplace & Intelligence**
1. C1-C2: Marketplace (enable community skills)
2. F1: Trend Analytics (reveal patterns)
3. F2: Threat Intel (enrich context)

---

## Success Metrics

**Phase 3 completion criteria:**
- [ ] All Tier 1 features complete and tested
- [ ] At least 2 Tier 2 features complete
- [ ] Investigation runtime < 5 min (average)
- [ ] Session resume capability: zero lost work on connection drop
- [ ] Community skills: 10+ submitted, 5+ approved
- [ ] Team workspace: 3+ teams active, 20+ investigations
- [ ] Finding dedup: reduce noise by 30% (duplicate findings per investigation)

---

## Notes

- This backlog is **not** a commitment — items may be deprioritized or reprioritized based on user feedback
- Each item should have its own implementation plan before development starts
- Effort estimates assume 1 developer, may vary with team size
- Dependencies exist (e.g., Session Persistence needed before History & Replay)
- Keep communicating with users about which features matter most

---

**Next Step:** After Phase 2 Docker tests pass, revisit this backlog and select Tier 1 features for Phase 3 sprint planning.
