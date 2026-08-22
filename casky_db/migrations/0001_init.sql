-- Casky Box Postgres schema — Part B (persistence layer).
--
-- investigations / investigation_steps / cve_references mirror harness.py's
-- Plan / Step / CveEnrichment dataclasses (see casky_db/store.py). skill_executions
-- and findings replace the file-based /var/casky/reports/<plan_id>/<run_id>.json
-- shape written by _ReportHandler.do_POST. consolidated_reports replaces
-- /var/casky/reports/<plan_id>/consolidated.json (the human-readable REPORT.md /
-- consolidated.json artifacts on disk are NOT removed — this is an additive,
-- queryable store, not a replacement for the transparency artifacts).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS investigations (
    id              UUID PRIMARY KEY,
    domain          TEXT,
    evidence_text   TEXT,
    status          TEXT NOT NULL DEFAULT 'draft',
    confidence      NUMERIC,
    evidence_gaps   TEXT[] NOT NULL DEFAULT '{}',
    agent_used      TEXT,
    model_used      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS investigation_steps (
    id                  UUID PRIMARY KEY,
    investigation_id    UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    skill_slug          TEXT,
    skill_category      TEXT,
    skill_document      TEXT,
    technique_id        TEXT,
    technique_name      TEXT,
    rationale           TEXT,
    evidence_focus      TEXT,
    step_order          INT,
    status              TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS cve_references (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id    UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    cve_id              TEXT NOT NULL,
    cvss_score          NUMERIC,
    cvss_severity       TEXT,
    is_kev              BOOLEAN NOT NULL DEFAULT false,
    technique_ids       TEXT[] NOT NULL DEFAULT '{}',
    skill_ids           TEXT[] NOT NULL DEFAULT '{}',
    ai_analysis         TEXT
);

CREATE TABLE IF NOT EXISTS skill_executions (
    id                  UUID PRIMARY KEY,
    investigation_id    UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    step_id             UUID REFERENCES investigation_steps(id) ON DELETE SET NULL,
    skill_slug          TEXT,
    agent_used          TEXT,
    model_used          TEXT,
    exit_code           INT,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    output              TEXT,
    score_pct           INT
);

CREATE TABLE IF NOT EXISTS findings (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id        UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    skill_execution_id      UUID REFERENCES skill_executions(id) ON DELETE SET NULL,
    title                   TEXT NOT NULL,
    description             TEXT,
    severity                TEXT NOT NULL DEFAULT 'informational'
                                CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    raw_evidence            TEXT,
    mitre_technique_id      TEXT,
    affected_asset          TEXT,
    remediation             TEXT,
    status                  TEXT NOT NULL DEFAULT 'open'
                                CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS consolidated_reports (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id    UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    summary             TEXT,
    risk_rating         TEXT,
    markdown            TEXT,
    report_json         JSONB
);

CREATE TABLE IF NOT EXISTS runtime_settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_investigation_steps_investigation_id ON investigation_steps(investigation_id);
CREATE INDEX IF NOT EXISTS idx_findings_investigation_id ON findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_cve_references_investigation_id ON cve_references(investigation_id);
CREATE INDEX IF NOT EXISTS idx_cve_references_cve_id ON cve_references(cve_id);
CREATE INDEX IF NOT EXISTS idx_skill_executions_investigation_id ON skill_executions(investigation_id);
