-- Migration 0002: outcome + per-step feedback capture.
--
-- Casky Box had no equivalent of the SaaS product's outcome_summary /
-- confirmed_techniques / per-step rating before this migration — nothing to
-- mine organizational memory FROM. This is the prerequisite for 0003's
-- investigation_memories table, mirroring the SaaS side's investigation_plans
-- outcome columns + investigation_plan_feedback table field-for-field so the
-- extraction prompt design can be shared conceptually across both products.

ALTER TABLE investigations
    ADD COLUMN IF NOT EXISTS outcome_summary        TEXT,
    ADD COLUMN IF NOT EXISTS confirmed_technique_ids TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS investigation_feedback (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id    UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    step_order          INT,                 -- NULL = plan-level; INT = specific step
    skill_slug          TEXT,
    rating              TEXT NOT NULL
                            CHECK (rating IN ('useful', 'not_useful', 'wrong_skill', 'missing_skill')),
    actual_finding      TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_investigation_feedback_investigation_id
    ON investigation_feedback(investigation_id);
