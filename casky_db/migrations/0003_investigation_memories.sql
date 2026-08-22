-- Migration 0003: investigation_memories — organizational memory layer.
--
-- Mirrors the SaaS product's investigation_memories table (supabase migration
-- 120) field-for-field, adapted to this repo's plain-SQL/psycopg style.
-- Deliberately no embedding/vector column yet — same reasoning as the SaaS
-- side: no real embedding generation exists anywhere in this repo either, so
-- a vector-search upgrade stays a documented, deferred v2 (see memory.py).
--
-- "Active" is computed at query time (superseded_by IS NULL AND (expires_at
-- IS NULL OR expires_at > now())) — no status column, no background job.

CREATE TABLE IF NOT EXISTS investigation_memories (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,

    statement               TEXT NOT NULL,
    rationale               TEXT NOT NULL,
    conditions              JSONB NOT NULL DEFAULT '{}',
    applies_to              JSONB NOT NULL DEFAULT '{}',   -- mirrors AdapterEntities shape:
                                                            -- cve_ids[], technique_ids[], ips[], hostnames[]

    confidence              NUMERIC NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    escalation_recommended  BOOLEAN NOT NULL DEFAULT true,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_reinforced_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ,                    -- NULL = permanent
    superseded_by           UUID REFERENCES investigation_memories(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_investigation_memories_source
    ON investigation_memories(source_investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigation_memories_active
    ON investigation_memories(expires_at) WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS idx_investigation_memories_applies_to
    ON investigation_memories USING GIN (applies_to jsonb_path_ops);
