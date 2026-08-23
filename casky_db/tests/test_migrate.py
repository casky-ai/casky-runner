"""Tests for casky_db.migrate — the bespoke migration runner.

Requires a real, reachable Postgres — see casky_db/tests/conftest.py's
docstring for how to point these at one locally. Skips cleanly (not a hard
failure) when DATABASE_URL is unset or the server isn't reachable.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from casky_db.migrate import MigrationError, run_migrations


# All migration files currently in casky_db/migrations/, in order — kept as one
# constant so adding a new migration only requires updating this list, not every
# assertion below individually.
ALL_MIGRATIONS = ["0001_init.sql", "0002_outcomes_and_feedback.sql", "0003_investigation_memories.sql"]


def test_run_migrations_applies_0001_init(test_db_dsn: str):
    applied = run_migrations(test_db_dsn)
    assert applied == ALL_MIGRATIONS

    with psycopg.connect(test_db_dsn, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
                """
            )
            tables = {row["table_name"] for row in cur.fetchall()}

    expected = {
        "investigations",
        "investigation_steps",
        "cve_references",
        "skill_executions",
        "findings",
        "consolidated_reports",
        "runtime_settings",
        "schema_migrations",
        "investigation_feedback",
        "investigation_memories",
    }
    assert expected <= tables


def test_run_migrations_is_idempotent(test_db_dsn: str):
    first = run_migrations(test_db_dsn)
    assert first == ALL_MIGRATIONS

    second = run_migrations(test_db_dsn)
    assert second == []  # nothing left to apply


def test_schema_migrations_reflects_applied_versions(test_db_dsn: str):
    run_migrations(test_db_dsn)

    with psycopg.connect(test_db_dsn, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migrations ORDER BY version")
            versions = [row["version"] for row in cur.fetchall()]

    assert versions == [1, 2, 3]


def test_run_migrations_raises_migration_error_on_bad_dsn():
    with pytest.raises(MigrationError):
        run_migrations("postgresql://bad:bad@127.0.0.1:1/nope")


def test_run_migrations_raises_migration_error_on_empty_dsn():
    with pytest.raises(MigrationError):
        run_migrations("")
