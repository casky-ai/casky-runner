"""Shared fixtures for casky_db's Postgres-backed tests.

These tests need a real, reachable Postgres server — set DATABASE_URL to one
before running them, e.g.:

    docker compose up -d db
    export DATABASE_URL=postgresql://casky:${DB_PASSWORD:-casky}@localhost:5432/casky
    pytest casky_db/tests/ -v

(The bundled docker-compose.yml `db` service does not publish a host port by
default — add a `ports: ["5432:5432"]` override, or run the tests from
inside a container on the `casky-internal` network, to reach it from the
host.)

Every test in this package runs against its own freshly created, empty
database (created via CREATE DATABASE against the server DATABASE_URL
points at, then dropped afterward) so tests never interfere with each
other or with a real casky database. This requires the connecting role to
have CREATEDB privilege — true for the default `casky` role in the bundled
postgres:16-alpine image.

If DATABASE_URL is unset, or the server it points at isn't reachable, every
test in this package is skipped (not failed) — this suite must not break a
`pytest casky_db/tests/` run in an environment with no Docker/Postgres
available.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip("psycopg", reason="psycopg is not installed")

import psycopg  # noqa: E402


def _base_dsn() -> str | None:
    return os.environ.get("DATABASE_URL") or None


def _server_reachable(dsn: str) -> bool:
    try:
        conn = psycopg.connect(dsn, connect_timeout=3)
        conn.close()
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def base_dsn() -> str:
    dsn = _base_dsn()
    if not dsn:
        pytest.skip(
            "DATABASE_URL not set — skipping casky_db Postgres-backed tests "
            "(see casky_db/tests/conftest.py docstring for how to run them locally)"
        )
    if not _server_reachable(dsn):
        pytest.skip(f"Postgres at DATABASE_URL is not reachable — skipping ({dsn!r})")
    return dsn


def _replace_db_name(dsn: str, new_name: str) -> str:
    """Swaps the path component (database name) of a postgresql:// DSN."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{new_name}", parts.query, parts.fragment))


@pytest.fixture
def test_db_dsn(base_dsn: str):
    """Creates a fresh, empty database on the same server as `base_dsn`,
    yields a DSN pointing at it, and drops it afterward."""
    db_name = f"casky_test_{uuid.uuid4().hex[:12]}"
    admin_dsn = _replace_db_name(base_dsn, "postgres")

    admin_conn = psycopg.connect(admin_dsn, autocommit=True)
    try:
        admin_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        pass  # keep admin_conn open for the teardown DROP below

    dsn = _replace_db_name(base_dsn, db_name)
    try:
        yield dsn
    finally:
        # Terminate any lingering connections before dropping — a leaked
        # connection from a failed test would otherwise make DROP DATABASE
        # hang/fail.
        try:
            admin_conn.execute(
                """
                SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                WHERE datname = %s AND pid <> pg_backend_pid()
                """,
                (db_name,),
            )
            admin_conn.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            admin_conn.close()
