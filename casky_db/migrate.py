#!/usr/bin/env python3
"""Tiny, bespoke migration runner for casky_db.

No framework (alembic, etc.) — matches this repo's existing minimalism.
Applies every ``.sql`` file in ``casky_db/migrations/`` whose numeric prefix
(``0001_init.sql`` -> ``1``) isn't yet recorded in ``schema_migrations``, in
ascending order, each inside its own transaction. Idempotent: running it
twice applies nothing the second time.

CLI usage:
    python3 -m casky_db.migrate                 # uses $DATABASE_URL
    python3 -m casky_db.migrate postgresql://... # explicit DSN

Wired into casky.sh as `casky db migrate` (see casky.sh's `db` subcommand).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

_VERSION_RE = re.compile(r"^(\d+)_")


class MigrationError(Exception):
    """Raised when a migration file can't be applied (connection failure,
    malformed filename, or a SQL error inside one migration's transaction)."""


def _discover_migrations() -> list[tuple[int, Path]]:
    """Returns (version, path) pairs sorted by version, for every
    ``<digits>_*.sql`` file directly under MIGRATIONS_DIR."""
    found: list[tuple[int, Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = _VERSION_RE.match(path.name)
        if not m:
            continue  # not a numbered migration file — ignore, don't error
        found.append((int(m.group(1)), path))
    found.sort(key=lambda t: t[0])
    return found


def run_migrations(database_url: str) -> list[str]:
    """Applies every not-yet-applied migration in casky_db/migrations/.

    Returns the list of migration filenames actually applied this call (empty
    if the database was already up to date). Raises MigrationError on a
    connection failure or a SQL error — callers decide whether that's fatal.
    """
    if not database_url:
        raise MigrationError("DATABASE_URL is empty — nothing to migrate against")

    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - environment issue, not logic
        raise MigrationError(f"psycopg is not installed: {exc}") from exc

    try:
        conn = psycopg.connect(database_url, autocommit=False)
    except Exception as exc:
        raise MigrationError(f"could not connect to {database_url!r}: {exc}") from exc

    applied: list[str] = []
    try:
        # NOTE: conn.transaction() (a Transaction, not the Connection itself)
        # is used for each commit boundary below — NOT `with conn:`, which in
        # psycopg3 closes the underlying connection on exit (unlike psycopg2,
        # where it only commits/rolls back). Using `with conn:` here would
        # close the connection after the very first block, breaking every
        # migration attempted after it.
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version     INT PRIMARY KEY,
                        applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                    """
                )
                cur.execute("SELECT version FROM schema_migrations")
                already_applied = {row[0] for row in cur.fetchall()}

        for version, path in _discover_migrations():
            if version in already_applied:
                continue
            sql = path.read_text()
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(sql)
                        cur.execute(
                            "INSERT INTO schema_migrations (version) VALUES (%s)",
                            (version,),
                        )
                applied.append(path.name)
            except Exception as exc:
                raise MigrationError(f"migration {path.name} failed: {exc}") from exc
    finally:
        conn.close()

    return applied


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    database_url = argv[0] if argv else os.environ.get("DATABASE_URL", "")

    try:
        applied = run_migrations(database_url)
    except MigrationError as exc:
        print(f"[casky_db.migrate] {exc}", file=sys.stderr)
        return 1

    if applied:
        print(f"[casky_db.migrate] applied {len(applied)} migration(s): {', '.join(applied)}")
    else:
        print("[casky_db.migrate] up to date — nothing to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
