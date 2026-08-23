"""Postgres persistence layer for the Casky Box runner.

Replaces the file-based investigation-plan/report storage
(``~/.casky/plans/*.json``, ``/var/casky/reports/<plan_id>/*.json``) with a
queryable Postgres store, wired into harness.py. No ORM — plain SQL,
hand-written repository functions in store.py, matching this repo's existing
minimalism.

Modules:
    migrations/     Plain numbered .sql files, applied by migrate.py.
    migrate.py      Tiny migration runner (DATABASE_URL -> schema_migrations).
    store.py        Repository functions (create_investigation, record_findings, ...).
    json_import.py  One-time importer for the pre-Postgres on-disk JSON shape.

DATABASE_URL is optional. Every call site in harness.py falls back to the
pre-existing JSON-file storage when it's unset or the database is
unreachable — local mode without Postgres keeps working exactly as before.
"""
