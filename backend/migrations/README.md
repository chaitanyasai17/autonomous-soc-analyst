# Migrations

Alembic migration environment for ASOC, configured in Part 2 — Backend Foundation.

- `env.py` — wired to `app.config.get_settings()` for the DB URL and
  `app.database.Base` for target metadata. No models are registered yet.
- `script.py.mako` — template used when generating new revision files.
- `versions/` — empty. No migrations have been generated yet; the first
  migration will be created in Part 3 — Database Foundation once ORM
  models exist.

## Manual commands (Part 3+, not run yet)

```bash
cd backend
alembic revision --autogenerate -m "create initial tables"
alembic upgrade head
```
