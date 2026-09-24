# ASOC Backend

FastAPI application implementing Clean Architecture for the ASOC platform.

> Placeholder only — the FastAPI app instance, routers, and business logic
> are added starting Part 2 — Backend Foundation. `requirements.txt`
> intentionally lists no installable dependencies yet.

## Layering

```
api/            → Presentation layer (routes only)
services/       → Application layer (business logic/orchestration)
repositories/   → Data-access layer (queries only)
models/         → Persistence layer (ORM table definitions)
schemas/        → API boundary DTOs (Pydantic)
```

Domain modules (`sigma/`, `mitre/`, `risk/`, `alerts/`, `incidents/`,
`analytics/`, `reports/`, `notifications/`, `users/`, `logs/`, `dashboard/`,
`ai/`) each own one bounded concern and are consumed by `services/`.

See each package's `__init__.py` docstring for its exact, non-overlapping
responsibility.
