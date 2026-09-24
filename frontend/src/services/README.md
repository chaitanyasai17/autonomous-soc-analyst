# services/

Frontend business/application logic: calls one or more `api/` functions,
applies transformations, caching hints, and error normalization, and exposes
clean data to `features/` and `pages/` (typically via TanStack Query hooks
defined in `hooks/`).

Distinction from `api/`: `api/` = "how to call the backend",
`services/` = "what the app does with that call".
