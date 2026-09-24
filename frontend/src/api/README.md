# api/

Low-level HTTP client layer only: Axios instance configuration, interceptors
(auth token attachment, refresh-on-401), and one function per backend endpoint.
Contains no state, no business rules, no UI concerns.

Consumed exclusively by `services/` — components never import from `api/` directly.
