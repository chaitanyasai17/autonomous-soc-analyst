# Contributing to ASOC

Thank you for your interest in contributing to the AI-Powered Autonomous SOC
Analyst project.

## Development Workflow

1. Fork the repository and create a feature branch from `main`.
2. Follow the existing Clean Architecture layout — do not introduce new
   top-level folders without discussion.
3. Keep backend code PEP 8 compliant; keep frontend code compliant with the
   project's ESLint/Prettier configuration (added in Part 13).
4. Write tests for new functionality (see `backend/tests/` and future
   frontend test setup).
5. Never commit secrets, API keys, or `.env` files.
6. Open a pull request with a clear description of the change.

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add sigma rule evaluation service
fix: correct JWT refresh token expiry check
docs: update deployment guide
chore: update dependency versions
```

## Code Review

All pull requests require at least one review before merging.
