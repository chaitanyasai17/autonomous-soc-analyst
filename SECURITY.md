# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ASOC, please report it
privately rather than opening a public issue. Email the maintainers (or
open a private security advisory on GitHub) with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge receipt within 5 business days and aim to provide a
resolution timeline shortly after.

## Supported Versions

As the project is currently in active development (pre-1.0), only the
latest commit on `main` is supported.

## Security Practices Followed by This Project

- No secrets are committed to version control (see `.gitignore`, `.env.example`)
- JWT-based authentication with refresh tokens and RBAC (Part 4)
- Passwords hashed with bcrypt, never stored in plaintext
- Input validation via Pydantic on all API boundaries
- Planned mitigations for SQL Injection, XSS, and broken authentication
  (see Master Project Blueprint, Part 0)
