# CoverOnes User Service

Identity and authentication service — owns user accounts, login sessions, email verification, and TOTP-based MFA.

## What it does

- Registers new user accounts (personal and company types) and enforces uniqueness
- Issues and rotates access / refresh token pairs on login; detects and revokes token reuse
- Handles email verification flows (send / verify / resend)
- Manages user profile reads and updates (gated by KYC tier)
- Provides TOTP 2FA enroll / confirm / verify / disable lifecycle
- Exposes a JWKS endpoint so the gateway can verify tokens without calling this service on each request
- Keeps the user's KYC tier in sync by consuming tier-change events published by the KYC service

## Where it sits

The user service runs behind the gateway on the internal network. It is the authority for identity: it issues access tokens, stores hashed credentials, and owns the `users` and `refresh_tokens` tables. The gateway forwards public auth routes directly; all other user-service routes are reached through the authenticated `/api/user/*` proxy path.

## API (high level)

| Group | Endpoints | Notes |
|-------|-----------|-------|
| `POST /v1/auth/*` | register / login / refresh / verify-email / resend-verification / logout | Public (logout requires token) |
| `GET /v1/me` | Current user identity | Requires access token |
| `GET /v1/me/profile` | Editable profile fields | Requires access token |
| `PUT /v1/me/profile` | Update profile | Requires token + KYC Tier ≥ 1 |
| `POST /v1/me/sessions/revoke-all` | Revoke all refresh tokens | Requires access token |
| `POST /v1/me/mfa/totp/*` | enroll / confirm / verify / disable | Requires access token |
| `GET /jwks` | Ed25519 public key set | Public |
| `GET /healthz`, `GET /readyz` | Liveness / readiness probes | Not rate-limited |

Request/response shapes follow the platform envelope; see `../conventions/http-api.md`.

## Tech

| Item | Choice |
|------|--------|
| Language | Go 1.25 |
| HTTP framework | Gin v1.12 |
| Database | PostgreSQL 17 via pgx/v5 |
| Cache / rate limiting | Redis (optional in dev) |
| Migrations | golang-migrate (embedded SQL) |
| Logging | slog JSON to stdout |

## Run locally

This service is part of the shared dev stack — see `../dev-stack/README.md`.
