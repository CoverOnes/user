# CoverOnes User Service

Walking-skeleton microservice implementing user authentication and profile management.

## Stack

| Component | Choice |
|-----------|--------|
| Language | Go 1.25 |
| HTTP | gin v1.12 |
| Database | PostgreSQL 17 via pgx/v5 |
| Auth | EdDSA (Ed25519) JWT + Argon2id |
| Migrations | golang-migrate (embedded SQL) |
| Config | Viper (ENV-first, prefix `USER_`) |
| Logging | slog JSON to stdout |

## Quick Start

```bash
# Copy and fill the example env file
cp .env.example .env
# edit .env

# Run all checks (lint + vet + test + build)
task check

# Start the server
task run
```

## API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | /v1/auth/register | public | Create account |
| POST | /v1/auth/login | public | Obtain token pair |
| POST | /v1/auth/refresh | public | Rotate refresh token |
| POST | /v1/auth/logout | Bearer | Revoke token family |
| GET | /v1/me | Bearer | Current user identity |
| GET | /v1/me/profile | Bearer | Editable profile subset |
| PUT | /v1/me/profile | Bearer + Tier≥1 | Update profile |
| GET | /jwks | public | Ed25519 public key set |
| GET | /healthz | public | Liveness probe |
| GET | /readyz | public | Readiness probe |

## Security Design

- Passwords: Argon2id (m=64MB, t=3, p=2)
- Access tokens: EdDSA (Ed25519), 10-minute TTL
- Refresh tokens: opaque `<id>.<secret>`, SHA-256 hash stored
- Token rotation: each refresh creates a new token, old is marked used
- Reuse detection: second use of a consumed token revokes the entire family
- Rate limiting: Redis sliding-window limiter (sorted-set ZADD/ZREMRANGEBYSCORE,
  evaluated atomically via a Lua script) on auth endpoints, with an in-process
  token-bucket fallback when Redis is unavailable. The sliding window prevents the
  fixed-window boundary-burst bypass (2×limit across a window boundary).
- No FK constraints in DB — referential integrity via service layer

## Operations

### Refresh-token garbage collection (`task db:gc`)

`refresh_tokens` is an append-mostly table: every login and every rotation inserts
a row, and rows are never deleted by the request path. Left unbounded it grows
without limit, so a retention job is **required in production**.

`task db:gc` runs the cleanup DELETE (requires `USER_POSTGRES_DSN` in the env):

```sql
DELETE FROM refresh_tokens
WHERE expires_at < now()
   OR (used_at IS NOT NULL AND used_at < now() - INTERVAL '7 days');
```

It removes (1) fully-expired tokens and (2) tokens consumed more than 7 days ago
(a forensic grace window for reuse-detection audit). The DELETE is range-friendly
via `refresh_tokens_expires_at_idx`.

**Production scheduling**: `task db:gc` is a manual convenience wrapper — it is NOT
self-scheduling. Run the DELETE on a recurring schedule (daily is sufficient) via
one of: `pg_cron`, a Kubernetes `CronJob`, or an external scheduler invoking
`task db:gc`. Without a scheduled job the table grows monotonically; this is the
implemented retention policy referenced in `migrations/000003_refresh_tokens.up.sql`.
