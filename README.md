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
- No FK constraints in DB — referential integrity via service layer
