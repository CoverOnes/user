-- 000003_refresh_tokens.up.sql
-- Creates the refresh_tokens table for the token-rotation + reuse-detection system.
-- NO FOREIGN KEY on user_id — referential integrity enforced in service layer.
--
-- Retention/TTL policy (F9 / CONVENTIONS §1.3):
--   Retention period: refresh token TTL (default 24 h) + 7-day forensic grace window.
--   Working cleanup implementation: `task db:gc` (Taskfile.yml) runs:
--     DELETE FROM refresh_tokens
--     WHERE expires_at < now()
--        OR (used_at IS NOT NULL AND used_at < now() - INTERVAL '7 days');
--   Schedule: run daily via cron or an external scheduler (e.g. pg_cron, k8s CronJob).
-- Backed by refresh_tokens_expires_at_idx for efficient range deletes.

CREATE TABLE refresh_tokens (
    id                 uuid        PRIMARY KEY,
    user_id            uuid        NOT NULL,
    family_id          uuid        NOT NULL,
    token_hash         bytea       NOT NULL,
    prev_id            uuid,
    used_at            timestamptz,
    revoked_at         timestamptz,
    device_fingerprint text,
    ip_addr            inet,
    user_agent         text,
    expires_at         timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    -- token_version captures the user's token_version at issuance time.
    -- Compared server-side at refresh against the fresh users.token_version to
    -- enforce logout-all without a DB hit on every access-token request (M1 fix).
    -- NO FK on user_id — referential integrity enforced in service layer.
    token_version      integer     NOT NULL DEFAULT 0
);

-- Unique token hash: enforces single-token-per-secret.
CREATE UNIQUE INDEX refresh_tokens_token_hash_unique ON refresh_tokens (token_hash);

-- Advisory indexes for family-level queries and TTL purge job.
CREATE INDEX refresh_tokens_user_id_idx   ON refresh_tokens (user_id);
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);
