-- 000008_password_reset_tokens.up.sql
-- Auth Increment 5: password-reset token table.
--
-- Design notes:
--   * token_hash is SHA-256 of the raw token. Raw value is delivered in email only,
--     never stored — same pattern as email_verification_tokens (000005).
--   * NO FOREIGN KEY constraints (CoverOnes red-line #9): user_id has NO REFERENCES.
--     Referential integrity is enforced in the service layer.
--   * used_at is nullable — NULL means the token is still valid/unused.
--   * Retention: this is an ephemeral/observability table. Expired rows are purged by
--     the `db:gc:password-reset-tokens` Taskfile target (backend-security-design §1.3).
--     Retention period: rows older than 7 days past expires_at are deleted.

CREATE TABLE password_reset_tokens (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL,
    token_hash  bytea       NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- token_hash is looked up directly on reset; uniqueness prevents collision/replay.
CREATE UNIQUE INDEX password_reset_tokens_token_hash_uniq
    ON password_reset_tokens (token_hash);

-- Advisory index: InvalidateForUser (new-request flow) filters by user_id.
CREATE INDEX password_reset_tokens_user_id_idx
    ON password_reset_tokens (user_id);

-- Advisory index: the retention GC deletes by expires_at.
CREATE INDEX password_reset_tokens_expires_at_idx
    ON password_reset_tokens (expires_at);
