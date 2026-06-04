-- 000005_user_identity_email_verification.up.sql
-- Auth Increment 1: real-name (legal_name) + national_id encrypted-at-rest columns,
-- an email_verified flag, the PENDING_VERIFICATION status, and a single-use
-- email-verification token table.
--
-- Design notes:
--   * legal_name_enc / national_id_enc are AES-256-GCM ciphertext (bytea); the
--     plaintext PII NEVER lands in a column. national_id_enc is NULL for COMPANY
--     accounts (company identity is KYC tier-2, handled later).
--   * NO FOREIGN KEY constraints anywhere (CoverOnes red-line): referential
--     integrity is enforced in the service layer. user_id has NO REFERENCES.
--   * Retention: email_verification_tokens is an observability/ephemeral table —
--     the `db:gc:verification-tokens` Taskfile target purges expired rows
--     (backend-security-design §1.3).

ALTER TABLE users
    ADD COLUMN legal_name_enc  bytea,
    ADD COLUMN national_id_enc bytea,
    ADD COLUMN email_verified  boolean NOT NULL DEFAULT false;

-- Replace the 2-value status CHECK with a 3-value one that admits the new
-- PENDING_VERIFICATION state used by the real-name register flow.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('ACTIVE', 'SUSPENDED', 'PENDING_VERIFICATION'));

CREATE TABLE email_verification_tokens (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL,
    token_hash  bytea       NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- token_hash is looked up directly on verify; uniqueness prevents collision/replay.
CREATE UNIQUE INDEX email_verification_tokens_token_hash_uniq
    ON email_verification_tokens (token_hash);

-- Advisory index: invalidate-all-for-user (resend flow) filters by user_id.
CREATE INDEX email_verification_tokens_user_id_idx
    ON email_verification_tokens (user_id);

-- Advisory index: the retention GC deletes by expires_at.
CREATE INDEX email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at);
