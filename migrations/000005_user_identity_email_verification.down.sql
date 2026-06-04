-- 000005_user_identity_email_verification.down.sql
-- Reverses 000005: drops the verification token table, restores the 2-value
-- status CHECK, and removes the identity / email_verified columns.
-- PLAIN SQL only — no psql metacommands (golang-migrate cannot parse them).

DROP TABLE IF EXISTS email_verification_tokens;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('ACTIVE', 'SUSPENDED'));

ALTER TABLE users
    DROP COLUMN IF EXISTS legal_name_enc,
    DROP COLUMN IF EXISTS national_id_enc,
    DROP COLUMN IF EXISTS email_verified;
