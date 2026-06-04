-- 000006_user_mfa_totp.down.sql
-- Reverses 000006: drops the TOTP 2FA columns from users.
-- PLAIN SQL only — no psql metacommands (golang-migrate cannot parse them).

ALTER TABLE users
    DROP COLUMN IF EXISTS mfa_enabled,
    DROP COLUMN IF EXISTS totp_secret_enc,
    DROP COLUMN IF EXISTS mfa_backup_codes_enc,
    DROP COLUMN IF EXISTS mfa_enrolled_at;
