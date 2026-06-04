-- 000006_user_mfa_totp.up.sql
-- Auth Increment 3: TOTP 2FA primitives. Adds the at-rest columns the
-- enroll / confirm / verify / disable flow needs. Login is NOT wired to TOTP in
-- this increment — these columns are populated by the /v1/me/mfa/totp/* endpoints
-- only; enforcement is a later, flag-gated increment.
--
-- Design notes:
--   * totp_secret_enc / mfa_backup_codes_enc are AES-256-GCM ciphertext (bytea),
--     produced by the SAME internal/crypto/pii.Encryptor that already protects
--     legal_name_enc / national_id_enc. The plaintext TOTP secret and the backup
--     codes NEVER land in a column (or a log line).
--   * totp_secret_enc doubles as the PENDING secret store: enroll writes the
--     encrypted secret with mfa_enabled = false; confirm verifies a live code
--     against it and flips mfa_enabled = true. The mfa_enabled flag is the
--     pending-vs-active discriminator, so no separate "pending" column is needed.
--   * mfa_backup_codes_enc holds the AES-256-GCM ciphertext of a JSON array of
--     SHA-256 hashes of one-time backup codes (the raw codes are returned exactly
--     once, at confirm, and never persisted in the clear).
--   * NO FOREIGN KEY constraints (CoverOnes red-line): there are no new tables and
--     these are plain columns on users, so there is nothing to reference anyway.
--   * No new index: every read of these columns is keyed by users.id (already the
--     PK) inside the MFA flow — no new hot query path is introduced.

ALTER TABLE users
    ADD COLUMN mfa_enabled          boolean     NOT NULL DEFAULT false,
    ADD COLUMN totp_secret_enc      bytea,
    ADD COLUMN mfa_backup_codes_enc bytea,
    ADD COLUMN mfa_enrolled_at      timestamptz;
