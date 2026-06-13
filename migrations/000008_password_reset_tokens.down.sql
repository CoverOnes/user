-- 000008_password_reset_tokens.down.sql
-- Reverses 000008: drops the password_reset_tokens table.
-- PLAIN SQL only — no psql metacommands (golang-migrate cannot parse them).

DROP TABLE IF EXISTS password_reset_tokens;
