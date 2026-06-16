-- 000009_user_public_profile.down.sql
-- Reverses 000009. Plain SQL only (no psql metacommands).

DROP INDEX IF EXISTS users_handle_unique;

ALTER TABLE users
    DROP COLUMN IF EXISTS handle,
    DROP COLUMN IF EXISTS headline,
    DROP COLUMN IF EXISTS bio,
    DROP COLUMN IF EXISTS location,
    DROP COLUMN IF EXISTS cover_url;
