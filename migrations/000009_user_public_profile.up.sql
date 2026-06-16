-- 000009_user_public_profile.up.sql
-- P4 Profile-CORE: nullable public-profile columns on the existing users table.
--
-- Design notes:
--   * Public, non-PII display fields only (handle, headline, bio, location,
--     cover_url). avatar_url already exists (000001) and is reused as-is.
--   * NO FOREIGN KEY constraints (CoverOnes red-line #9).
--   * handle is citext (extension created in 000001) for case-insensitive
--     uniqueness, enforced by a PARTIAL unique index over live rows only
--     (mirrors users_email_unique). A soft-deleted row frees its handle.
--   * Length / format limits are enforced in the service layer (ProfileService),
--     NOT via DB CHECK constraints (platform rule §5.2).

ALTER TABLE users
    ADD COLUMN handle    citext,
    ADD COLUMN headline  text,
    ADD COLUMN bio       text,
    ADD COLUMN location  text,
    ADD COLUMN cover_url text;

-- Partial unique: only live rows with a non-null handle compete for uniqueness.
CREATE UNIQUE INDEX users_handle_unique
    ON users (handle)
    WHERE handle IS NOT NULL AND deleted_at IS NULL;
