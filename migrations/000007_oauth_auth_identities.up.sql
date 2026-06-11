-- 000007_oauth_auth_identities.up.sql
-- Auth Increment 4: OAuth social login (Google OIDC + LINE Login v2.1).
--
-- Design notes:
--   * auth_identities records OAuth provider → user mappings. One user may have
--     at most one identity per provider, enforced by UNIQUE(provider, provider_subject).
--   * password_hash is made nullable so OAuth-only accounts (no password) can be
--     created. Existing rows are unaffected (password_hash IS NOT NULL already).
--   * NO FOREIGN KEY constraints (CoverOnes red-line §1.1): referential integrity for
--     auth_identities.user_id is enforced in the service layer (GetByID validates the
--     user exists before insert). The index on user_id backs the fast path for
--     "list identities for user" lookups.
--   * TTL / retention: auth_identities rows are long-lived (persist for the life of
--     the linked account); no GC needed beyond the user's soft-delete flow.

-- Make password_hash nullable so OAuth-only accounts can exist.
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

-- Create the auth_identities table.
CREATE TABLE auth_identities (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider         text        NOT NULL,
    provider_subject text        NOT NULL,
    user_id          uuid        NOT NULL,
    email            text,
    linked_at        timestamptz NOT NULL DEFAULT now()
);

-- Unique constraint: one identity per (provider, subject) pair.
CREATE UNIQUE INDEX auth_identities_provider_subject_uq
    ON auth_identities (provider, provider_subject);

-- Advisory index: backs list-identities-for-user and unbind lookups.
CREATE INDEX auth_identities_user_id_idx
    ON auth_identities (user_id);
