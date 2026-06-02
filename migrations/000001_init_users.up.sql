-- 000001_init_users.up.sql
-- Creates the users table with citext email, partial unique index, and advisory indexes.
-- NO FOREIGN KEY constraints — referential integrity enforced in service layer.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         citext      NOT NULL,
    password_hash text        NOT NULL,
    display_name  text        NOT NULL DEFAULT '',
    avatar_url    text,
    account_type  text        NOT NULL DEFAULT 'PERSONAL' CHECK (account_type IN ('PERSONAL','COMPANY')),
    kyc_tier      smallint    NOT NULL DEFAULT 0 CHECK (kyc_tier BETWEEN 0 AND 3),
    company_id    uuid,
    status        text        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
    token_version integer     NOT NULL DEFAULT 0,
    deleted_at    timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Partial unique index: erasure frees the email address for re-registration (GDPR right-to-erasure).
CREATE UNIQUE INDEX users_email_unique ON users (email) WHERE deleted_at IS NULL;

-- Advisory index: backs lookups from user -> company service-layer queries.
CREATE INDEX users_company_id_idx ON users (company_id) WHERE company_id IS NOT NULL;
