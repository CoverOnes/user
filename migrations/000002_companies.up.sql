-- 000002_companies.up.sql
-- Creates the companies table.
-- NO FOREIGN KEY on owner_user_id — referential integrity enforced in service layer.

CREATE TABLE companies (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text        NOT NULL,
    registration_no text,
    owner_user_id   uuid        NOT NULL,
    status          text        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Partial unique index: NULL registration_no is allowed (unverified companies).
CREATE UNIQUE INDEX companies_registration_no_unique ON companies (registration_no) WHERE registration_no IS NOT NULL;

-- Advisory index: backs owner lookup from user profile.
CREATE INDEX companies_owner_user_id_idx ON companies (owner_user_id);
