-- 000011_company_public_profile.up.sql
-- P4 Company-CORE: nullable public-profile columns on the EXISTING companies table
-- (created in 000002 — which is MERGED/immutable and is NOT edited here).
--
-- Design notes:
--   * Public, non-PII display fields only. registration_no (from 000002) stays
--     owner-view-only and is NEVER added to a public projection.
--   * NO FOREIGN KEY constraints (CoverOnes red-line #9). owner_user_id (000002)
--     and the users.company_id membership link have no REFERENCES — referential
--     integrity is enforced in the service layer.
--   * handle is citext (extension created in 000001) for case-insensitive
--     uniqueness, enforced by a PARTIAL unique index over non-null handles.
--     companies has NO soft-delete column (confirmed against 000002), so the
--     predicate is `WHERE handle IS NOT NULL` only (no deleted_at clause).
--   * Length / format limits are enforced in the service layer (CompanyService,
--     §5.2 bounds), NOT via DB CHECK constraints (platform rule §5.2).
--   * No new tables: profile fields live on the companies row.

ALTER TABLE companies
    ADD COLUMN handle       citext,
    ADD COLUMN tagline      text,
    ADD COLUMN about        text,
    ADD COLUMN location     text,
    ADD COLUMN website      text,
    ADD COLUMN industry     text,
    ADD COLUMN company_size text,
    ADD COLUMN founded_year smallint,
    ADD COLUMN logo_url     text,
    ADD COLUMN cover_url    text;

-- Partial unique: only companies with a non-null handle compete for uniqueness.
CREATE UNIQUE INDEX companies_handle_unique
    ON companies (handle)
    WHERE handle IS NOT NULL;
