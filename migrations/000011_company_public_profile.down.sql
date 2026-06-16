-- 000011_company_public_profile.down.sql
-- Reverses 000011. Plain SQL only (no psql metacommands). Does NOT touch 000002.

DROP INDEX IF EXISTS companies_handle_unique;

ALTER TABLE companies
    DROP COLUMN IF EXISTS handle,
    DROP COLUMN IF EXISTS tagline,
    DROP COLUMN IF EXISTS about,
    DROP COLUMN IF EXISTS location,
    DROP COLUMN IF EXISTS website,
    DROP COLUMN IF EXISTS industry,
    DROP COLUMN IF EXISTS company_size,
    DROP COLUMN IF EXISTS founded_year,
    DROP COLUMN IF EXISTS logo_url,
    DROP COLUMN IF EXISTS cover_url;
