-- 000007_oauth_auth_identities.down.sql

DROP INDEX IF EXISTS auth_identities_user_id_idx;
DROP INDEX IF EXISTS auth_identities_provider_subject_uq;
DROP TABLE IF EXISTS auth_identities;

ALTER TABLE users
    ALTER COLUMN password_hash SET NOT NULL;
