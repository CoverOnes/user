-- 000007_oauth_auth_identities.down.sql

DROP INDEX IF EXISTS auth_identities_user_id_idx;
DROP INDEX IF EXISTS auth_identities_provider_subject_uq;
DROP TABLE IF EXISTS auth_identities;

-- Guard: only restore the NOT NULL constraint if no OAuth-only users exist.
-- If OAuth-only users (password_hash IS NULL) were created after running the up
-- migration, ALTER TABLE will fail. The guard prevents a hard error while
-- honestly leaving the constraint absent (data inconsistency is caller's responsibility).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE password_hash IS NULL) THEN
        ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;
    END IF;
END $$;

