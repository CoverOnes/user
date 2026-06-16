-- 000010_connections.up.sql
-- P4 Network: user-to-user business connections (invite → accept/decline).
-- NO FOREIGN KEY (CoverOnes red-line #9): requester_id/addressee_id have no REFERENCES;
--   referential integrity enforced in service layer (validates target user exists/live).
-- status is a VALUE check only (not FK): 'pending' | 'accepted' | 'declined'.
-- Undirected uniqueness via LEAST/GREATEST partial index: at most one LIVE
--   (pending|accepted) edge per unordered pair; a declined row does NOT block re-invite.
CREATE TABLE connections (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id uuid        NOT NULL,
    addressee_id uuid        NOT NULL,
    status       text        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','accepted','declined')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX connections_pair_live_uniq
    ON connections (LEAST(requester_id, addressee_id), GREATEST(requester_id, addressee_id))
    WHERE status IN ('pending','accepted');
CREATE INDEX connections_addressee_status_idx ON connections (addressee_id, status);
CREATE INDEX connections_requester_status_idx ON connections (requester_id, status);
