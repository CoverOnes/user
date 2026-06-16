-- 000012_saved_items.up.sql
-- P4 Saved: generic per-user bookmarks over heterogeneous targets (jobs/companies).
-- NO FOREIGN KEY (CoverOnes red-line #9): item_id references rows that may live in a
--   DIFFERENT service's DB (a 'job' is a marketplace Listing). Referential integrity is
--   resolve-on-read in the service/handler layer (fetch target; if gone, the row is
--   simply not rendered). item_type is a VALUE check only (not FK).
-- Generic by design: (user_id, item_type, item_id). 'user'/'document' reserved for
--   future tabs without a new migration.
CREATE TABLE saved_items (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL,
    item_type  text        NOT NULL
                           CHECK (item_type IN ('job','company')),
    item_id    uuid        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- At most one live bookmark per (user, type, id). A re-save after unsave (hard DELETE)
-- is allowed because the row was removed. Unique authority for the toggle 23505 path.
CREATE UNIQUE INDEX saved_items_user_item_uniq
    ON saved_items (user_id, item_type, item_id);

-- Hot path: list a user's saved items of one type, newest first.
CREATE INDEX saved_items_user_type_created_idx
    ON saved_items (user_id, item_type, created_at DESC);
