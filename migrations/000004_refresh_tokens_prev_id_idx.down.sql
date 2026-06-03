-- 000004_refresh_tokens_prev_id_idx.down.sql
-- Plain SQL only (no psql metacommands) so golang-migrate parses it (CONVENTIONS §11).

DROP INDEX IF EXISTS refresh_tokens_prev_id_idx;
