-- 000004_refresh_tokens_prev_id_idx.up.sql
-- Adds an advisory index on refresh_tokens(prev_id) to accelerate reuse-chain
-- walks. The reuse-detection / rotation logic follows the prev_id linkage when
-- auditing a token family (which token superseded which); without this index a
-- "find the row whose prev_id = X" lookup is a sequential scan as the table grows.
--
-- NO FOREIGN KEY — referential integrity (prev_id → refresh_tokens.id) is enforced
-- in the service layer, consistent with the rest of the schema (CONVENTIONS §11).
-- prev_id is nullable (the first token in a family has no predecessor); a plain
-- B-tree index already skips NULLs efficiently for the `prev_id = $1` access path.

CREATE INDEX IF NOT EXISTS refresh_tokens_prev_id_idx ON refresh_tokens (prev_id);
