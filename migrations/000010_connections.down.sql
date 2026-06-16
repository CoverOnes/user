-- 000010_connections.down.sql
DROP INDEX IF EXISTS connections_requester_status_idx;
DROP INDEX IF EXISTS connections_addressee_status_idx;
DROP INDEX IF EXISTS connections_pair_live_uniq;
DROP TABLE IF EXISTS connections;
