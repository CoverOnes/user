-- 000001_init_users.down.sql
-- Extensions left in place intentionally: other tables may depend on citext/pgcrypto.

DROP TABLE IF EXISTS users;
