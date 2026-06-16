-- 000012_saved_items.down.sql
DROP INDEX IF EXISTS saved_items_user_type_created_idx;
DROP INDEX IF EXISTS saved_items_user_item_uniq;
DROP TABLE IF EXISTS saved_items;
