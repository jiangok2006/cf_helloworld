-- Seed a default regular user
-- Inserts if not present

INSERT OR IGNORE INTO users (email, role, is_active, created_at)
VALUES (
  'lian_jiang_hust@yahoo.com',
  'USER',
  1,
  CAST(strftime('%s','now') AS INTEGER) * 1000
);
