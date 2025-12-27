-- Bootstrap default admin user
-- Inserts admin user if not already present.

INSERT OR IGNORE INTO users (email, role, is_active, created_at)
VALUES (
  'jiangok2006@gmail.com',
  'ADMIN',
  1,
  CAST(strftime('%s','now') AS INTEGER) * 1000
);
