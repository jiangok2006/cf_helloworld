-- Initial D1 schema migration
-- Tables: magic_tokens, sessions, roles (seed), users

-- Magic-link tokens
CREATE TABLE IF NOT EXISTS magic_tokens (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Roles
CREATE TABLE IF NOT EXISTS roles (
  role TEXT PRIMARY KEY,
  can_admin INTEGER NOT NULL DEFAULT 0,
  can_use INTEGER NOT NULL DEFAULT 1,
  CHECK (role IN ('ADMIN','USER')),
  CHECK (can_admin IN (0,1)),
  CHECK (can_use IN (0,1))
);

-- Seed default roles
INSERT OR IGNORE INTO roles (role, can_admin, can_use) VALUES
  ('ADMIN', 1, 1),
  ('USER', 0, 1);

-- Users
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  CHECK (role IN ('ADMIN','USER')),
  CHECK (is_active IN (0,1)),
  FOREIGN KEY (role) REFERENCES roles(role)
);
