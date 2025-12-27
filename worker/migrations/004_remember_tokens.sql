-- Remember tokens for persistent login
CREATE TABLE IF NOT EXISTS remember_tokens (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remember_email ON remember_tokens(email);
