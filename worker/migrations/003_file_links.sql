-- Table for presigned file download links (token-based)
CREATE TABLE IF NOT EXISTS file_links (
  token TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
