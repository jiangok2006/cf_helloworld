-- Add device binding to remember tokens
ALTER TABLE remember_tokens ADD COLUMN ua_hash TEXT; 
CREATE INDEX IF NOT EXISTS idx_remember_ua ON remember_tokens(ua_hash);
