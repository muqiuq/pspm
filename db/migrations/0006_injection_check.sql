-- Injection check (docs/security-ai-improvements.md §2): results per string, kept 24 h.
CREATE TABLE ai_check_cache (
  hash   text PRIMARY KEY,                        -- SHA-256 of check type, model and the string
  label  text NOT NULL CHECK (label IN ('safe', 'injection')),
  score  real NOT NULL,
  sample text NOT NULL,                           -- the string, shortened, for the AI log
  at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_check_cache_at ON ai_check_cache (at);
