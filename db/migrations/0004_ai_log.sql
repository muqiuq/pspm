-- AI log (docs/security-ai-improvements.md §5): one row per API call of any model.
CREATE TABLE ai_calls (
  id           bigserial PRIMARY KEY,
  at           timestamptz NOT NULL DEFAULT now(),
  role         text NOT NULL,                  -- main, check, verify
  purpose      text NOT NULL,                  -- scan, behaviour, honeypots, check, verify, test
  model        text NOT NULL,                  -- the model requested
  model_answer text,                           -- the model that answered (providers route)
  request      jsonb NOT NULL,                 -- instructions and pseudonymised data, as sent (never the key)
  response     text,                           -- the raw answer, or the HTTP body of an error
  result       jsonb,                          -- the parsed answer
  status       integer,                        -- HTTP status; 0 = no connection
  duration_ms  integer,
  tokens_in    integer,
  tokens_out   integer,
  cost         numeric(12, 6),                 -- as reported by the provider (OpenRouter)
  error        text,
  pseudonyms   jsonb NOT NULL DEFAULT '{}'     -- pseudonym → real value; stays on this box
);
CREATE INDEX ai_calls_at ON ai_calls (at DESC);
CREATE INDEX ai_calls_role_at ON ai_calls (role, at);

-- The call that produced a verdict. No foreign key: calls are kept 30 days, verdicts 180.
ALTER TABLE ai_verdicts ADD COLUMN call_id bigint;
CREATE INDEX ai_verdicts_call ON ai_verdicts (call_id);
