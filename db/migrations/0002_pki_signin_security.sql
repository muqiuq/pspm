-- PSPM: client-certificate PKI, Microsoft sign-in, security monitoring, blocklists,
-- notifications. Expand only (plan §10.3).

-- ---------------------------------------------------------------- PKI (plan §13)

CREATE TABLE cas (
  id                 uuid PRIMARY KEY,
  name               text NOT NULL UNIQUE,
  cert_pem           text NOT NULL,
  fingerprint_sha256 text NOT NULL UNIQUE,
  subject_cn         text NOT NULL,
  not_after          timestamptz NOT NULL,
  key_wrapped        text,                       -- NULL = trust only: cannot issue
  trusted            boolean NOT NULL DEFAULT true,  -- in nginx's CA bundle (static: applied by install.sh)
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE client_certs (
  id                 uuid PRIMARY KEY,
  ca_id              uuid NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
  serial             text NOT NULL,
  subject_cn         text NOT NULL,
  label              text NOT NULL DEFAULT '',
  fingerprint_sha1   text NOT NULL UNIQUE,        -- as nginx's $ssl_client_fingerprint
  fingerprint_sha256 text NOT NULL,
  scope              text NOT NULL DEFAULT 'all', -- 'all' or comma-separated site ids
  cert_pem           text NOT NULL,
  not_before         timestamptz NOT NULL,
  not_after          timestamptz NOT NULL,
  issued_by          text NOT NULL,
  issued_at          timestamptz NOT NULL DEFAULT now(),
  revoked_at         timestamptz,
  revoked_by         text,
  revoke_reason      text
);

CREATE TABLE pki_failures (
  user_id bigint NOT NULL,
  at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX pki_failures_user_at ON pki_failures(user_id, at);

-- ---------------------------------------------------------------- Sign-in (plan §12)

CREATE TABLE oauth_providers (
  id                uuid PRIMARY KEY,
  name              text NOT NULL UNIQUE,
  config            jsonb NOT NULL,              -- tenant, client id, sign-in host, … (validated)
  client_secret_enc text,                        -- sealed with app.key
  cookie_secret_enc text NOT NULL,               -- sealed with app.key, generated once
  updated_at        timestamptz NOT NULL DEFAULT now(),
  updated_by        text
);

-- ---------------------------------------------------------------- security monitoring (plan §15)

CREATE TABLE scan_state (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scan_runs (
  id          bigserial PRIMARY KEY,
  kind        text NOT NULL,                     -- fast, full, mining
  started_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  stats       jsonb NOT NULL DEFAULT '{}'
);

-- Activity per client (IPv4 address or IPv6 /64) and hour.
CREATE TABLE ip_activity (
  ip    cidr NOT NULL,
  hour  timestamptz NOT NULL,
  data  jsonb NOT NULL,
  PRIMARY KEY (ip, hour)
);
CREATE INDEX ip_activity_hour ON ip_activity(hour);

CREATE TABLE ai_verdicts (
  id         bigserial PRIMARY KEY,
  kind       text NOT NULL,                      -- verdict, behaviour, mining
  subject    text NOT NULL,                      -- ip, actor or 'traps'
  verdict    text,
  confidence real,
  reason     text,
  evidence   jsonb NOT NULL DEFAULT '{}',
  answer     jsonb NOT NULL DEFAULT '{}',
  model      text,
  outcome    text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_verdicts_subject ON ai_verdicts(subject, created_at DESC);

-- Every block ever placed: escalation (1 d → 7 d → 30 d) and "an admin removed it".
CREATE TABLE block_history (
  id             bigserial PRIMARY KEY,
  ip             cidr NOT NULL,
  source         text NOT NULL,
  reason         text NOT NULL,
  duration_secs  integer NOT NULL,
  created_by     text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  removed_at     timestamptz,
  removed_by     text,
  removed_reason text
);
CREATE INDEX block_history_ip ON block_history(ip, created_at DESC);

-- Honeypots (plan §15.5)
CREATE TABLE traps (
  id           bigserial PRIMARY KEY,
  host         text NOT NULL,                    -- a host name, or '*'
  kind         text NOT NULL CHECK (kind IN ('exact', 'prefix')),
  path         text NOT NULL,
  state        text NOT NULL CHECK (state IN ('proposed', 'shadow', 'active', 'disabled', 'retired', 'rejected')),
  track        text NOT NULL DEFAULT 'standard' CHECK (track IN ('fast', 'standard')),
  pinned       boolean NOT NULL DEFAULT false,
  votes        integer NOT NULL DEFAULT 0,
  attackers    integer NOT NULL DEFAULT 0,
  hits         integer NOT NULL DEFAULT 0,
  last_hit_at  timestamptz,
  shadow_since timestamptz,
  note         text NOT NULL DEFAULT '',
  created_by   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (host, kind, path)
);

CREATE TABLE trap_votes (
  trap_id      bigint NOT NULL REFERENCES traps(id) ON DELETE CASCADE,
  window_start timestamptz NOT NULL,
  PRIMARY KEY (trap_id, window_start)
);

-- Refused paths per host and day, with what the backends answered (trap evidence).
CREATE TABLE attack_paths (
  host  text NOT NULL,
  path  text NOT NULL,
  day   date NOT NULL,
  data  jsonb NOT NULL,
  PRIMARY KEY (host, path, day)
);

-- Behaviour analysis (plan §15.7)
CREATE TABLE behaviour_hours (
  actor_type text NOT NULL,                      -- ip, cert, user, link
  actor      text NOT NULL,
  hour       timestamptz NOT NULL,
  data       jsonb NOT NULL,
  PRIMARY KEY (actor_type, actor, hour)
);
CREATE INDEX behaviour_hours_hour ON behaviour_hours(hour);

CREATE TABLE behaviour_baselines (
  actor_type text NOT NULL,
  actor      text NOT NULL,
  data       jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (actor_type, actor)
);

CREATE TABLE risk_findings (
  id          bigserial PRIMARY KEY,
  actor_type  text NOT NULL,
  actor       text NOT NULL,
  pattern     text NOT NULL,
  class       text NOT NULL CHECK (class IN ('attack', 'risky', 'normal')),
  risk        integer NOT NULL DEFAULT 0,
  confidence  real,
  authorised  boolean NOT NULL DEFAULT false,
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'expected', 'blocked', 'acted', 'closed')),
  deadline    timestamptz,
  evidence    jsonb NOT NULL DEFAULT '{}',
  ai          jsonb,
  notified    jsonb NOT NULL DEFAULT '{}',
  acted_by    text,
  acted_at    timestamptz,
  note        text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX risk_findings_open ON risk_findings(status, created_at DESC);

CREATE TABLE expected_patterns (
  actor_type text NOT NULL,
  actor      text NOT NULL,
  pattern    text NOT NULL,
  until      timestamptz NOT NULL,
  PRIMARY KEY (actor_type, actor, pattern)
);

-- Red/green state of the dashboard checks, for "resolved" notifications.
CREATE TABLE health_state (
  key         text PRIMARY KEY,
  level       text NOT NULL,
  message     text NOT NULL,
  since       timestamptz NOT NULL DEFAULT now(),
  notified_at timestamptz
);

-- ---------------------------------------------------------------- external blocklists (plan §14.5)

CREATE TABLE blocklists (
  id              uuid PRIMARY KEY,
  name            text NOT NULL UNIQUE,
  url             text NOT NULL,
  format          text NOT NULL CHECK (format IN ('plain', 'jsonl')),
  field           text NOT NULL DEFAULT 'cidr',
  auth_header_enc text,
  refresh_hours   integer NOT NULL DEFAULT 24,
  mode            text NOT NULL CHECK (mode IN ('block', 'observe')),
  enabled         boolean NOT NULL DEFAULT true,
  etag            text,
  last_modified   text,
  last_fetch_at   timestamptz,
  last_ok_at      timestamptz,
  last_status     jsonb NOT NULL DEFAULT '{}',
  held            jsonb,                          -- a suspicious new list waiting for "Accept anyway"
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE blocklist_fetches (
  id           bigserial PRIMARY KEY,
  blocklist_id uuid NOT NULL REFERENCES blocklists(id) ON DELETE CASCADE,
  at           timestamptz NOT NULL DEFAULT now(),
  http_status  integer,
  entries      integer,
  refused      integer,
  changed      boolean,
  accepted     boolean,
  error        text
);

-- ---------------------------------------------------------------- notifications (plan §8.6)

CREATE TABLE notification_outbox (
  id          bigserial PRIMARY KEY,
  category    text NOT NULL,
  dedupe_key  text,
  subject     text NOT NULL,
  body        text NOT NULL,
  recipients  jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  send_after  timestamptz NOT NULL DEFAULT now(),
  attempts    integer NOT NULL DEFAULT 0,
  last_error  text,
  sent_at     timestamptz,
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'digested', 'dropped'))
);
CREATE INDEX notification_outbox_pending ON notification_outbox(status, send_after);
