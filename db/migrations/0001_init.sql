-- PSPM initial schema.
-- Runs inside one transaction (bin/migrate.php). Migrations only ever add (expand);
-- drops follow one release later (contract), so rolling the app back stays safe.

-- The ranges that are never blocked (plan §14.2). Kept in sync with PHP, Lua and the
-- firewall rules by tests/unit/NeverBlockTest.php.
CREATE FUNCTION pspm_never_blocked(a inet) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT a <<= '10.0.0.0/8' OR a <<= '172.16.0.0/12' OR a <<= '192.168.0.0/16'
      OR a <<= '127.0.0.0/8' OR a <<= '::1/128' OR a <<= 'fc00::/7' OR a <<= 'fe80::/10'
      OR a >>= '10.0.0.0/8' OR a >>= '172.16.0.0/12' OR a >>= '192.168.0.0/16'
      OR a >>= '127.0.0.0/8' OR a >>= '::1/128' OR a >>= 'fc00::/7' OR a >>= 'fe80::/10'
$$;

-- ---------------------------------------------------------------- auth

CREATE TABLE users (
  id                   bigserial PRIMARY KEY,
  username             text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,31}$'),
  role                 text NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
  password_hash        text NOT NULL,
  must_change_password boolean NOT NULL DEFAULT true,
  totp_secret_enc      text,              -- secretbox with app.key; NULL = not enrolled
  totp_confirmed       boolean NOT NULL DEFAULT false,
  totp_last_step       bigint NOT NULL DEFAULT 0,   -- replay protection
  email                text,
  notify               jsonb NOT NULL DEFAULT '[]',
  disabled             boolean NOT NULL DEFAULT false,
  failed_logins        integer NOT NULL DEFAULT 0,
  last_failed_at       timestamptz,
  last_login_at        timestamptz,
  last_login_ip        inet,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  id_hash      text PRIMARY KEY,            -- SHA-256 of the cookie value
  user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage        text NOT NULL CHECK (stage IN ('password', 'otp', 'full')),
  csrf         text NOT NULL,
  ip           inet,
  user_agent   text,
  reauth_at    timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE login_failures (
  id         bigserial PRIMARY KEY,
  ip         inet NOT NULL,
  username   text,
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_ip_at ON login_failures(ip, at);

CREATE TABLE banned_ips (
  ip         cidr PRIMARY KEY CHECK (NOT pspm_never_blocked(ip)),
  reason     text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
  id         bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  actor      text NOT NULL,                 -- username, or 'root (script)'
  ip         inet,
  action     text NOT NULL,
  object     text,
  details    jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log(at DESC);

-- One-time nonces for forms that carry secrets or must not be submitted twice.
CREATE TABLE nonces (
  nonce      text PRIMARY KEY,
  user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose    text NOT NULL,
  expires_at timestamptz NOT NULL
);

-- ---------------------------------------------------------------- configuration (working copy)

-- key 'global' holds the static global settings (part of every revision);
-- other keys are runtime settings.
CREATE TABLE settings (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text
);

CREATE TABLE backends (
  id         uuid PRIMARY KEY,
  name       text NOT NULL UNIQUE,
  config     jsonb NOT NULL,                -- validated by lib/validate.php
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text
);

CREATE TABLE sites (
  id         uuid PRIMARY KEY,
  name       text NOT NULL UNIQUE,          -- the primary host name
  config     jsonb NOT NULL,                -- includes the ordered routes
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text
);

-- Enforces "no host name in two sites".
CREATE TABLE site_hosts (
  host    text PRIMARY KEY,
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------- revisions and applies

CREATE TABLE config_revisions (
  id         serial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  author     text NOT NULL,
  message    text NOT NULL DEFAULT '',
  document   jsonb NOT NULL,
  sha256     text NOT NULL
);

CREATE TABLE applies (
  id            bigserial PRIMARY KEY,
  revision_id   integer REFERENCES config_revisions(id),
  release       text NOT NULL,
  manifest_sha  text,
  code_commit   text,
  ssh_user      text,
  result        text NOT NULL CHECK (result IN ('applied', 'warnings', 'rolled_back', 'failed', 'dry_run')),
  message       text,
  log_file      text,
  log_excerpt   text,
  started_at    timestamptz NOT NULL,
  finished_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX applies_finished ON applies(finished_at DESC);

-- ---------------------------------------------------------------- access (runtime)

CREATE TABLE access_links (
  id          uuid PRIMARY KEY,
  token_hash  text NOT NULL UNIQUE,         -- SHA-256 of the URL token
  site_id     uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  label       text NOT NULL,
  grant_secs  integer,                      -- NULL = permanent
  valid_until timestamptz,
  max_uses    integer,
  uses        integer NOT NULL DEFAULT 0,
  after_path  text NOT NULL DEFAULT '/',
  revoked_at  timestamptz,
  last_used_at timestamptz,
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cleared_ips (
  site_id    uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  ip         cidr NOT NULL,
  link_id    uuid REFERENCES access_links(id) ON DELETE CASCADE,
  expires_at timestamptz,                   -- NULL = permanent
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (site_id, ip)
);

-- Trust registry (plan §15.2): kind 'trusted' (admin, every port) or 'authorised'
-- (certificate, access link, sign-in; web ports only).
CREATE TABLE trusted_ips (
  ip         cidr PRIMARY KEY,
  kind       text NOT NULL CHECK (kind IN ('trusted', 'authorised')),
  source     text NOT NULL,                 -- 'admin', 'cert:<fp>', 'link:<id>', 'signin:<user>'
  note       text,
  last_seen  timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Blocks published to nginx and the firewall.
CREATE TABLE blocks (
  ip         cidr PRIMARY KEY CHECK (NOT pspm_never_blocked(ip)),
  source     text NOT NULL,                 -- 'manual', 'ai', 'trap', 'unknown-host', 'login', 'behaviour'
  reason     text NOT NULL,
  firewall   boolean NOT NULL DEFAULT true,
  expires_at timestamptz NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Serial numbers of the published snapshot files.
CREATE TABLE snapshot_serials (
  name   text PRIMARY KEY,
  serial bigint NOT NULL
);
