# PSPM — implementation plan

Status: **draft, reviewed five times** · 2026-11-09 · decisions in §20, questions in §21

PSPM (Philipp's Secure Proxy Manager; in the product only **PSPM** / *Secure Proxy
Manager*, §8.1) is a reverse-proxy appliance on one Debian 13 box. nginx terminates TLS
for any number of sites and enforces per-site access rules: LAN, access links, client
certificates and OAuth sign-in. Hostile addresses are blocked in nginx and in the kernel
firewall.

Every domain, backend and nginx option is configured in the web UI and stored in
PostgreSQL. An admin then logs in over SSH and runs `/opt/pspm/install.sh`, which renders,
tests and applies the configuration, and rolls it back on its own if something fails.

---

## 1. Requirements

| # | Requirement | Where |
|---|---|---|
| R1 | Name **PSPM** (Philipp's Secure Proxy Manager). "Philipp" is never shown prominently | §8.1 |
| R2 | The first page is a **dashboard** | §8.4 |
| R3 | Installed by cloning the repo to `/opt/pspm` and running `install.sh`. On the first run it provisions a Debian box. On every run it **applies the nginx configuration**, which the web UI cannot do | §6 |
| R4 | **Docker** is installed, and **PostgreSQL** runs in a container instead of SQLite | §10 |
| R5 | Evil hosts are blocked at **iptables level, on every port**, not only in nginx/Lua | §14 |
| R6 | Issuing a client certificate takes the CA key's **passphrase**. The CA key is not uploaded; it **stays on the server** | §13 |
| R7 | The **whole configuration** is exported to and imported from **one JSON file** that includes everything | §16 |
| R8 | Domains, backends and nginx options (max body size etc.) are **all configured in the web UI** | §7 |
| R9 | **No checklists** displayed on top of any page | §8.5 |
| R10 | **User management**. **OTP setup is mandatory at first login**. Reset-password and reset-OTP scripts ship in the repo; there are no recovery codes | §9 |
| R11 | Flow: configure in the UI, then the admin runs `install.sh` over SSH to apply. Applying must **never break** the running proxy | §4, §6.3, §6.5 |
| R12 | **External blocklists** can be defined; they are downloaded and applied automatically | §14.5 |
| R13 | Without a host name, the UI is reachable **by IP, from private addresses only**. Once a host name is configured, it is reachable **only by that host name**. The one exception, always available: an SSH tunnel to the box's loopback listener | §8.2 |
| R14 | The web UI may **read** the nginx configuration and other system state wherever that makes it more accurate or resilient, e.g. to notice files changed by hand | §5.3, §6.8 |
| R15 | `install.sh` provides **everything Debian 13 needs to run as a proxy**. The documented path: install Debian 13, install git, create an SSH key on the server, add it to GitHub, clone, run `install.sh`. From then on `install.sh` is the whole deployment workflow | §6.2, §6.6, §6.7 |
| R16 | An **access link authorises exactly one site** | §11.1 |
| R17 | The AI-based security also **analyses behaviour** and identifies risky behaviour | §15.7 |
| R18 | **Microsoft sign-in** (Entra ID, OAuth / OIDC) for selected sites; other providers later | §12 |
| R19 | Admins are **notified by e-mail** through an SMTP relay, in time to react to findings before they turn into blocks | §8.6 |

---

## 2. Relation to nginx-proxy-h62

PSPM is a **separate product**. It shares no deployment, servers, sites, data or
configuration with `nginx-proxy-h62`, and there is no migration between the two.

It reuses proven building blocks from that project's code as a starting point. This
plan describes all of them, so it does not depend on the h62 documents:

| Building block | In PSPM |
|---|---|
| Lua gates, block check, loading state from snapshot files | `lua/`. Gates take a list of conditions instead of a mode name (§7.5) |
| Snapshot files: PHP publishes, nginx loads, nginx never opens the DB | §11.3 |
| Access links, cleared IPs, login lockout | §11 |
| Client-certificate PKI with revocation and scopes in Lua | §13. The CA key now stays on the server |
| Security scan with AI verdicts; honeypots | §15 |
| `install.sh` habits: transcript log, lock, idempotent checks, exit codes | §6 |

---

## 3. Architecture

```
                          Debian 13 host
 internet ─▶ netfilter  PSPM-INPUT: private ranges, allow sets ─▶ pass
               │                    block set, blocklist set  ─▶ DROP   (every port)
               ▼
            nginx (workers: www-data)
               │  rewrite  block.lua ─┐
               │  access   gate.lua  ─┼─▶ shared dicts ◀── load ── snapshot files
               │     │                │                          /var/lib/pspm/state/
               │     └─ sign-in check ─▶ Docker: oauth2-proxy, 127.0.0.1 ─▶ identity provider
               ├─▶ backends           │                              ▲          ▲
               ▼                      │                      writes  │          │ reads
            php-fpm pool "pspm" ──────┴── UI · access links · scan job · blocklist fetcher
               │ Unix socket          reads, never writes: live nginx releases,     │
               ▼                      logs, public certificates, /proc (§5.3)       │
            Docker: postgres:18 (network: none)                                     │
                                                                                    │
 root only:  install.sh  (packages, migrations, app release, render + apply nginx
                          and oauth2-proxy, certificates, code updates)             │
             pspm-agent  (loads the firewall sets from the snapshot files ──────────┘,
                          writes status JSON for the dashboard)
```

| Principal | Runs | May | May not |
|---|---|---|---|
| root via SSH: `install.sh`, `scripts/*` | provisioning, updates, apply, recovery | everything | — |
| `pspm-agent` (root, systemd) | firewall sync, status reports | maintain its own chain and ipsets; write `/var/lib/pspm/status/` | touch nginx config, read the DB |
| `pspm` (php-fpm pool, timers) | UI, access links, scan job, blocklist fetcher, e-mail notifications, scheduled export | read/write the DB; write snapshot files; make outbound HTTPS requests; send mail through the configured SMTP relay; **read** system state that holds no secret (§5.3) | write code, nginx config or certificates; read private keys; use Docker; run anything as root |
| `pspm-render` | the renderer, during apply only | turn JSON into nginx and oauth2-proxy files (stdin → stdout) | read the DB or any secret |
| `www-data` (nginx workers) | requests | read snapshot files | open the DB |
| postgres (container) | the database | — | any network access |
| oauth2-proxy (container per sign-in provider, uid 65532) | sign-in for sites that use OAuth (§12) | answer nginx's auth subrequests on 127.0.0.1; talk HTTPS to its identity provider; use Redis | read the DB, snapshot files or anything else on the host |
| redis (container) | sign-in sessions (§12.6) | listen on 127.0.0.1, password required | any other network access |

**The design rule:** nothing in the web UI leads to root. The agent is the only root
process that consumes data written by the UI. It reads lists of addresses, validates
every entry (§14.3), and can only fill its own sets.

---

## 4. Static configuration vs runtime state

This split shapes the whole plan.

| | Static configuration | Runtime state |
|---|---|---|
| Examples | sites, host names, routes, backends, access policy per site, sign-in providers and per-site sign-in, body size, timeouts, headers, TLS options, extra ports, LAN ranges, which CAs nginx trusts, error pages, admin host name | access links (one site each), cleared IPs, login bans, blocks, traps, trusted addresses, external blocklists, client certificates (revocation, scopes), behaviour findings, users, scan mode and settings, AI key |
| Stored as | working-copy tables, frozen into a **revision** (one JSON document) | ordinary tables |
| Takes effect | when `install.sh` applies a committed revision | **immediately**: snapshot file → `/pspm-sync` → Lua dicts; agent → ipsets |
| Why | it changes nginx files, which only root writes | it must react in seconds, and it acts only within the policy the static config set |

The flow also adds a security property. Everything that **widens** what nginx lets
through (a site's policy, a new public route, a newly trusted CA, a new port, the admin
host name, a new sign-in provider or looser sign-in rules) needs a second,
SSH-authenticated step. A hijacked UI session alone cannot open a site to the internet,
make nginx trust a planted CA or point a site's sign-in at a foreign identity provider.
`install.sh` points out such widening changes before it asks for confirmation (§6.3
step 3). Runtime state can only act within that frame. An access link, for example,
opens exactly one site, and only if that site's policy accepts cleared addresses.

---

## 5. Layout

### 5.1 Repository (`/opt/pspm`)

```
install.sh              the single entry point: install, update, apply, rollback, status, doctor
README.md
app/                    PHP web UI and CLI
  public/               docroot: index.php (dashboard), sites.php, backends.php, access.php, …
  lib/                  db, auth, totp, render, validate, pki, secscan, behaviour, traps, blocklists,
                        oauth, state, live (system state and drift), notify, export, …
  bin/                  CLI: render.php, migrate.php, user.php, export.php, import.php, secscan.php,
                        blocklists.php, notify.php, selftest.php
  vendor/               vendored PHP libraries: PHPMailer (SMTP)
  assets/               vendored Bootstrap 5, QR-code JS, PSPM CSS/JS
  help/                 operator docs (Markdown), shown under Help
nginx/
  static/               fixed parts: http.conf (maps, zones, log format, Lua wiring), snippets, error pages
  templates/            site, sign-in host, management, IP-access and catch-all servers (filled by lib/render.php)
lua/                    pspm.lua, gate.lua (incl. the sign-in check), block.lua, sync.lua
agent/                  pspm-agent (firewall sync, status JSON)
db/migrations/          0001_init.sql, 0002_….sql
docker/compose.yml      the PostgreSQL service
docker/oauth2-proxy/    templates for the per-provider config and compose file (§12.2)
systemd/                pspm-agent.{service,path,timer}, pspm-firewall.service, pspm-secscan.timer,
                        pspm-blocklists.timer, pspm-notify.timer, pspm-backup.timer, nginx.service.d/pspm.conf,
                        tmpfiles.d/pspm.conf
motd/                   50-pspm: the SSH login message (§8.2)
scripts/                reset-password.sh, reset-otp.sh, create-admin.sh, unblock-ip.sh, export.sh, import.sh
tests/
docs/
```

### 5.2 Server

| Path | Owner / mode | Content |
|---|---|---|
| `/opt/pspm` | `root:root`, read-only for everyone else | git checkout. Never served directly |
| `/root/.ssh/pspm_deploy` | `root 0600` | the box's read-only GitHub deploy key (§6.6) |
| `/srv/pspm/app/releases/<git-sha>` | `root:root 0755` | app releases. `current` → symlink to the live one |
| `/etc/pspm/` | `root:pspm 0750` | `db.env`, `app.key`, `never-block`, `pspm.conf` (install-time facts) |
| `/etc/pspm/nginx/releases/<rel>/` | `root:root 0755` | rendered nginx trees, oauth2-proxy configs, `revision.json`, `MANIFEST.sha256`; no secrets. `current` → symlink to the live one |
| `/etc/pspm/oauth2-proxy/` | `root:root 0755`; configs `0644`; `<provider>.env` `root 0600`; `redis.conf` `0400`, owned by the Redis container's uid | `compose.yml`; one `<provider>/` config directory per sign-in provider, and its secrets, which Docker passes as environment; the Redis config with its password (§12.2) |
| `/etc/pspm/tls/` | `root:root 0700` | the self-signed IP-access certificate (§8.2); keys of uploaded certificates |
| `/var/lib/pspm/state/` | `pspm:www-data 0750` | snapshot files, including `blocklists/` (PHP writes; nginx and the agent read) |
| `/var/lib/pspm/status/` | `root:pspm 0750` | status JSON from the agent and `install.sh` |
| `/var/lib/pspm/postgres/` | container uid | database files |
| `/var/lib/pspm/redis/` | container uid | Redis data: the sign-in sessions |
| `/var/lib/pspm/backups/` | `root:pspm 0750` | dumps and exports |
| `/var/log/pspm/` | `root:pspm 0750` | one log per `install.sh` run; never contains a secret (§6.5) |

Code is **never writable** by the web user or the nginx user.

### 5.3 What the web UI may read

The `pspm` user may **read** system state wherever that makes the UI more accurate or
helps it notice problems, as long as nothing it reads is a secret. It never writes
outside its own directories.

| Source | Access | Used for |
|---|---|---|
| nginx releases `/etc/pspm/nginx/` (live, previous, `revision.json`, `MANIFEST.sha256`) | group `pspm` via `/etc/pspm/`; holds no secret | *Changes* diffs against what is really on disk; drift (§6.8) |
| Debian's `/etc/nginx/`, the systemd drop-in | world-readable | drift: the drop-in is in place, nothing unmanaged expects to be loaded |
| nginx processes in `/proc` (command line, start times of master and workers) | unprivileged | which config nginx runs, when it last reloaded |
| Public certificate files `/etc/letsencrypt/{live,archive}/*/{cert,chain,fullchain}*.pem` | ACL `u:pspm:rx` on the directories; `privkey*.pem` stay `0600 root` | exact SANs and expiry; the *Ready to apply* preview knows which sites would be pending |
| nginx logs `/var/log/nginx/` | default ACL `u:pspm:r`, so rotated files keep it | security scan; errors after a reload, on *Changes* and the dashboard |
| `install.sh` logs `/var/log/pspm/` | group `pspm` | full apply logs in the UI |
| Loopback endpoints: `/pspm-release`, `/pspm-sync?status=1`, oauth2-proxy `/ready` | HTTP on 127.0.0.1 | what nginx and oauth2-proxy actually run |
| Unit and timer states | `systemctl is-active` / `show`, unprivileged | *System* tile |
| The git checkout `/opt/pspm` | world-readable | code version shown in the UI |

Still root-only, so the agent reports them in `/var/lib/pspm/status/`: ipset contents
and rule counters (they need `CAP_NET_ADMIN`), private keys, `nginx -T` (it opens
private keys), and container state. The Docker socket is root-equivalent and is never
opened to `pspm`.

Whatever the UI reads is only shown or compared. Rendering and applying still use the
facts that root collects at apply time (§6.3 step 1).

---

## 6. `install.sh`

### 6.1 Usage

```
sudo /opt/pspm/install.sh                      # install or update everything, then apply the newest committed revision
sudo /opt/pspm/install.sh update               # deploy new code: fast-forward pull, then the full run (§6.7)
sudo /opt/pspm/install.sh update --to <commit> # deploy a specific commit of the tracked branch, e.g. the previous one
sudo /opt/pspm/install.sh apply                # apply only (skips packages and the app release)
sudo /opt/pspm/install.sh apply --revision 14  # a specific revision
sudo /opt/pspm/install.sh rollback             # back to the previously applied release (works without the DB)
sudo /opt/pspm/install.sh status               # applied vs pending, health, IP-certificate fingerprint
sudo /opt/pspm/install.sh doctor               # read-only checks: renewal, firewall, DB, php-fpm, disk, time sync
sudo /opt/pspm/install.sh firewall off|on      # kill switch for the firewall layer (§14.7)
sudo /opt/pspm/install.sh --import backup.json # fresh box: install, restore everything, apply (§16.4)

options: --yes  (no confirmation prompt)   --dry-run  (render and test, switch nothing)
```

A plain run uses whatever is checked out, so a manual `git pull` followed by
`install.sh` also works. A pull alone changes nothing that is live.

### 6.2 What a run does

| # | Phase | Work | If it fails |
|---|---|---|---|
| 1 | Preflight | root, Debian 13, `flock`, log file, free disk, git state (warn on local edits), note the SSH client address | abort, nothing changed |
| 2 | Packages | **first run on a fresh box:** `apt-get update && apt-get full-upgrade` once, because nothing is live yet (a reboot is suggested at the end if the kernel changed). **Later runs:** install **missing** packages only, never an upgrade. The set: nginx, libnginx-mod-http-lua (+ lua-resty-core), luajit (Lua syntax check), php8.4-fpm/cli/pgsql/mbstring/curl/intl, openssl, ca-certificates, curl, jq, certbot, ipset, iptables, acl, docker.io, docker-cli (Debian 13 ships the client separately), docker-compose, git, unattended-upgrades | abort before anything live changes |
| 3 | System baseline | what Debian needs to run as a proxy: time sync (`systemd-timesyncd` unless another NTP client runs; TOTP and certificates depend on it) · `/etc/sysctl.d/90-pspm.conf` (listen backlog, local port range for many upstream connections, conntrack table size) · open-file limit for nginx (in the drop-in, plus `worker_rlimit_nofile`) · security updates from the Debian security archive (`unattended-upgrades`, set up on the first run only, so an admin can turn it off) · a journald size cap. **sshd is left alone**; `doctor` reports risky SSH settings instead | abort |
| 4 | Users, dirs, secrets | system users `pspm` and `pspm-render`; the tree from §5.2; the read ACLs from §5.3; secrets generated **once**, never overwritten; the IP-access certificate (renewed when the box's addresses change) | abort |
| 5 | Database | `docker compose up -d`, wait for healthy (≤ 120 s) | abort, nginx untouched |
| 6 | Backup | `pg_dump` + JSON export to `backups/pre-install-<ts>/` (skipped while the DB is empty) | abort: no migration without a backup |
| 7 | Migrations | pending files from `db/migrations/`, each in its own transaction | abort; the DB is unchanged (PostgreSQL has transactional DDL) |
| 8 | App release | copy `app/` to `releases/<sha>`, `php -l`, `bin/selftest.php`, switch `current`, reload php-fpm, check `/healthz` over loopback | switch back to the previous release |
| 9 | System units | systemd units and timers, the nginx drop-in (§6.3), certbot hook, logrotate, tmpfiles, the SSH login message (§8.2) | abort |
| 10 | Firewall | create the chain and sets if missing, run one agent sync. On the first run, the SSH client's address is added to `never-block` (printed, so it can be removed) | warning; nginx still blocks |
| 11 | Bootstrap | first run only: an `admin` user with a generated password, printed once (or the users from `--import`) | abort |
| 12 | Apply configuration | §6.3, nginx and oauth2-proxy | automatic rollback |
| 13 | Certificates | §6.4 | warning; the affected sites stay *pending* |
| 14 | Report | summary, apply record in the DB, status JSON, the URLs where the UI answers | — |

Exit status: `0` success · `1` failed (live state unchanged, or rolled back) · `2` applied
with warnings · `3` cancelled, nothing applied.

### 6.3 Applying the configuration

**Who owns nginx's main config.** PSPM does not edit Debian's `/etc/nginx/nginx.conf`.
A systemd drop-in, `/etc/systemd/system/nginx.service.d/pspm.conf`, starts, tests and
reloads nginx with `-p /etc/pspm/nginx/current/ -c nginx.conf`. With the release as
nginx's prefix, every path inside a release is relative: `nginx -t -p releases/<rel>/`
tests exactly the new tree, and a diff between releases shows only real changes.
Debian's `modules-enabled` snippets use prefix-relative paths, so the renderer loads the
modules by absolute path (collected as a fact). A package update of nginx
therefore never overwrites PSPM's config and never prompts about a conffile.
`sites-enabled/` is backed up once and emptied.

Each release directory is **self-contained**: the generated `nginx.conf` and all its
includes reference only files inside that release. Debian's `mime.types`,
`fastcgi_params` and `modules-enabled/` are the exceptions. A release can therefore be
tested in full before it goes live.

Steps:

1. **Read.** Load the newest committed revision (or `--revision N`) from PostgreSQL and
   store it as `releases/<rel>/revision.json`. Run the drift check (§6.8) on what is
   live. Collect the **facts** the renderer needs: which Let's Encrypt certificates exist
   (names, SANs, expiry), the box's addresses, the php-fpm socket, the nginx version, the
   SSH ports. The UI reads most of the same facts itself (§5.3), so its preview matches,
   but only root's copy is used here.
2. **Render.** Run `bin/render.php` as `pspm-render`, with revision and facts as JSON on
   stdin and `{ "files": { path: content } }` on stdout: the nginx tree and one
   oauth2-proxy config per sign-in provider (§12.2), without secrets. Root writes the
   files into the release, accepting only whitelisted relative paths. The static parts
   (`nginx/static/`, `lua/`) are copied into the same release, so Lua and fixed config
   are versioned with it. Root then writes `MANIFEST.sha256` over every file. The
   renderer is a pure function, which makes it testable with golden files (§18).
3. **Review.** Print a summary (sites added, removed, changed) and `diff -ru current new`.
   Changes that **open** something are marked in red: a looser access policy, a new
   public route, a new port, a newly trusted CA, the admin host name, a new sign-in
   provider, a changed issuer or client ID, a longer e-mail domain list, looser allowed
   users, sign-in removed from a site. Drift found in step 1 is listed with its diff.
   Then ask `Apply? [y/N]` (`--yes` skips the prompt, but not the drift confirmation of
   §6.8).
4. **Test.**
   - `nginx -t -c releases/<rel>/nginx.conf`
   - a Lua syntax check (`nginx -t` does not load Lua)
   - CA-bundle checks: every entry `CA:TRUE`, self-signed, not expired, and its
     fingerprint matches the DB
5. **Journal.** Write `/var/lib/pspm/apply.journal` (`rel`, `previous`, `state=switching`).
   From here to step 9, `SIGHUP` and `SIGINT` are ignored.
6. **Switch.** `ln -s` to a temporary name, then `mv -T` over `current`, which is atomic.
7. **Reload.**
   - Sign-in providers: install the configs that changed into `/etc/pspm/oauth2-proxy/`
     and recreate those containers, and start new ones (§12.2). The previous configs are
     kept for the rollback. Redis starts with the first provider. Sign-in on a
     recreated provider pauses for a few seconds; sessions survive because they are in
     Redis and the cookie secret stays the same.
   - `systemctl reload nginx`. The reload is graceful.
   - Providers that are no longer used are stopped after step 8.
8. **Verify** (≤ 30 s):
   - nginx is active.
   - The loopback-only `GET /pspm-release` answers `<rel>`, which proves the new config
     is loaded.
   - `error.log` shows no new `[emerg]`, `[alert]` or Lua error since the reload.
   - For every TLS host name, a TLS handshake on `127.0.0.1:443` with that SNI returns the
     expected certificate.
   - The management UI answers `/healthz` over loopback, and on the admin host name if
     that is in effect.
   - Every sign-in provider answers `/ready`, and its `/oauth2/start` redirects to the
     issuer's authorization endpoint.

   Unreachable backends are reported, but they do not trigger a rollback. An identity
   provider that cannot be reached is reported too (the sites fail closed, §12.3).
9. **Roll back** on any failure in 7–8: switch back to `previous`, restore the previous
   provider configs and containers, reload, verify that, then exit 1 with the reason.
10. **Record.** An `applies` row (revision, release, manifest hash, code commit, SSH
    user, result, log excerpt); journal `state=done`; keep the newest 20 releases.

If a run is interrupted (SSH drops), the next run reads the journal and first finishes
step 8 for whatever is live. Because every step is atomic, nginx always runs either the
previous config or the new, tested one.

### 6.4 Certificates

- **Let's Encrypt HTTP-01**, webroot `/var/www/acme`. Port 80 serves the ACME path for
  every configured host name at all times, even before that name has a certificate.
- **A site without a certificate is rendered as *pending*.** Port 80 serves ACME plus a
  503 "certificate pending" page, and port 443 is not served for that name (the catch-all
  handles it). One missing certificate never blocks the rest. This avoids the usual
  chicken-and-egg problem: nginx cannot load a TLS server without its certificate, and
  the certificate cannot be issued unless nginx serves the challenge.
- After the switch, for each pending name whose DNS points at this box: a self-check of
  the challenge path, then `certbot certonly --webroot` with one certificate per site
  (all its host names as SANs). If any certificate was issued, render and apply again,
  with the same safety steps.
- The ACME e-mail address is optional (*Settings*). Expiry is watched by the dashboard.
- **Renewal:** `certbot.timer` with a deploy hook that takes the same lock as
  `install.sh`, runs `nginx -t` and reloads.
- **Custom certificates** (uploaded in the UI): the key is stored encrypted with
  `app.key`, and `install.sh` writes it to `/etc/pspm/tls/<site>/` (`0600`).
- The UI reads the public certificate files itself (§5.3), so the dashboard and the
  preview show exact SANs and expiry. Private keys stay root-only.
- **Overview** (*Certificates → Server certificates*): every certificate the box presents
  or trusts, with names, issuer, key, validity, what uses it (from the live release) and a
  state. Let's Encrypt certificates with fewer than 25 days left count as *renewal
  overdue* (certbot renews at 30), the IP certificate warns 60 days ahead, trusted client
  CAs a year ahead. Also listed: `certbot.timer` and its next run, and the certificates
  the next `install.sh` run will request, with Let's Encrypt refusals. The IP certificate
  is read from a copy `install.sh` puts into the status directory (`/etc/pspm/tls` holds
  its key and stays root-only).
- Later: wildcard certificates via DNS-01, which keep new host names out of the
  Certificate Transparency logs.

### 6.5 Resilience rules

- Nothing goes live before its replacement has passed its test: the nginx release
  (`nginx -t`), the app release (lint + selftest), the migration (transaction).
- Every switch is an atomic rename. The previous version is kept and restored on failure.
- `install.sh` never stops nginx, never runs `apt upgrade`, and only ever touches its own
  firewall chain and sets.
- One lock (`/run/lock/pspm.lock`) is shared by `install.sh`, the certbot hook and the
  agent's rule maintenance.
- **There is always a way back into the UI:**
  - The management server is rendered from a fixed template with few parameters.
  - Until a host name is in effect, the UI answers by IP from private addresses (§8.2).
  - It always answers on `127.0.0.1:9443`, so `ssh -L 9443:127.0.0.1:9443 root@proxy`
    works whatever a revision did to host names, certificates or policies. This
    listener always runs (decided in review), and the SSH login message shows how to
    use it (§8.2).
- **The database is optional for the data path.** If PostgreSQL is down, nginx keeps the
  last snapshots, firewall entries expire on their own (kernel timeouts), and `rollback`
  works from disk.
- **Manual edits are never lost or adopted silently** (§6.8).
- **Sign-in fails closed.** If oauth2-proxy or the identity provider is down, sites that
  require sign-in answer 503; their other conditions (LAN, certificate) still work.
- **Idempotent.** A second run without changes changes nothing, and says so.
- The script's body is a `main()` function called on the last line, so bash parses the
  whole file before running it. A `git pull` during a run cannot corrupt it.
- Every run writes `/var/log/pspm/install-<ts>.log` and exits non-zero on failure.
- **No secret reaches a log file.** Generated passwords are written to the terminal
  only, and decrypted secrets are never echoed.

### 6.6 From a fresh Debian 13 to a running PSPM

Only the steps before the repository is on the box are manual. Everything after that is
`install.sh`, which installs whatever Debian needs to run as a proxy (§6.2 phases 2–3).
The commands run as root (on a minimal Debian, `sudo` may not be installed).

1. **Install Debian 13** from the netinst image. In *Software selection*, choose only
   **SSH server** and **standard system utilities**: no desktop, no web server. Give the
   box a fixed address (static, or a DHCP reservation) and its host name.
2. **Install git**, the only package needed before the clone:
   ```bash
   apt-get update && apt-get install -y git
   ```
3. **Create the deploy key on the server**, one per box. The private key never leaves
   it:
   ```bash
   install -d -m 700 /root/.ssh
   ssh-keygen -t ed25519 -N '' -C "pspm@$(hostname -f)" -f /root/.ssh/pspm_deploy
   cat >> /root/.ssh/config <<'EOF'
   Host github.com
       IdentityFile /root/.ssh/pspm_deploy
       IdentitiesOnly yes
   EOF
   cat /root/.ssh/pspm_deploy.pub
   ```
4. **Add the key to GitHub:** the repository's *Settings → Deploy keys → Add deploy key*.
   Paste the public key and leave *Allow write access* **off**. A deploy key opens only
   this one repository, read-only, and each box's key can be removed on its own.
5. **Check GitHub's host key and clone:**
   ```bash
   ssh -T git@github.com    # compare the fingerprint with the ones GitHub publishes, then accept
   git clone git@github.com:<owner>/pspm.git /opt/pspm
   ```
6. **Run the installer:**
   ```bash
   /opt/pspm/install.sh
   ```

The first run asks nothing. At the end it prints:

- `https://<address>/` for every private address of the box, with the SHA-256
  fingerprint of the self-signed IP certificate to compare in the browser
- the generated `admin` password, once, to the terminal only (never to the log)
- *reboot recommended* if the first upgrade installed a new kernel

Open the URL from a private address, sign in, choose a password and enrol OTP. On a box
without a private address (e.g. a VPS), use `ssh -L 9443:127.0.0.1:9443 root@<box>` and
`https://localhost:9443`. The admin host name, ACME e-mail and everything else are set in
the UI and take effect with the next `install.sh` run.

`doctor` checks the deploy key (`git ls-remote`), so a key removed on GitHub shows up
before the next update.

### 6.7 Deploying updates

`install.sh` is the whole deployment workflow. New code is deployed with:

```bash
sudo /opt/pspm/install.sh update
```

1. Refuse if `/opt/pspm` has local changes or is not on its tracking branch.
2. `git fetch`; show the new commits (`git log --oneline HEAD..@{u}`) and any new
   migrations; ask.
3. `git merge --ff-only`: never a merge commit, never a forced reset.
4. Run itself again from the new code (`exec`), which then does the full run of §6.2:
   backup, migrations, app release, apply.
5. Record the old and the new commit in the apply record.

`update --to <commit>` deploys a given commit of the tracked branch, for example the
previous one. Going back is safe for the database because migrations only ever add
(§10.3).

The agent runs `git fetch` once a day without merging, so the dashboard can show that
updates are available. Nothing is ever deployed without an admin running `update`.

### 6.8 Changes made outside PSPM (drift)

Someone may edit files under `/etc/pspm/nginx/current/`, remove the systemd drop-in, or
put files into Debian's `/etc/nginx/` expecting them to work. PSPM notices this, shows
it, and never loses or adopts it silently.

**What is compared,** by the UI every minute and whenever *Changes* is opened, using
read access only (§5.3):

| Check | Finding |
|---|---|
| Files of the live release against its `MANIFEST.sha256` | changed, added or missing files |
| File times against the start time of the nginx workers | *edited, not loaded yet* or *edited and loaded* |
| The nginx master's `-c` argument, the systemd drop-in | nginx runs a config that is not PSPM's (red) |
| `/pspm-release`, `current`, the DB's last apply | nginx, disk and DB disagree about what is live |
| Files in Debian's `sites-enabled/` and `conf.d/` | *present but not loaded*: PSPM's config does not include them |
| Installed oauth2-proxy configs against the release | changed by hand |
| The firewall chain, the jump and the sets (from the agent) | missing, moved or extra rules (the agent also repairs them, §14.3) |

**Shown:** the *Proxy* tile turns amber, or red if nginx runs a foreign config. *Changes*
shows a read-only diff of every changed file against its manifest version.

**At the next apply,** `install.sh` lists the drift with its diff and explains that the
new release replaces it. It goes ahead only after `yes` is typed, or with
`--discard-drift` in unattended runs; `--yes` alone is not enough. The edited release is
not deleted: it stays on disk as `previous`, so nothing typed by hand is gone.
`rollback` to an edited release warns first.

**Never adopted.** Hand-written directives do not go into the configuration model, which
holds typed fields only (§7.6). A change that is needed is made in the UI. If the UI has
no field for it, that is a missing feature, not a reason to edit files.

**Database behind disk:** if the DB was restored from an older backup, the UI still
shows what is really live (from `current/revision.json`) and offers *Load the live
configuration as working copy*.

---

## 7. Configuration model (what the UI configures)

### 7.1 Global settings

| Setting | Default |
|---|---|
| Admin host name (the UI) | empty: the UI is reachable by IP from private addresses only (§8.2) |
| Admin UI access on the host name | LAN **or** client certificate, then password + TOTP |
| ACME e-mail | empty (optional) |
| LAN ranges (IPv4 and IPv6), used by the *LAN* condition | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| TLS profile | *intermediate* (TLS 1.2 + 1.3, ECDHE AEAD ciphers); *modern* = TLS 1.3 only |
| Default security headers | `nosniff`, `Referrer-Policy strict-origin-when-cross-origin`, `server_tokens off`, hide `X-Powered-By` |
| Default HSTS | on, `max-age` 1 year, `includeSubDomains` |
| Rate-limit profiles | *off*, *standard* (100 r/s per address, burst 200), *strict* (10 r/s, burst 20) |
| PSPM error pages (403/404/429/502/503/504) | on |
| Unknown host names | connection closed (444), counted by the unknown-host rule (§15.6) |
| Firewall enforcement | on (§14) |
| E-mail notifications (SMTP relay, sender) | off until a relay is set (§8.6) |

The ranges that are **never blocked** (§14.2) are not a setting. They are hard-coded.

### 7.2 Site

| Group | Fields |
|---|---|
| General | primary host name, aliases, enabled, description, tags |
| TLS | certificate: *Let's Encrypt* / *custom upload* / *none (HTTP only)* · TLS profile · HTTP/2 · HSTS (off / on, max-age, includeSubDomains, preload) |
| Port 80 | *redirect to HTTPS* / *serve the same routes* / *ACME only, 404 otherwise* |
| Client certificates | *request (optional)* / *do not request* (no certificate prompt in the browser) |
| Access | policy and sign-in (§7.5, §12.1) · response when denied: *403* / *404* (do not reveal that something is there) / *302 to a URL* / *close (444)* |
| Limits | `client_max_body_size` (0 = unlimited) · rate-limit profile · `limit_conn` |
| Proxy defaults | backend · `Host` sent upstream: *client's host* / *fixed name* · connect/read/send timeouts · WebSocket · request buffering (off for large uploads) · response buffering |
| Headers | request headers to the backend (name + value, e.g. `X-Client-IP` = *client address*) · response headers to add · headers to hide · security-header profile override |
| Extra listeners | additional plain-HTTP or TLS ports, e.g. a device-management port such as 8080 |

### 7.3 Routes (nginx `location`s)

An ordered list per site. Each route has:

| Field | Values |
|---|---|
| Match | *prefix* (`^~`) · *exact* (`=`) · *any of several prefixes* |
| Listeners | 443 · 80 · an extra port |
| Action | *proxy to backend* · *return status* · *redirect* · *proxy the ACME challenge to the backend* (for a backend that obtains its own certificate) |
| Overrides | access policy and sign-in, each alone or both (e.g. one public path on an otherwise closed site, `/mcp` for the LAN without sign-in, or the callbacks `/signin-oidc` `/signout-callback-oidc` of an application with its own Microsoft sign-in: *exact*, public, sign-in *none*), body size, timeouts, backend, `Host` |
| Without the prefix | off by default · for a *prefix* route that proxies: the backend gets the path without the prefix (below) |

Regular expressions are not offered. A list of prefixes covers the cases that would need
one.

**Without the prefix** (added 2026-11-17) puts an application that runs at `/` under a
path, e.g. two applications on one host name: `/site1/` to one backend, `/site2/` to
another.

- The path is stored with a trailing `/`, so `/site1` does not also take `/site1abc`.
  `/site1` redirects to `/site1/` unless another route has that path. The redirect has
  the route's access and sign-in, and is answered after block.lua and the gate (from Lua,
  not with nginx's `return`, which answers before them). So on a closed site a public
  `/site1/` redirects without sign-in, and a closed `/site3` reveals nothing (2026-11-18).
- Each route can have its own access (its *Overrides*): e.g. `/site1/` public, `/site2/`
  with the site's sign-in. Public on a site whose sign-in is *required* also needs
  sign-in *none* (public AND signed in is signed in). A route that signs in uses the
  site's provider, which must be chosen even when the site itself does not sign in.
- `/site1/page?x=1` reaches the backend as `/page?x=1` (nginx's normalised path:
  `%2F` and the like arrive decoded).
- The backend gets `X-Forwarded-Prefix: /site1`; frameworks that honour it write their
  links under the prefix (ASP.NET Core: `ForwardedHeaders` with `XForwardedPrefix`).
- Redirects of the backend, relative or to the site's host name, and the paths of its
  cookies are put under `/site1/`; those already under it stay. So two applications on
  one host name do not overwrite each other's cookies.
- Not rewritten: links inside pages and scripts. An application that writes absolute
  links such as `/css/app.css` and ignores `X-Forwarded-Prefix` needs its own host name.
- Stored only when on: routes of existing installations, their revisions and their
  rendered configuration stay exactly as they were.

### 7.4 Backends

| Field | Values |
|---|---|
| Name | unique |
| Servers | `host:port`, weight, *backup*, `max_fails` / `fail_timeout` (passive health) |
| Protocol | `http` / `https` |
| TLS verification | *off* / *system CAs* / *custom CA* (PEM pasted in the UI) |
| TLS name | SNI and verify name (`proxy_ssl_name`) |
| Keepalive | idle connections kept to the upstream |
| Response header buffer | 16 (default) / 32 / 64 / 128 KB (`proxy_buffer_size`, with `proxy_buffers` and `proxy_busy_buffers_size` derived so that `nginx -t` accepts them). Larger headers than the buffer make nginx answer 502 and log *upstream sent too big header* (large cookies, long CSP headers, SSO tokens). A property of the application, so it is set on the backend and applies to every site and route that uses it. nginx's own default is one memory page (4 KB); PSPM sets 16 KB in `http.conf`. |

### 7.5 Access policy

A policy has two parts. The first is a set of **conditions, OR-ed**: any one is enough.

| Condition | Met when |
|---|---|
| `lan` | the client address is in the LAN ranges (§7.1) |
| `cleared` | the address was cleared **for this site** through an access link (§11.1) |
| `cert` | the client presented a **valid certificate**: verified by nginx against the CA bundle, not revoked, in scope for this site, and listed in PSPM if its CA is PSPM-managed (§13.3) |
| `public` | always |

The second is **sign-in** at the site's OAuth provider (§12):

| Sign-in | Effect |
|---|---|
| *none* | the conditions alone decide |
| *alternative* | a valid sign-in also lets the request in (OR): "from the LAN, or signed in" |
| *required* | a valid sign-in is needed **in addition** (AND): "with a certificate and signed in". With `public`, anyone who can sign in |

The UI offers presets:

| Preset | Conditions | Sign-in |
|---|---|---|
| Certificate | cert | none |
| Cleared or certificate | cleared, cert | none |
| LAN, cleared or certificate | lan, cleared, cert | none |
| LAN or cleared | lan, cleared | none |
| Cleared only | cleared | none |
| LAN only | lan | none |
| Signed in | public | required |
| LAN or signed in | lan | alternative |
| Certificate and signed in | cert | required |
| Public | public | none |

**How nginx enforces it**, for every request:

1. **`block.lua`** (rewrite phase, every server):
   - Private addresses pass.
   - A blocked address is refused, unless it has a valid certificate in scope for this
     site, is on the LAN, or is cleared for this site.
   - An untrusted address that hits an active trap, or keeps asking for unknown host
     names, is blocked on the spot (§15.5–15.6).
2. **`gate.lua`** (access phase): a banned address is refused (§11.2). Then the
   conditions of the route, or else of the site, are checked from `$pspm_allow` (e.g.
   `lan,cleared,cert`) and `$pspm_site`. These are shared-dict lookups only, with no disk
   and no database. Last comes the sign-in check, if the policy has one (§12.3).

### 7.6 Validation and rendering

The DB is written by the web user, so `install.sh` treats it as untrusted input.

- **No free-text nginx directives, anywhere.** nginx's master process runs as root and
  can run Lua at init. A raw-directive field would let anyone who can write the DB run
  code as root. Every option is a typed field, and the renderer is the only code that
  writes nginx syntax.
- **Strings** are checked against strict patterns:
  - host names: IDNA to punycode, RFC 1123
  - paths: no whitespace, quotes, braces, `;` or `$`; the prefix `/.pspm/` is reserved
    for access links (§11.1)
  - header names: RFC 9110 tokens
  - header values: printable ASCII without `"`, `\` or `$`
  - URLs: `http`/`https` with a valid host name
  - sign-in groups, e-mail addresses and domains: strict patterns, URL-encoded by the
    renderer

  **`$` is never accepted** because nginx would expand it as a variable. Choices that
  need a variable (client host, client address) are enums.
- **Numbers have bounds.** Body size 0–100G, timeouts 1 s–24 h, ports 1–65535 except the
  SSH ports.
- **Checked twice:** on save in the UI, and again in the renderer.
- **Consistency at commit:**
  - no host name in two sites
  - no duplicate match within a site
  - every enabled site has a route
  - routes point only at existing, enabled backends
  - the admin host name and the sign-in hosts are not taken by a site, and no two providers
    share a sign-in host (the admin host name may be one of them, §12.3)
  - every site with sign-in lies inside its provider's cookie domain (§12.1)
- **Deterministic output.** Fixed ordering, so unchanged input gives byte-identical
  files and diffs show only real changes.

### 7.7 Revisions

```
working copy ──"Ready to apply"──▶ revision N (immutable JSON + SHA-256, author, message)
     ▲                                     │ install.sh
     └── "revert to revision N" ◀──────────┴──▶ applied (release, SSH user, result, log)
```

- **"Ready to apply"** validates and renders a preview in PHP, using the last known
  facts. The *Changes* page shows the rendered diff against what is live on disk
  (§5.3).
- `install.sh` applies the **newest committed** revision. Edits made later are not
  included, and the script says so.
- There is one shared working copy. Optimistic locking per object (`updated_at`)
  prevents lost updates between admins.

---

## 8. Web UI

### 8.1 Branding

- The product is **PSPM**, subtitle *Secure Proxy Manager*: navbar, page titles,
  `<title>`, login page, README heading.
- The full name appears **only in small print**: the login-page footer, the About
  dialog, and the first paragraph of the README. It is never in a heading, a title, the
  navbar, a certificate subject or an e-mail.
- Logo: a plain "PSPM" monogram or shield.
- Stack: PHP 8.4 without a framework, Bootstrap 5 and a little vanilla JS. Everything is
  served locally, with a strict CSP (`script-src 'self'`).
- **Contrast and colour modes:** text, borders and secondary text are darker than
  Bootstrap's defaults; pages sit on a tinted background with cards and tables as
  surfaces. A switch in the navigation bar chooses *auto* (follow the system), *light*
  or *dark*; the choice is kept per browser. `assets/theme.js` applies it in `<head>`
  (a file, because of the CSP), so a dark page never flashes light. Asset URLs carry the
  code version, so an update loads the new files at once.
- **Settings** has two groups: *configuration* (part of a revision, applied with
  `install.sh`) and *runtime* (takes effect at once), each as titled cards with a line on
  what the card is for, and a section index at the top.
- `tests/screenshots.sh` takes light and dark screenshots of chosen pages for review.

### 8.2 Reaching the UI

| State | `https://<server IP>/` | `https://<admin host>/` | `127.0.0.1:9443` (SSH tunnel) |
|---|---|---|---|
| No admin host name | UI, **private source addresses only**; anyone else: connection closed | — | UI |
| Host name configured, its certificate not yet issued | still UI as above; the dashboard says IP access ends once the certificate exists | ACME + "certificate pending" | UI |
| Host name **in effect** (configured and served with a valid certificate) | **connection closed for everyone**, like any unknown host | UI (admin access policy, §7.1) | UI |

How it works:

- **Private source addresses** are a hard-coded list, the same one that is never
  blocked: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `fc00::/7`,
  `fe80::/10`, `::1`. It is not the configurable LAN list.
- **The catch-all server** (`default_server` on 80 and 443) serves the UI only when all
  of these hold: no admin host name is in effect, the request names an IP address (or
  sends no SNI), and the source is private. Port 80 then redirects to
  `https://<same IP>/`. Everything else is closed (444) and counted by the unknown-host
  rule.
- **IP certificate:** self-signed, created by `install.sh`, with SANs for all addresses
  of the box and valid for 10 years. Its fingerprint is printed by `install.sh` and
  `install.sh status`.
- **"In effect"** is decided at apply time. A configured host name without a working
  certificate never ends IP access, so setting the host name cannot lock anyone out.
- **The loopback listener** always runs (decided in review). It is reachable only from
  the box itself, in practice through an SSH tunnel, and still needs password + TOTP. It
  is the way back in when the host name, its certificate or the admin access policy is
  broken, and the way to set up a box that has no private address.
  - 127.0.0.1 is never banned (it is a never-blocked range, §14.2). Failed sign-ins over
    the tunnel only slow down the account (§9.2), so the tunnel cannot be locked.
  - Other local processes (php-fpm, the containers on the host network) can reach it
    too. They meet the same password + TOTP sign-in.
- **SSH login message.** `install.sh` installs `/etc/update-motd.d/50-pspm`, so every SSH
  login shows how to reach the UI:

  ```
  PSPM · Secure Proxy Manager · revision 15, applied 2026-11-09 14:03 by alice
    UI:       https://admin.example.ch/
    Tunnel:   ssh -L 9443:127.0.0.1:9443 root@proxy.example.ch   then https://localhost:9443/
    Pending:  revision 16 is ready, apply with: sudo /opt/pspm/install.sh
  ```

  - The agent writes the text to `/var/lib/pspm/status/motd` every minute. The login
    script only prints that file, so it is instant and needs neither the DB nor the
    network.
  - The *Tunnel* line is always shown, even when the status is stale or missing.
  - The other lines appear when they apply: the UI addresses by IP while no host name
    is in effect, a pending revision, drift (§6.8), *updates available* (§6.7), a red
    dashboard tile.
  - The product is named as in the UI (§8.1).
- **Access links** are served on the host names of the sites they open (§11.1), so they
  work without an admin host name and never reveal it.

### 8.3 Pages

| Page | Content |
|---|---|
| **Dashboard** | first page (§8.4) |
| Sites | list (host, backend, policy, cert state, pending marker) and editor (§7.2, §7.3) |
| Backends | upstreams (§7.4) |
| Access | access links and cleared IPs, per site; login bans |
| Certificates | CAs, issuing (passphrase), issued certificates (revoke, scopes) |
| Sign-in | OAuth providers (§12): state, sites using them, *Test sign-in* |
| Security | blocks (nginx and firewall state), **blocklists**, AI verdicts, **behaviour findings** (§15.7), traps, trusted addresses, scan settings |
| Changes | working copy vs what is live on disk: diff, *Ready to apply*, revisions, apply history with full logs, live nginx files (read-only), drift (§6.8) |
| Settings | §7.1, AI provider and key, SMTP relay with *Send test e-mail*, backup passphrase |
| Users | users, roles, e-mail address, notification categories, OTP state, sessions |
| Backup | export, import, list of backups |
| Activity | audit log |
| Help | operator docs from `app/help/` |

The navbar shows a count badge on *Changes* while something is not applied.

### 8.4 Dashboard

A grid of tiles. Each tile is green, amber or red, and links to its page.

| Tile | Shows |
|---|---|
| Proxy | nginx running · applied revision (when, by whom) · last apply result · live files match the applied release, or *changed outside PSPM* (§6.8) · how the UI is reached (IP / host name) |
| Changes | *Revision 15 is ready — on the server run `sudo /opt/pspm/install.sh`* (copy button), or *3 changes not yet marked ready*, or *everything applied* |
| Sites | enabled sites by policy · sites waiting for a certificate |
| Certificates | next TLS expiry · client certificates expiring within 30 days · CA expiry |
| Traffic (24 h) | requests, denied, blocked: small sparklines from the activity table |
| Blocks | active in nginx / in the firewall (the two should match) · new in 24 h · trap hits |
| Blocklists | lists OK / warning / failed · entries loaded · packets dropped in 24 h |
| Security scan | mode · last run · circuit breaker |
| Behaviour | open findings by risk · the next block if nobody reacts, with the time left · red if a finding concerns an authorised actor (§15.7) |
| Sign-in | providers ready · sign-ins and denials in 24 h · identity provider reachable |
| Access | active grants · links used in 24 h |
| System | PostgreSQL up, size, last backup · disk · agent heartbeat · code version, *updates available* (§6.7) · e-mail delivery (last sent, failures) |
| Packages | Debian packages that can be upgraded, how many from the security archive, the list · *reboot required* · amber when security updates wait for more than two days (unattended-upgrades installs them daily), `apt-get update` failed, or the lists are older than three days. The root agent counts every hour from the lists as they are; `pspm-apt.timer` runs `apt-get update` once a day, and only when the lists are older than 20 hours (Debian's `apt-daily` usually refreshed them already). PSPM never upgrades packages by itself. The SSH login message shows the same. |
| Recent activity | the last 10 audit events |

The UI reads most facts itself (§5.3). Those only root can see (ipset contents, rule
counters, container state) come from the agent's status JSON, and a tile shows how old
that data is (normally under 1 minute).

### 8.5 No checklists

- No setup checklists, no "*n* of *m* steps", no "Setup complete ✓", and no stack of
  banners at the top of a page.
- In the UI, a problem is shown **in two places only**: as a coloured tile on the
  dashboard, and as a badge next to the object it concerns (the CA row, the site row, the
  blocklist row), with the fix in a tooltip or popover. Outside the UI, it can also
  arrive by e-mail (§8.6).
- The only element at the top of a page is the dismissible one-line result after an
  action.

### 8.6 E-mail notifications

Decided in review: notifications go out by **e-mail through an SMTP relay**. They matter
most for behaviour findings, which turn into blocks when nobody reacts (§15.7).

**Relay** (*Settings*, admin):

| Field | Values |
|---|---|
| Host, port | e.g. `smtp.office365.com:587` |
| Security | *STARTTLS* (default) or *TLS* (port 465), with the certificate verified. *None* is accepted only for a relay at a private address |
| Login | optional user name and password. The password is stored encrypted with `app.key` and sent only over TLS |
| Sender | default `pspm@<box FQDN>` |
| Extra recipients | addresses that are not users, e.g. a team mailbox |

*Send test e-mail* checks the settings at once. The relay is runtime state, so it takes
effect without `install.sh`.

**Recipients:** every user can give an e-mail address and choose categories under
*Users*. The defaults depend on the role:

| Category | Sent when | Default |
|---|---|---|
| Findings | a behaviour finding opens; again 2 h before its reaction time runs out; when it becomes a block | admin, operator |
| Health | a dashboard tile turns red, and when it is green again: certificate renewal, sign-in provider, blocklists, backups, agent, disk, drift, circuit breaker | admin |
| Accounts and PKI | users created or changed, password or OTP reset (also by script), CA created or its key exported, certificates issued | admin |
| Changes | a revision is ready; a revision was applied or rolled back | off |

**Sending:**

- Events are written to an outbox table. `pspm-notify.timer` sends them every minute as
  `pspm`, using the vendored PHPMailer, and retries with backoff for up to 24 h.
- **Only `pspm` sends mail.** Root processes (agent, certbot hook, `install.sh`) report
  through their status JSON, and PHP turns red states into mail.
- **No flood:**
  - one mail per issue and state change
  - more than 5 mails within 10 minutes become one digest
  - at most 50 mails an hour, then a single *notifications paused* mail
- **Content:**
  - plain text, subject prefix `[PSPM]`
  - what happened, when, and the deadline for findings
  - a link that only **opens** the page in the UI. A mail never contains an action
    link, a secret or an access-link token
- **Delivery does not move the deadline.** If mail cannot be delivered, the *System* tile
  turns red. The reaction time of a finding still runs from its creation, because
  blocks only ever affect untrusted addresses.

---

## 9. Users, login and OTP

### 9.1 Roles

| | admin | operator | viewer |
|---|:-:|:-:|:-:|
| Dashboard, read everything | ✓ | ✓ | ✓ |
| Access links, cleared IPs, blocks, trust, revoke certificates, act on behaviour findings | ✓ | ✓ | |
| Issue certificates (needs the CA passphrase) | ✓ | ✓ | |
| Sites, backends, sign-in providers, settings, blocklists, *Ready to apply* | ✓ | | |
| CAs, users, export, import | ✓ | | |

### 9.2 Login flow

1. **Username and password** (Argon2id via `password_hash`), behind the rate limits and
   IP lockout of §11.2. Per account there is an increasing delay, but never a permanent
   lock, because that would let an attacker lock the admin out.
2. **Password change**, if the password was generated or reset by a script
   (`must_change_password`).
3. **TOTP enrolment, mandatory, no skip**, if the user has no confirmed secret: a QR code
   drawn in the browser by vendored JS (the secret never goes to a third party), the
   secret as text, and confirmation with one valid code.
4. **TOTP code** on every later login.

Until steps 2–3 are done, the session can reach only those pages and *Sign out*.

### 9.3 TOTP

- RFC 6238: SHA-1, 6 digits, 30 s, ±1 step. That works with every authenticator app.
- **Replay protection:** the last used time step is stored per user.
- 160-bit secret, **encrypted at rest** with `/etc/pspm/app.key` (libsodium secretbox),
  so a DB dump alone does not reveal it.
- **No recovery codes** (decided in review). A user who lost their authenticator asks an
  admin with SSH access, who runs `reset-otp.sh` (§9.5); the user enrols again at the
  next sign-in.

### 9.4 Sessions

- Stored in PostgreSQL, not in files, so scripts and admins can end them.
- Cookie `__Host-pspm`: `Secure`, `HttpOnly`, `SameSite=Strict`. Expires after 1 h idle,
  12 h at most.
- **Re-authentication** (password + TOTP) for import, user management, creating or
  removing a CA, editing a sign-in provider, and export.
- Resetting a password or OTP ends all of that user's sessions. *Users* lists open
  sessions with *Revoke*.
- Every change is written to `audit_log` (who, from where, what, before/after as JSONB).

### 9.5 Scripts (`/opt/pspm/scripts/`)

```bash
sudo /opt/pspm/scripts/reset-password.sh <user>   # prompts, or --generate; change forced at next login; ends sessions
sudo /opt/pspm/scripts/reset-otp.sh <user>        # deletes the TOTP secret; enrolment at next login; ends sessions
sudo /opt/pspm/scripts/create-admin.sh <user>     # recovery when no admin can sign in
sudo /opt/pspm/scripts/unblock-ip.sh <ip>         # lifts login bans and blocks, in nginx and the firewall
```

- Root only. They run the app's own CLI (`bin/user.php`) as user `pspm`, with the same
  hashing and the same audit entries (marked *by root via script*).
- They need only the database, not nginx or the UI.
- Each run is mailed to the admins as an *Accounts and PKI* notification (§8.6).

---

## 10. PostgreSQL in Docker

### 10.1 Docker

- Installed from **Debian's packages** (`docker.io`, `docker-compose`), with no
  third-party apt repository. `install.sh` checks `docker compose version`.
- `/etc/docker/daemon.json`:
  - `"live-restore": true`: the container keeps running while dockerd restarts or is
    upgraded.
  - `"log-driver": "local"`: rotated logs.
- Docker also runs one oauth2-proxy container per sign-in provider and one Redis for
  their sessions (§12.2), all with docker compose. Each container gets only what it
  needs: PostgreSQL has no network, oauth2-proxy and Redis listen on 127.0.0.1.

### 10.2 The container

```yaml
# docker/compose.yml
services:
  postgres:
    image: postgres:18@sha256:<pinned digest>   # changed deliberately, never "latest"
    container_name: pspm-postgres
    network_mode: none                          # no network at all: Unix socket only
    restart: unless-stopped
    env_file: /etc/pspm/postgres.env
    volumes:
      - /var/lib/pspm/postgres:/var/lib/postgresql
      - /run/pspm/postgres:/var/run/postgresql   # the socket, shared with the host
    shm_size: 256m
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "pspm"]
      interval: 10s
```

- The app connects with `pgsql:host=/run/pspm/postgres;dbname=pspm` and a password
  (scram-sha-256) from `/etc/pspm/db.env` (`root:pspm 0640`).
- No TCP port is published, so Docker adds no rules for it. `tmpfiles.d` recreates the
  socket directory at boot.

### 10.3 Schema and migrations

- Plain SQL files in `db/migrations/NNNN_name.sql`, tracked in `schema_migrations`. Each
  runs in one transaction.
- **Only `install.sh` migrates.** An app that finds an older schema than it needs shows a
  maintenance page instead of running.
- **Expand, then contract:** a release only adds. Drops follow one release later, so
  rolling the app back is always safe.
- Types:
  - `uuid` keys for configuration objects, stable across export and import
  - `inet`/`cidr` for addresses
  - `timestamptz`
  - `jsonb` for revisions and evidence
- Every block table has a `CHECK` that refuses the never-blocked ranges (§14.2).
- **Tables by area:**
  - auth: `users` (incl. e-mail address and notification categories), `sessions`, `login_failures`, `banned_ips`, `audit_log`
  - notifications: `notification_outbox`
  - config: `settings`, `sites` (routes, listeners and headers inside the site's validated JSON), `site_hosts`, `backends` (servers inside), `custom_certs`
  - sign-in: `oauth_providers`, `site_signin` (provider, mode, allowed users, identity headers)
  - revisions: `config_revisions`, `applies`
  - access: `access_links`, `cleared_ips` (both with their `site_id`)
  - PKI: `cas`, `client_certs`
  - security: `trusted_ips`, `ip_activity`, `ai_verdicts`, `auto_blocks`, `scan_runs`, `scan_state`, `traps`, `trap_votes`, `attack_paths`, `attack_path_ips`, `trap_blocks`
  - behaviour: `behaviour_hours`, `behaviour_baselines`, `risk_findings`
  - blocklists: `blocklists`, `blocklist_fetches`

### 10.4 Backups

| What | When | Where | Kept |
|---|---|---|---|
| `pg_dump -Fc` + JSON export | before every `install.sh` run | `backups/pre-install-<ts>/` | 20 |
| `pg_dump -Fc` + JSON export (secrets encrypted with the backup passphrase from *Settings*) | nightly (`pspm-backup.timer`) | `backups/nightly-<date>/` | 14 days |
| JSON export | on demand, in the UI or `scripts/export.sh` | download / chosen path | — |

Off-box copies are the admin's job. The *Backup* page and the dashboard show the age of
the newest backup. Restore: `install.sh --import <file>` (complete), or `pg_restore` for
the DB alone (documented in Help).

### 10.5 When things fail

| Down | Effect |
|---|---|
| PostgreSQL | nginx serves with the last snapshots; blocks, grants and blocklists stay as published; UI shows a maintenance page; access links answer 503; `install.sh rollback` works; `apply` first tries to start the DB |
| php-fpm | nginx and the firewall unaffected; UI and access links unavailable; blocklists are not refreshed (entries stay until their maximum age) |
| Agent | nginx blocks as before; firewall entries expire on their own; the dashboard shows a stale heartbeat |
| oauth2-proxy (one provider) | its sites with sign-in *required* answer 503 "sign-in unavailable"; with *alternative*, LAN, cleared and certificate still work; other sites are unaffected |
| Redis | like oauth2-proxy down, for all providers (fail closed); after the restart the sessions are back, because Redis keeps them on disk |
| Docker daemon | the containers keep running (`live-restore`) |

Major PostgreSQL upgrades (18 → 19) are a separate, explicit command, `install.sh
db-upgrade`: dump, start the new container, restore, verify, switch, keep the old data
directory. That comes later.

---

## 11. Access links, cleared IPs, login bans

### 11.1 Access links

An access link lets someone without a certificate into **exactly one site**, by clearing
the address they open it from for that site.

| Option | Values |
|---|---|
| Site | one site; only sites whose policy contains *cleared* are offered; or the admin UI (below) |
| Grant | how long a visit clears the address: 1 h … 90 days, or permanent |
| Link validity | until a date or until revoked; optional maximum number of uses |
| After the grant | the site's start page, or a path on the same site (so there is no open redirect) |
| Label | who it is for |

**The link lives on the site's own host name:** `https://<site host>/.pspm/access/<uuid>`.
It is HTTPS only and public, with at most 30 requests per minute per address. The
`/.pspm/` prefix is reserved (§7.6) and answered by PSPM's fixed access-link script, never
by the backend.

- The visitor opens the host name they are going to use. The address that gets cleared
  is therefore the one their browser really uses for that site, IPv4 or IPv6.
- The recipient never learns the admin host name.
- The token is checked together with the host name. A link for site A does nothing on
  site B, not even if someone copies the path across.

Visiting the link:

1. A banned address is refused.
2. The address (IPv4 address, IPv6 `/64`) is cleared **for this site** for the grant
   time. If the address is blocked in nginx, the block stays for every other site; on
   this site the clearance takes precedence (§7.5).
3. The address becomes *authorised* (§15.2). That puts it in the firewall's web allow
   set, which opens only the web ports (§14.2), never SSH.
4. A confirmation page is shown, or the redirect to the chosen path follows.

*Access* lists links per site (use count, last use, addresses) and cleared addresses per
site (remove, purge expired). Revoking a link ends the clearances it gave.

**Links to the admin UI.** A link can open the admin UI instead of a site, for an admin
away from the LAN without a client certificate. It needs:

- an admin host name: the link is used there (`https://<admin host>/.pspm/access/<token>`),
  never on a site host or by IP
- *Access links* ticked under *Settings → Admin access*: the admin server then accepts the
  condition *cleared* for the scope `admin` and serves `/.pspm/access/`; the review shows it
  as an OPENS line
- the admin role to create one (operators can revoke)

The link opens only the network gate. Signing in still needs a PSPM account with password
and code. Cleared addresses are keyed by a *scope*, the site's id or `admin`, which is also
the `$pspm_site` nginx checks.

### 11.2 Login protection

- **nginx rate limits:**
  - sign-in POSTs: 10/min (burst 3)
  - the rest of the UI: 5 r/s (burst 20)
  - access links: 30/min (burst 10)

  Over the limit, nginx answers 429.
- **Lockout:** 30 failed sign-ins from one address within 1 h ban it for 24 h (all three
  values configurable). nginx refuses a banned address on every site and in every policy
  before anything else, and the firewall drops it (§14.4).
- **`X-Forwarded-For` is ignored.** nginx is the edge, so the peer address is the client.
- **Lifting bans:** *Access* lists them (lift, purge expired); `unblock-ip.sh` works on
  the server.

### 11.3 How runtime state reaches nginx

- PHP is the only component that talks to PostgreSQL. After each change it writes the
  affected snapshot files into `/var/lib/pspm/state/`:
  - one file per list: `cleared` (keyed by site and address), `banned`, `certs`,
    `blocked`, `traps`, `trusted`, plus `blocklists/`
  - each written atomically (temp file + rename) and carrying a serial number

  Then it calls the loopback-only `/pspm-sync`.
- nginx rebuilds its shared dicts from the files **in place**: it sets the new keys,
  then deletes the stale ones. No grant goes missing during a sync. Expiry is enforced
  by dict TTLs.
- nginx loads the files at every start and reload. It therefore starts with the last
  published state even if PHP or the DB is down.
- The agent reads the same directory for the firewall (§14.3).
- `/pspm-sync?status=1` reports what nginx has loaded (serials, counts). The dashboard
  compares that with the DB.

---

## 12. Sign-in with Microsoft (OAuth / OIDC)

Selected sites can require a sign-in with Microsoft (Entra ID). Only Microsoft is
supported for now (decided in review); the model keeps a provider type, so other OpenID
Connect providers can follow later. PSPM runs **oauth2-proxy** for this, in auth-request
mode only. nginx asks it whether a request's session is valid, and then proxies to the
backend itself; oauth2-proxy never carries application traffic.

The design avoids the weaknesses that oauth2-proxy setups behind nginx commonly have
(§12.7).

**PSPM's own UI does not use it.** The UI keeps password + TOTP, so getting into PSPM
never depends on an external provider.

### 12.1 Model

| Object | Fields |
|---|---|
| **Provider** | name · type: *Microsoft Entra ID*, the only one for now · tenant ID (→ issuer `https://login.microsoftonline.com/<tenant>/v2.0`, single tenant) · client ID · client secret · scopes (`openid email profile offline_access`; `offline_access` is needed for the hourly re-check) · groups claim (`groups`, or `roles` for app roles) · accepted e-mail domains (an explicit list; *any* is possible but marked) · **sign-in host** (e.g. `auth.example.com`) · session lifetime (default 24 h, at most 7 days) · re-check interval (default 1 h) · start page of the sign-in host (a URL, or 404) |
| **Site** (*Access* group) | sign-in: *none* / *alternative* / *required* (§7.5) · provider · allowed users: *everyone the provider accepts*, or groups, e-mail addresses and e-mail domains · identity headers to the backend (§12.4) · requests that are not from a browser: *401* instead of a redirect (default for non-GET requests and when `Accept` does not include `text/html`) |
| **Route** | sign-in override, alone or with an access override, e.g. `/mcp` for the LAN without sign-in, or an application's own sign-in callbacks (Microsoft returns there with a cross-site form POST, which does not carry the SameSite=Lax session cookie) |

- **The ACME challenge never asks for sign-in.** `/.well-known/acme-challenge/` (PSPM's own
  and a route that proxies it) is public with sign-in *none*, also on a site that requires
  sign-in; otherwise Let's Encrypt gets 401 and the certificate cannot be renewed.

- **One provider is one app registration** in Entra, one sign-in
  host, and one cookie domain: the common parent of the sign-in host and every site that
  uses the provider (e.g. `.example.com`). A site outside that domain needs a second
  provider (the same Entra app with a second redirect URI, another sign-in host). Validation enforces this (§7.6).
- **Static configuration.** Providers and site sign-in settings go through revisions and
  `install.sh`. The widening changes among them are marked red in the review (§6.3
  step 3).
- **Secrets:** the client secret and the cookie secret (generated once per provider) are
  stored encrypted with `app.key` and are part of the export's encrypted section.

### 12.2 One container per provider

```yaml
# rendered into the release; installed as /etc/pspm/oauth2-proxy/compose.yml
services:
  oauth-<provider>:
    image: quay.io/oauth2-proxy/oauth2-proxy:v7.<n>@sha256:<pinned digest>   # never "latest"
    network_mode: host          # outbound HTTPS to the IdP; listens on 127.0.0.1 only
    user: "65532"
    read_only: true
    restart: unless-stopped
    env_file: /etc/pspm/oauth2-proxy/<provider>.env                         # secrets, root 0600
    command: ["--config=/etc/oauth2-proxy/oauth2-proxy.cfg"]
    volumes:
      - /etc/pspm/oauth2-proxy/<provider>:/etc/oauth2-proxy:ro

  redis:                        # sessions of all providers; plain Redis, default settings
    image: redis:8@sha256:<pinned digest>
    network_mode: host
    restart: unless-stopped
    command: ["redis-server", "/usr/local/etc/redis/redis.conf"]
    volumes:
      - /etc/pspm/oauth2-proxy/redis.conf:/usr/local/etc/redis/redis.conf:ro   # bind 127.0.0.1, port, requirepass
      - /var/lib/pspm/redis:/data
```

- **Listener** `127.0.0.1:4180 + n`, one port per provider. Host networking avoids
  Docker's NAT and the docker-proxy, so oauth2-proxy sees nginx as 127.0.0.1 and
  `trusted-proxy-ip` can be set exactly. Its replies to the IdP pass the firewall's reply
  rule (§14.2).
- **Config without secrets** is rendered into the release (versioned, diffable, covered
  by the manifest) and installed by `install.sh` into `/etc/pspm/oauth2-proxy/<provider>/`.
  The secrets are in `<provider>.env` (`root 0600`); Docker passes them as environment.
- **Always set by PSPM:**
  - `reverse-proxy`, `trusted-proxy-ip=127.0.0.1/32`, `upstream=static://202`
  - `session-store-type=redis`, `redis-connection-url=redis://127.0.0.1:6379`; the Redis
    password comes from the provider's `.env`
  - `code-challenge-method=S256` (PKCE)
  - `cookie-refresh` = the re-check interval; `cookie-expire` = the session lifetime
  - cookie `Secure`, `HttpOnly`, `SameSite=Lax`, its own name per provider, the cookie
    domain
  - `cookie-csrf-per-request`, so two tabs do not break each other's sign-in
  - `whitelist-domain` = the **exact host names** of the provider's sites, no wildcard
  - `email-domain` = the configured list
  - `set-xauthrequest`; `pass-access-token` only if a site forwards the token
  - `skip-provider-button`, `footer=-`
  - `insecure-oidc-allow-unverified-email=false`
  - request logging off, auth logging on; logs rotated by Docker's `local` driver
- **Startup needs DNS and the IdP** (OIDC discovery). The restart policy retries.
  `install.sh` waits for `/ready` (§6.3 step 8), and the dashboard shows the provider as
  down until it answers.

### 12.3 Request flow

```
Browser ─▶ nginx (site) ─▶ gate.lua
             conditions met (lan / cleared / cert) and sign-in "alternative" ─▶ pass
             otherwise, or sign-in "required":
               subrequest /_pspm/oauth/<provider>/auth?allowed_groups=…   (no body)
                 202      ─▶ pass; identity from X-Auth-Request-User / -Email / -Groups
                 401      ─▶ browser: 302 https://<sign-in host>/oauth2/start?rd=<this URL>
                             other clients: 401
                 403      ─▶ PSPM "not authorised" page
                 error or no answer within 2 s ─▶ 503 "sign-in unavailable" (fail closed)

Browser ─▶ nginx (sign-in host) /oauth2/* ─▶ 127.0.0.1:41xx ─▶ IdP (authorization code + PKCE)
```

- **The check runs in `gate.lua`** (`ngx.location.capture` to an internal location).
  That way sign-in combines with the other conditions as OR or as AND, which nginx's
  `auth_request` cannot do.
- **The subrequest's headers are set by nginx:** `X-Real-IP`, `X-Forwarded-Proto`,
  `X-Forwarded-Host` and `X-Forwarded-Uri` come from nginx's own variables. Whatever the
  client sent under those names is dropped.
- **The sign-in host** is a system site with a certificate and ACME like any other site.
  `/oauth2/` is rate-limited (60 per minute per address, burst 120). `/` goes to the
  configured start page or answers 404, and every other path answers 404.
  The sign-in host may also be the **admin host name** (e.g. the box's own name). Then one
  server serves both: `/oauth2/` is public as on any sign-in host, and the UI keeps the
  admin access (LAN, certificate). Any valid certificate covering the name is used.
- **Small cookies:** the sessions are in Redis, so the cookie carries only a ticket. No
  split cookies and no enlarged header buffers are needed.

### 12.4 What the backend receives

- **Identity headers,** chosen per site from a fixed list: `X-Forwarded-User`,
  `X-Forwarded-Email`, `X-Forwarded-Groups`, `X-Forwarded-Preferred-Username`,
  `X-Remote-User` (= e-mail). The access token (`X-Forwarded-Access-Token`) is optional
  and off by default.
- **These headers are always set, on every route of every site:** to the signed-in
  identity, or else to an empty value. A client can never pass its own `X-Remote-User`
  to a backend, not even on a route that is exempt from sign-in.
- **No inheritance trap.** In nginx, a `location` with its own `proxy_set_header` loses
  all server-level ones. The renderer therefore writes the complete header list into
  every `location`, and a golden-file test checks it.
- **The session cookies are removed** from the `Cookie` header before proxying. The
  cookie is valid for the whole cookie domain, so a backend that saw it could replay it
  against the provider's other sites.

### 12.5 Who may sign in, per site

- *Allowed users* are rendered into the subrequest's query (`allowed_groups`,
  `allowed_emails`, `allowed_email_domains`). A user admitted to one site is therefore not
  automatically admitted to every site of the provider.
- Groups need the groups claim. For Entra, Help explains the token configuration (the
  groups claim, or app roles with `roles` as the claim for large tenants) and *assignment
  required* on the enterprise app.

### 12.6 Sessions, sign-out, trust

- **Sessions in Redis** (decided in review), in a plain Redis container with its
  default settings and a data volume, so a restart does not sign everyone out. There is
  no extra session handling in PSPM. Because of the re-check interval and
  `offline_access`, oauth2-proxy refreshes the session at Microsoft every hour. A user disabled there loses access within that hour, not at the end of the
  session lifetime.
- **Sign-out:** `https://<sign-in host>/oauth2/sign_out`. A site route can redirect
  there.
- **Trust:** a successful sign-in makes the address *authorised*, like a certificate
  (§15.2). It goes into the firewall's web allow set and is never blocked automatically.
- **Logging:** the security log records the sign-in result and the user per request. The
  behaviour analysis uses it (§15.7), and the AI only ever sees a pseudonym.

### 12.7 Common weaknesses avoided

Pitfalls of a typical oauth2-proxy setup behind nginx, and what PSPM does instead.

| Common weakness | In PSPM |
|---|---|
| sessions last days without a refresh: a user disabled at the IdP keeps access | re-check every hour with `offline_access`; lifetime 24 h by default |
| paths exempt from sign-in pass client-sent identity headers to backends | identity headers always set or blanked, on every route |
| server-level `proxy_set_header` is silently ignored in locations that set their own | the complete header list rendered into every location |
| `trusted-proxy-ip` unset: client `X-Forwarded-*` headers reach oauth2-proxy | host network, `trusted-proxy-ip=127.0.0.1/32`, headers set by nginx |
| image tag `latest` | pinned by digest |
| no PKCE | S256 |
| container log without rotation | Docker `local` log driver; request logging off |
| every user of the tenant can open every application | allowed users per site |
| a wildcard domain as the redirect whitelist | exact host names |
| CSRF failures with two tabs; the version shown in the footer | a CSRF cookie per request; footer off |
| the start fails while DNS is not ready | restart policy; `/ready` checked by `install.sh` and the dashboard |
| the session cookie reaches every backend under the cookie domain | session cookies stripped before proxying |
| sessions over 4 kB split into several cookies, with a warning on every login | sessions in Redis; the cookie holds only a ticket |

---

## 13. Client-certificate PKI: the CA key stays on the server

### 13.1 CAs

| Topic | Design |
|---|---|
| Create | Generated on the server: RSA 4096, SHA-256, self-signed root with `CA:TRUE, pathlen:0`, valid 10, 15 or 20 years, unique subject. It signs client certificates directly; nginx is configured with `ssl_verify_depth 1` |
| Key storage | The private key is **wrapped and stored** in `cas.key_wrapped`. Argon2id (`sodium_crypto_pwhash`, MODERATE limits) derives a key from the passphrase; XChaCha20-Poly1305 encrypts; the CA's id and fingerprint are the associated data, which binds the key to its CA. OpenSSL's PKCS#8 encryption is not used because its PBKDF2 is far cheaper to brute-force |
| Passphrase | at least 16 characters, or *Generate* (5 random words). Never stored, logged or put in the session; it lives only in the POST that uses it |
| Change passphrase | re-wrap; needs the old passphrase |
| Export the key | encrypted PKCS#8 PEM with a passphrase of your choice, for offline safekeeping |
| Import | certificate plus, optionally, its key (PEM, with its password) → re-wrapped. Certificate only = **trust only**: in the bundle, but it cannot issue |
| Trust in nginx | Each CA has a *trusted by nginx* flag. It is **static configuration**: `install.sh` renders the CA bundle from the flagged CAs and checks it (§6.3 step 4). A UI user can create a CA, but nginx trusts it only after the SSH step |
| Expiry | the dashboard warns from one year before the end, because client certificates can run up to 6 years |

### 13.2 Issuing

- **Form:**
  - CA
  - subject: `<user>@<domain>` or `<domain>`
  - duration: 1 week to 6 years, never past the CA's expiry
  - label
  - sites (scope): all, or a selection
  - PKCS#12 compatibility (on by default)
  - the CA passphrase
- **Steps:**
  1. Consume the one-time nonce.
  2. Unwrap the CA key in memory.
  3. Generate an RSA 2048 client key with `clientAuth` and a random 63-bit serial.
  4. Build the `.p12` with `openssl pkcs12 -export`, the key passed on a pipe, never a
     file.
  5. Record certificate, serial, fingerprints, CN, scope, expiry, CA and issuer.
  6. Wipe the key material (`sodium_memzero`).
- **Wrong passphrase:** one generic message. 5 failures in 10 minutes per user start a
  cool-down, so the passphrase cannot be brute-forced through the UI.
- **`.p12` password:** generated as `<word><4 digits>` and shown once. Compatibility mode
  (3DES/SHA-1) imports into old macOS, iOS, Android and Windows keychains, so the
  password is only casual protection. Hand over the file and the password through
  different channels.
- **Result page:** rendered in the POST response itself (no redirect, `Cache-Control:
  no-store`); the download starts through a JS Blob. The form uses no file upload, so
  nothing reaches `upload_tmp_dir`. A refresh cannot issue twice because of the nonce.
- **Client private keys are never stored.**

### 13.3 Revocation, scopes, strict mode

- **Revoke** in the UI, with a reason. It takes effect on the next request, even on an
  open connection: the `certs` snapshot feeds a Lua dict keyed by the SHA-1 fingerprint
  (`$ssl_client_fingerprint`). Its value is either *revoked* or the certificate's scope.
- **A revoked or out-of-scope certificate counts as no certificate.** The policy's other
  conditions (LAN, cleared) can still let the request in.
- **Strict mode:** a certificate from a PSPM-managed CA counts only if PSPM issued it.
  One signed outside PSPM with that CA's key is refused. Certificates from trust-only CAs
  count when nginx verified them, unless they were revoked by fingerprint.
- **No CRL.** nginx's `ssl_crl` would need a CRL for every CA in the bundle, a reload for
  every change, and the CA key for every update.
- **Revoking also removes the trust** the certificate gave its addresses (§15.2).

### 13.4 Accepted risk (R6)

The encrypted CA key now lives on the server. An attacker who controls the `pspm` user
**and** captures a passphrase as it is typed can issue certificates. What limits that:

- the passphrase is needed only at issuance
- new certificates work only within their site scopes
- every issuance is in the audit log
- the dashboard lists certificates issued in the last 7 days
- revocation takes effect on the next request

---

## 14. Blocking at the firewall

### 14.1 Two layers

| | nginx (Lua) | Firewall (ipset + iptables) |
|---|---|---|
| Speed | the **first** request (trap hit, unknown host) | ≤ 1 s after a block is published (≤ 1 min for trap hits, §15.1) |
| Sees certificates, grants and sign-ins | yes | no: authorised addresses are put in **allow sets**, which are checked first (§14.2) |
| Cost | TLS handshake + request | nothing reaches userspace |
| Covers | the web ports | **every port and protocol**, SSH included |

nginx stays the immediate, precise layer. The firewall is the hard layer: once an
address is blocked, it gets no TCP handshake, no TLS, no SSH and no ping.

### 14.2 Rules

Created idempotently by `install.sh` and, at boot, by `pspm-firewall.service` (before
nginx):

```
# address sets (the same five again with family inet6)
ipset create pspm-allow4     hash:net family inet                                   # never-block, admin-trusted, logged-in SSH peers
ipset create pspm-allowweb4  hash:net family inet timeout 86400                     # authorised: cleared, certificate, sign-in
ipset create pspm-block4     hash:net family inet timeout 86400  maxelem 262144     # PSPM blocks, per-entry timeouts
ipset create pspm-feed4      hash:net family inet timeout 604800 maxelem 1048576    # external blocklists, mode "block"
ipset create pspm-watch4     hash:net family inet timeout 604800 maxelem 1048576    # external blocklists, mode "observe"
# port set, shared by IPv4 and IPv6
ipset create pspm-webports   bitmap:port range 0-65535                              # 80, 443 and the extra listeners

iptables -N PSPM-INPUT
iptables -A PSPM-INPUT -i lo -j RETURN
iptables -A PSPM-INPUT -s 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j RETURN        # private: never blocked
iptables -A PSPM-INPUT -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN   # answers to connections this box opened
iptables -A PSPM-INPUT -m set --match-set pspm-allow4 src -j RETURN
iptables -A PSPM-INPUT -p tcp -m set --match-set pspm-allowweb4 src \
                              -m set --match-set pspm-webports dst -j RETURN        # authorised: web ports only
iptables -A PSPM-INPUT -m set --match-set pspm-block4 src -j DROP
iptables -A PSPM-INPUT -m set --match-set pspm-watch4 src                           # counts only, no target
iptables -A PSPM-INPUT -m set --match-set pspm-feed4  src -j DROP
iptables -I INPUT 1 -j PSPM-INPUT
# IPv6: the private rule passes fc00::/7 and fe80::/10
```

- **Order matters:** loopback and private addresses pass first, as do allowed and
  authorised addresses. Only then do blocks and blocklists drop, on every port.
- **Two allow sets.** Addresses an admin trusts, `never-block` and logged-in SSH peers
  pass on every port. Addresses that are only *authorised* (an access link, a
  certificate, a sign-in) pass on the **web ports only**. A leaked link or certificate
  therefore never opens SSH. `install.sh` writes the web ports of the applied revision
  to `/etc/pspm/webports`, and the agent loads them into `pspm-webports`.
- **The reply rule** lets answers to connections the box opened itself pass. A blocklist
  that contains a package mirror, Let's Encrypt, a DNS resolver or the AI API therefore
  does not break apt, renewals or the scan. Connections *from* a blocked address are
  ORIGINAL-direction traffic and are still dropped, open keep-alive connections included.
- **Expiry is in the kernel.** Block and blocklist entries carry their remaining time, so
  they disappear even if the agent is dead.
- **Never-blocked ranges** are hard-coded in four places: PHP, the SQL `CHECK`, Lua and
  these rules. A test checks that all four agree: `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, loopback, `fc00::/7`, `fe80::/10`.
- PSPM changes neither the default policy nor any other rule.

### 14.3 Agent sync

Triggered by a systemd `.path` unit on `/var/lib/pspm/state/`, plus a 60-s timer.

1. **Read** the snapshots `blocked`, `trusted`, `cleared` and `blocklists/*`, plus
   `/etc/pspm/never-block`, `/etc/pspm/webports` and the peer addresses of **logged-in**
   SSH sessions (`loginctl`). Logged-in sessions are authenticated; a TCP connection from
   a brute-forcer does not count. Those peers stay allowed for 1 h after logout.
   `trusted` carries the kind of each entry (§15.2): *trusted* goes into `pspm-allow`,
   *authorised* and cleared addresses into `pspm-allowweb`.
2. **Validate** every entry:
   - blocks: IPv4 `/32`, IPv6 `/64`, or a manual CIDR no wider than `/16` (IPv4) or
     `/32` (IPv6)
   - blocklists: no wider than their limit (§14.5)
   - expiry in the future
   - never a never-blocked range (dropped again here, as defence in depth)
3. **Cap** each set at its `maxelem`, so a log flood or a huge list cannot exhaust
   memory.
4. **Build** a fresh set, `ipset swap` it with the live one (atomic), destroy the old.
5. **Repair** the chain and the jump if either is missing or no longer first in `INPUT`.
6. **Report** to `status/firewall.json`: entries per set, per-rule packet counters, a
   heartbeat.

### 14.4 What goes into which set

| Source | nginx | Firewall |
|---|:-:|---|
| AI verdict | ✓ | block |
| Honeypot hit | ✓ at once | block (≤ 1 min) |
| Unknown-host rule | ✓ at once | block (≤ 1 min) |
| Login lockout ban | ✓ | block |
| Manual block | ✓ | block by default; per-block option *nginx only* |
| External blocklist | — | feed (or watch in observe mode) |
| Trusted by an admin, never-block, logged-in SSH peer | passes | allow: every port, checked before block and feed |
| Authorised: cleared, certificate, sign-in | passes on its sites | allowweb: web ports only, checked before block and feed |

### 14.5 External blocklists

Defined on *Security → Blocklists*. They are **runtime state**: they can only narrow
access, so they take effect without `install.sh`.

| Field | Values / default |
|---|---|
| Name, enabled | |
| URL | HTTPS only, certificate verified |
| Format | *plain*: the first IP address or CIDR on each line, lines starting with `#`, `;` or `//` ignored (most published lists) · *JSON lines*: one object per line, field name configurable (default `cidr`) |
| Auth header | optional, for providers that require a key; stored encrypted with `app.key` |
| Refresh | every 24 h (at least 1 h) |
| Mode | *block* · *observe*: loaded into the counting-only set, to see what a list would drop before enabling it |
| Widest network accepted | `/8` (IPv4), `/16` (IPv6) |
| Entries per list | at most 250 000 |
| Maximum age | 7 days: if refreshes keep failing, the list's entries expire then |

**No presets ship** (decided in review). Every list is entered with its URL in the UI;
Help describes the supported formats.

**Fetching:** `pspm-blocklists.timer` checks every 15 min what is due. `bin/blocklists.php`
then runs as `pspm`, never as root:

1. GET with `ETag` / `If-Modified-Since`; at most 32 MB and 60 s; User-Agent
   `PSPM-blocklist-fetcher`.
2. Parse, validate, normalise (host bits cleared), deduplicate.
3. Drop the never-blocked ranges, everything else reserved (multicast, documentation,
   `0.0.0.0/8` …), and anything wider than the limit. The refused entries are counted
   and shown.
4. **Sanity check:** an empty list, or one that shrank by more than half, does **not**
   replace the last good list. The list shows a warning and *Accept anyway*.
5. Write `state/blocklists/<id>.txt` atomically, with the fetch time. Record the status:
   HTTP code, entries, refused, changed, error.
6. Compute the overlap with trusted, cleared and never-block addresses and show it per
   list. Those addresses still pass, because the allow sets come first.

**Loading:** the agent puts every list in *block* mode into `pspm-feed4/6` and every list
in *observe* mode into `pspm-watch4/6`. Each entry's timeout is the maximum age minus the
list's age.

**Shown** per list on *Security* and in total on the dashboard: last fetch, entries
loaded, refused, overlap, packets dropped in 24 h (from the rule counters).

### 14.6 Trade-offs

- **Every port: a blocked public address also loses SSH.** What protects admins:
  - private addresses pass first
  - `never-block` (the first `install.sh` run adds the SSH client's address)
  - manual trusted addresses in the UI
  - the addresses of logged-in SSH sessions
  - the hosting provider's console as the last resort
- **A first-time certificate holder or OAuth user behind an address that is already
  blocked** cannot get in, because the firewall sees neither the certificate nor the
  sign-in. This is limited by allowing (on the web ports) every address that has shown
  proper authorisation before.
- **Authorisation opens the web ports only.** Someone who is authorised but also on a
  blocklist reaches their sites, but not SSH.
- **A firewall-blocked address cannot use an access link to lift its block.** It never
  reaches nginx. An admin lifts it in the UI or with `unblock-ip.sh`.

### 14.7 Kill switches

From fastest to slowest:

1. *Settings → Firewall enforcement: off*: the agent empties the block and blocklist
   sets.
2. `install.sh firewall off`: removes the jump.
3. Doing nothing: every entry expires by itself.

### 14.8 Coexistence with Docker

- Docker manages `FORWARD`, `nat` and `DOCKER-USER`. PSPM touches only `INPUT`, through
  its own chain.
- Both must use the same iptables backend (Debian 13: `nf_tables`). `install.sh` and
  `doctor` check this.
- The database container has no network, so no published ports exist.

---

## 15. Security monitoring and honeypots

The AI part was revised (built 2026-11-10): the 300 best honeypots, an injection check
before every model call, a verifier model for every automatic block, the models as
separate fields in Settings, and an AI log of every call. See
[security-ai-improvements.md](security-ai-improvements.md); where it differs from the
sections below, it wins.

### 15.1 Security log and scan job

- **Security log:** nginx writes one JSON line per request to
  `/var/log/nginx/pspm-security.log`:
  - time, client address, host, server, port, method
  - raw and normalised URI, status, upstream status
  - TLS version, client-certificate result and fingerprint, LAN flag, User-Agent
  - request length, bytes sent, request time, upstream response time
  - the policy outcome, the access-link grant used, the sign-in result and user

  Never logged: cookies, auth headers, bodies, referers.
- **Scan job:** `pspm-secscan.timer` runs every minute as `pspm`.
  - **Every minute, a fast pass** records trap and unknown-host blocks from the log and
    publishes them, so the firewall follows within a minute.
  - **Every 5 minutes, a full round:**
    1. read the new lines since the cursor (survives log rotation)
    2. update the trust registry (§15.2)
    3. count activity per address and hour, tagging suspicious paths
    4. update the behaviour features (§15.7)
    5. select candidates: untrusted addresses with enough evidence in 24 h for the
       *blocking aggressiveness* (§15.4), at most 100
    6. ask the AI for verdicts (§15.3)
    7. behaviour (§15.7): **every 12 hours by default** (*Settings → Blocking and trust*,
       1–168 h; *Run now* forces it) run the detectors over the last 24 h, ask the AI to
       assess the findings and record them; **every round** check the reaction
       deadlines and send the reminders, so a block after the reaction time is not late
    8. apply the policy (§15.4) and publish

### 15.2 What counts as authorised: the trust registry

| | Becomes so when | Firewall | Automatic blocks |
|---|---|---|---|
| **Authorised** | it presents a valid certificate, uses an access link, or signs in at an OAuth provider | web allow set: web ports only (§14.2) | never |
| **Trusted** | an admin adds it (address or CIDR, e.g. a monitoring service) | allow set: every port | never |

Every other address is *untrusted*.

- **Still watched.** Both kinds are analysed for risky behaviour (§15.7). Findings are
  shown to an admin, but never turned into automatic blocks.
- **IPv6 per `/64`**, for trust and blocks alike, because privacy addresses rotate
  within a `/64`.
- **Revoking** a certificate or a link removes the authorisation it gave.
- **Duration:** authorisation lasts for N days without a new authorisation (setting,
  default 30). Trust lasts until removed.

### 15.3 AI verdicts

- **Provider:** any OpenAI-compatible API (OpenRouter, OpenAI). Model and key are set in
  *Settings*; an empty model turns the AI off.
- **Data minimisation:** no IP addresses, certificates, link tokens or user names, only
  pseudonyms (`ip-14`, `cert-7`, `link-3`, `user-12`); query values removed. Traffic of
  authorised and trusted actors is sent only for behaviour analysis (§15.7), and
  *Settings* can exclude it.
- **When:** at most once per 15 min, and only when there is a new candidate (*Run now*
  asks at once). Batches of 25, at most 200 calls a day.
- **Answer:** a fixed JSON schema per candidate (*block* / *watch* / *benign*,
  confidence, reason). The evidence sent is stored and shown with the verdict.

### 15.4 Decision policy

The guards are checked in order. The AI cannot override them:

| # | Check | Outcome |
|---|---|---|
| 1 | never-blocked range | never blocked |
| 2 | trusted or authorised, cleared included (checked again now) | not blocked; a behaviour finding instead (§15.7) |
| 3 | an admin removed a block on it in the last 30 days | not blocked |
| 4 | already blocked | skipped |
| 5 | verdict is not *block* | watch / benign |
| 6 | confidence below the threshold of the aggressiveness (0.85 at 0.5) | below threshold |
| 7 | mode *dry-run* | would block |
| 8 | run or day cap reached | capped |
| — | otherwise | **blocked** |

- **Blocking aggressiveness** (*Settings → AI decisions*, 0–1, default 0.5) sets how
  much the AI needs before it blocks:
  - **Evidence before the AI judges an address**, in 24 h, any one of these or a mix in
    proportion. Below it, the address is not sent at all, so it comes back as soon as
    the evidence suffices.

    | | at 0 | at 0.5 | at 1 |
    |---|---|---|---|
    | requests by IP address or for host names no site serves, exploit paths included | 40 | 10 | 3 |
    | requests for exploit paths at a site | 12 | 3 | 1 |
    | refused requests | 80 | 20 | 5 |
    | not-found answers | 160 | 40 | 10 |

    The values are those at 0.5 × 4^(1 − 2a), rounded up. Scanners of the whole
    internet probe the bare IP all the time, so even at 1 a single probe is not enough.
  - **Confidence** for a block (both models, behaviour *attack* included):
    0.95 − 0.2a, i.e. 0.95 / 0.85 / 0.75.
  - Not affected: honeypots block on the first hit (§15.5), and the unknown-host rule
    keeps its own count (§15.6).
- **Durations escalate** per address: 1 day → 7 days → 30 days, counted over 180 days.
  No automatic block is permanent. Manual blocks last 1 d, 7 d, 30 d or 1 year.
- **Modes:** *enforce* (default), *dry-run*, *collect* (no AI calls). The **circuit
  breaker** switches to *dry-run* by itself when one run would add more than 50 blocks,
  or a day more than 300. The *Security scan* tile turns red until an admin switches
  back.
- **Remove** takes an optional reason and keeps the history. *Remove and trust* also adds
  a trust entry. *Remove all* is the bulk kill switch.

### 15.5 Honeypots

- **A trap** is a request path that only attackers ask for: `/.env`, `/.git/config`, or
  `/wp-login.php` on a site without WordPress.
  - Kind: *exact* or *prefix*. Matched against nginx's normalised `$uri`, lower-cased.
    No regular expressions.
  - Scope: the host it was attacked on, or `*` once it has been seen on at least 3
    hosts.
- **Enforcement:** the first request to an active trap from an untrusted address blocks
  that address at once in `block.lua`. The fast pass records the block, and the firewall
  follows within a minute.
- **Lifecycle:** *proposed* → *shadow* (matched but not enforced) → *active*. From there
  a trap can be *disabled*, or *retired* after 90 days without a hit. An admin can
  activate, disable, pin, add or delete traps.
- **Mining:** every 3 h (only if something was refused since the last mining) and on
  *Suggest now*. The AI gets the refused paths of the last 24 h per path and host, with
  counts, status codes and backend answers, and suggests patterns. Each pattern gets at
  most one vote per 3-hour window.
- **Evidence from the backends,** on routes open to the public:

  | Backend answer | Track |
  |---|---|
  | 404 or 410 everywhere the pattern can reach | **fast**: 1 vote, 2 attackers, 1 h in shadow |
  | no backend asked yet | **standard**: 3 votes, 5 attackers, 12 h in shadow |
  | anything else | **rejected**: cannot be activated, not even by hand |

  An active trap whose path a backend later answers is disabled at once. Public routes
  are read from the configuration model.
- **Only the 300 best are active** (see
  [security-ai-improvements.md](security-ai-improvements.md) §1):
  - score per trap over 30 days: distinct attacking addresses, ×1.5 on the fast track,
    ×1.2 for scope `*`, × recency (1.0 within 7 days, 0.5 within 30, 0.2 older)
  - pinned traps are always active and count towards the 300
  - ranked once a day and after each mining run; a shadow trap replaces an active one
    only with a score at least 20 % higher, so traps do not flap
  - traps outside the 300 stay in shadow: matched and logged, so their score keeps growing
- **Safety:**
  - at most 300 active traps (above)
  - a breaker at 200 trap blocks per hour puts every trap back into shadow
  - prefixes need a minimum length

### 15.6 Unknown host names

Five requests within an hour for host names that no site serves block the address. This
includes requests by IP from public addresses, which never reach the UI (§8.2). Private
addresses are never blocked. The values are settings; 0 turns the rule off.

### 15.7 Behaviour analysis: risky behaviour

The verdicts of §15.3 judge an address by what it asked for. Behaviour analysis looks at
**how actors behave over time**, including authorised ones. It reports risky behaviour
even when no single request looks suspicious.

**Actors:**

- an address (IPv4, or IPv6 `/64`)
- a client certificate
- an access-link grant
- a signed-in user

One request can belong to several actors, e.g. an address and a user.

**Features per actor and hour,** computed deterministically by the scan job from the
security log, without AI:

| Group | Features |
|---|---|
| Volume | requests, bytes sent, distinct paths, distinct sites |
| Outcomes | denied, 404, 5xx, **backend 401/403** (failed logins at the application) |
| Shape | method mix, request body sizes, regularity of the intervals (script vs. human), user-agent changes |
| Spread | addresses per certificate, link or user; users per address |
| Time | activity outside the actor's usual hours |
| Sequence | ordered path patterns per site, normalised (ids and numbers replaced), e.g. *login → admin → export* |

**Baselines:**

- per site: usual paths, rates and status mix
- per authorised actor: its own last 30 days

Every feature gets a deviation score against its baseline.

**Detectors** (deterministic) turn features into candidates:

| Pattern | Typical signs |
|---|---|
| Brute force or credential stuffing at a backend | many backend 401s on a login path, from one address or from many |
| Enumeration | sequential ids, many distinct 404s inside an application, directory walking |
| Scraping or bulk download | far above the actor's or the site's usual volume, machine-regular intervals |
| Shared or stolen credential | one certificate, link or user active from several networks at the same time; a new user agent in the middle of a session |
| Leaked access link | one link's grants used from many unrelated networks |
| Probing beyond its scope | an authorised actor collecting denials on other sites or paths |
| Changed behaviour | an authorised actor suddenly active at unusual hours, on new paths, or with a new client |
| Distributed attack on one site | many new addresses with the same sequence within an hour |

**AI assessment.** For each candidate, the scan job sends a pseudonymised behaviour
summary (features, deviations, path sequences, recent verdicts) to the AI. The answer
follows a fixed JSON schema:

- class: *attack* / *risky* / *normal*
- category (one of the patterns above, or *other*)
- risk from 0 to 100, confidence
- reason and suggested action

The summaries share the daily call cap of §15.3. When the AI is off, the detectors still
create findings, marked *not assessed*.

**What happens:**

| Actor | *attack* | *risky* |
|---|---|---|
| Untrusted address | the decision policy of §15.4 (it can be blocked) | finding; **blocked if nobody reacts** within the reaction time |
| Authorised or trusted actor | finding marked red; **never blocked automatically** | finding |
| A site as a whole (distributed pattern) | finding with a suggested change, e.g. a stricter policy, a rate limit or sign-in | finding |

**Findings** appear on *Security → Behaviour* and in the *Behaviour* tile. Each shows the
actor, the pattern, the risk and the evidence: the requests, the summary sent to the AI,
and its answer. The actions that apply are offered next to it:

- *revoke certificate*
- *end clearance* / *revoke link*
- *block address*
- *mark as expected*: suppresses this pattern for this actor for 30 days

**No reaction means a block** (decided in review). A *risky* finding about an untrusted
address waits for an admin for the **reaction time** (setting, default 24 h). The
*Behaviour* tile and the finding show the time left. Choosing *block address* or *mark as
expected* is a reaction. If the time runs out with no reaction, the finding goes through
the guards of §15.4 like a *block* verdict, except for the confidence threshold, because
the missing reaction is the decision. So never-blocked ranges, trust, recent removals by
an admin, *dry-run* and the caps still apply. The block uses the escalating durations,
and its reason says *risky behaviour, no reaction*. Findings about authorised or trusted
actors are never blocked this way. Each finding is mailed when it opens and again 2 h
before its deadline (§8.6).

Every action is in the audit log. Hourly features are kept for 90 days, baselines are
rolling over 30 days, and findings are kept for one year.

---

## 16. Export and import: one JSON file

### 16.1 Contents

| Part | Included | Form |
|---|---|---|
| Settings, sites, routes, backends, custom backend CAs | ✓ | plain JSON |
| Revisions (all committed ones) and apply history | ✓ | plain JSON |
| Access links with their site | ✓ | plain JSON; the UUIDs (bearer tokens) are in the encrypted part |
| Sign-in providers and per-site sign-in settings | ✓ | plain JSON; client and cookie secrets in the encrypted part |
| Cleared IPs (per site), bans, blocks, trusted addresses, traps, scan settings | ✓ | plain JSON |
| Blocklist definitions (not the downloaded lists, which are fetched again) | ✓ | plain JSON; auth headers in the encrypted part |
| CAs (certificates), client-certificate records, scopes, revocations | ✓ | plain JSON |
| CA private keys | ✓ | encrypted part (still wrapped with their own passphrase as well) |
| Users, roles | ✓ | plain JSON; password hashes and TOTP secrets in the encrypted part |
| AI API key, SMTP password, custom TLS certificates and keys, backup passphrase | ✓ | encrypted part |
| History: audit log, activity, verdicts, behaviour findings and baselines, scan runs | ✓ by default; *without history* for a small file | plain JSON |
| Let's Encrypt certificates, keys, renewal configuration and ACME account; `/etc/pspm/never-block` | **CLI only** (decided in review): `scripts/export.sh --with-tls`, `scripts/import.sh`. The UI can neither read nor write the keys | encrypted part |
| Never exported | sessions (PSPM's and the sign-in sessions in Redis), nonces, rate-limit counters, caches, `app.key`, DB and Redis passwords, the IP certificate | — |

### 16.2 Format

```json
{
  "format": "pspm-export",
  "format_version": 1,
  "exported_at": "2026-11-09T14:03:00Z",
  "pspm_version": "<git sha>",
  "schema_version": 7,
  "options": { "history": true, "tls": false },
  "settings":   { },
  "sites":      [ { "id": "…uuid…", "host": "app.example.ch", "routes": [ ], "…": "…" } ],
  "backends":   [ ],
  "revisions":  [ ],
  "access":     { "links": [ { "id": "…uuid…", "site": "…uuid…", "grant": "P7D" } ], "cleared": [ ], "bans": [ ] },
  "signin":     { "providers": [ { "id": "…uuid…", "type": "entra", "signin_host": "auth.example.ch" } ] },
  "pki":        { "cas": [ ], "client_certs": [ ] },
  "security":   { "trusted": [ ], "blocks": [ ], "traps": [ ], "settings": { } },
  "blocklists": [ { "id": "…uuid…", "name": "Provider DROP list", "url": "https://…", "mode": "block" } ],
  "users":      [ { "username": "alice", "role": "admin", "otp": true } ],
  "history":    { "audit": [ ], "activity": [ ], "findings": [ ] },
  "secrets": {
    "kdf": "argon2id", "opslimit": 3, "memlimit": 268435456, "salt": "…",
    "aead": "xchacha20poly1305", "nonce": "…", "ciphertext": "…"
  }
}
```

- The **export passphrase** (at least 16 characters, asked for each export) protects
  `secrets`.
- The AEAD's associated data is the SHA-256 of the canonical plain part. Changing any
  byte of the file makes the import fail, so the file is tamper-evident.
- Keys are sorted and arrays ordered by id. Two exports of the same state are identical
  apart from `exported_at` and the encrypted part (fresh salt and nonce each time), so the
  files can be diffed.

### 16.3 Export

- **UI** (admin, after re-authentication): *Backup → Export*, then download.
- **CLI** (root): `scripts/export.sh [--with-tls] [--no-history] -o file.json`. With
  `--with-tls` the Let's Encrypt material is added, so a new box can serve TLS before DNS
  points to it. Only the CLI can produce a file with TLS material.

### 16.4 Import

1. **Upload** (admin, after re-authentication). Checks:
   - format and version (older formats are migrated forward, newer ones refused)
   - schema
   - decryption with the passphrase
   - every value validated as on save (§7.6)
2. **Preview:** counts per part, a diff of the configuration against the working copy,
   users to be added or changed, and conflicts.
3. **Confirm** by typing `IMPORT`. Then:
   - The current state is exported automatically.
   - Everything is written in **one transaction**.
   - **Static configuration** lands in the working copy. It takes effect after *Ready to
     apply* and `install.sh`.
   - **Runtime state** takes effect immediately and is published to nginx and the agent.
     Blocklists are fetched again.
   - The importing admin's account is never deleted or demoted.
4. **CLI on a running box:** `scripts/import.sh file.json` (root) runs the same checks,
   shows the preview in the terminal and asks for `IMPORT`. It also restores the TLS
   material if the file has it: certificates, keys, renewal configuration and ACME
   account into `/etc/letsencrypt`, plus `never-block`. The UI import skips the TLS part
   and says so.
5. **Fresh box:** `install.sh --import file.json` installs, restores everything (with TLS
   material if present), commits the imported configuration and applies it in one run.

**Round-trip test:** export → import into an empty box → export again gives an identical
plain part and identical decrypted secrets (§18).

---

## 17. Security notes

- **Trust boundaries** (§3): the web user cannot reach root, nginx cannot reach the DB,
  and the DB has no network.
- **No raw nginx directives** (§7.6). Everything that widens access needs the SSH step
  and is highlighted in its review (§4, §6.3).
- **The UI is never on a public IP address.** Before a host name is in effect, it answers
  by IP to private addresses only. Afterwards, only on the host name and behind its
  access policy (§8.2).
- **Code is root-owned and read-only** for the web and nginx users.
- **Read access without secrets.** The web user may read the live configuration, logs,
  public certificates and process state (§5.3), never a private key or the Docker
  socket. Reading never feeds back into what root renders.
- **Secrets on disk:** `/etc/pspm/db.env` and `/etc/pspm/app.key` (`root:pspm 0640`).
  TOTP secrets, the AI key, blocklist auth headers and custom TLS keys are stored
  encrypted with `app.key`. CA keys are wrapped with their own passphrases.
- **Downloaded blocklists are untrusted input.** They are parsed by the unprivileged user
  and validated again by the agent, and they can never block the never-blocked ranges or
  allowed addresses.
- **In the UI:** CSRF tokens, one-time nonces for forms that carry secrets, `no-store` on
  result pages, and request bodies kept in memory (`client_body_buffer_size`).
- **Login:** the access policy, then password, then TOTP; rate limits and IP bans
  enforced by nginx and the firewall; sessions in the DB that can be revoked.
- **OAuth sign-in** (§12):
  - identity headers are always set or blanked, so they cannot be injected
  - the session cookies never reach a backend
  - redirects are allowed only to the exact host names of the provider's sites
  - oauth2-proxy listens on loopback only and trusts only 127.0.0.1
  - sign-in fails closed
  - PSPM's own UI does not depend on the identity provider
- **Authorisation is narrow.** An access link opens one site. Certificates and sign-ins
  open the sites they are scoped to. In the firewall, all three open the web ports only
  (§14.2).
- **Deploy key:** read-only and limited to the one repository, one per box (§6.6).
- **Audit log** for every change, including those made by scripts and imports.
- **E-mail** goes only through the configured relay, over verified TLS. Mails carry no
  secrets, tokens or action links (§8.6).

---

## 18. Testing

| Level | What |
|---|---|
| Unit | renderer golden files (fixture revision → expected nginx tree and oauth2-proxy configs); every `location` carries the complete identity-header list; validators (with fuzzing); TOTP against the RFC 6238 vectors; CA key wrap/unwrap; blocklist parser (formats, refused ranges, sanity rule); behaviour detectors on recorded log fixtures; drift checks against a manipulated release; export round trip; never-blocked ranges agree between PHP, the SQL `CHECK`, Lua and the firewall rules |
| nginx | every golden tree passes `nginx -t` in a Debian 13 container with the Lua module; the gates against a matrix of conditions |
| End to end (Debian 13 VMs) | listed below |

End-to-end cases:

- **Install:**
  - §6.6 followed step by step on a fresh Debian 13 VM, with a test deploy key
  - a second run changes nothing
  - `install.sh update` from an older commit; `update --to` the previous commit
- **Drift:** a file edited in the live release shows up in the UI and in `install.sh`.
  The apply replaces it only after confirmation, and the edited release remains as
  `previous`.
- **Apply:** a fixture covering every site and route option applies; a deliberately
  broken revision rolls back; nginx killed during an apply.
- **Reaching the UI:**
  - by IP from a private address: answers
  - by IP from a public address: closed
  - with a host name in effect: IP access closed
  - host name set but no certificate: IP access stays
- **Access:**
  - an external curl matrix per site and condition (`tests/external-check.sh`)
  - a link for site A clears the address for A only; its path on site B does nothing
- **Microsoft sign-in** (automated runs: an OIDC mock that issues Entra-shaped tokens;
  before a release: an Entra test tenant):
  - sign-in and sign-out
  - *alternative* and *required* combined with LAN and certificates
  - group restriction per site
  - a client-sent `X-Remote-User` never reaches the backend, on exempt routes either
  - the backend never sees the session cookie
  - oauth2-proxy stopped: *required* sites answer 503, LAN access still works
  - a user disabled at the IdP loses access within the re-check interval
- **Firewall:**
  - a block makes every port of a second, public test VM time out, SSH included, while
    a private address stays unaffected
  - a logged-in SSH session survives its address being blocked
  - an authorised (cleared) address on a blocklist reaches its site, but not SSH
- **Blocklists:**
  - a list containing the test VM drops it on every port
  - a list containing a trusted address does not affect that address
  - a list that comes back empty keeps the previous one
  - apt, certbot and the AI call keep working while a list contains their servers
- **Behaviour:** replayed scenarios (credential stuffing at a backend, a certificate
  shared across networks, scraping) produce findings; authorised actors are never
  blocked automatically.
- **Resilience:** with the DB stopped, nginx keeps serving.
- **Notifications** (a mail-catcher container as the relay):
  - a finding sends its mail, the reminder and the block mail
  - a burst of findings becomes one digest
  - a red tile sends one mail, and the green one a single *resolved* mail
  - a relay that is unreachable turns the *System* tile red
  - no mail contains a secret or a token
- **Restore:** `--import` onto a blank VM restores everything.

---

## 19. Phases

| Phase | Content | Done when |
|---|---|---|
| **P0 Skeleton** | repo layout; the bootstrap path of §6.6; `install.sh` phases 1–11 including the system baseline; `install.sh update`; Docker + PostgreSQL; migration runner; app skeleton; IP access, management server, loopback listener, SSH login message | a fresh Debian 13 VM reaches a running PSPM by following §6.6; two runs succeed and the second changes nothing; the login page answers by IP from a private address and is closed from a public one |
| **P1 Users** | users and roles, login, mandatory TOTP, sessions in the DB, reset scripts, audit log, dashboard frame | a new user must enrol OTP; both reset scripts work with nginx stopped |
| **P2 Configuration and apply** | model, editors, validation, revisions, renderer, manifest, apply/verify/rollback, certificate automation, admin host name, read access (§5.3) and drift (§6.8) | the full-option fixture is entered in the UI and applied; a broken revision rolls back by itself; a host name in effect ends IP access; a hand edit is detected |
| **P3 Access and PKI** | snapshot files, Lua, single-site access links, cleared IPs per site, bans, PKI with the key on the server, CA trust through apply | issuing needs only the passphrase; a revoked certificate is refused on the next request; a link opens only its site |
| **P4 Microsoft sign-in** | providers, oauth2-proxy and Redis containers through apply, the sign-in check in `gate.lua`, sign-in host, identity headers, allowed users per site | the sign-in cases of §18 pass against the mock and an Entra test tenant |
| **P5 Security, firewall, blocklists, notifications** | scan job, AI, behaviour analysis, traps, agent, ipsets and rules (both allow sets), blocklist fetcher and UI, SMTP relay and outbox | a trap hit is refused at once and dropped on every port within a minute; private addresses never affected; blocklist, behaviour and notification cases of §18 pass; kill switches work |
| **P6 Export, import, backups** | JSON format, UI and CLI, scheduled backups, `--import` | identical round trip; a blank VM fully restored with one command |

Each phase ships its own Help pages.

---

## 20. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | PHP 8.4 + Lua + Bootstrap; start from the building blocks in §2 | proven code for gates, PKI, scan and traps |
| D2 | Snapshot files: nginx and the agent never talk to PostgreSQL | the data path survives a DB or PHP outage |
| D3 | nginx is pointed at PSPM's config with a systemd drop-in and self-contained release directories | full test before the switch, atomic switch and rollback, no conffile conflicts |
| D4 | An explicit *Ready to apply* step; `install.sh` applies the newest committed revision | half-finished edits are never applied by accident |
| D5 | PostgreSQL over a Unix socket, container with `network_mode: none` | no exposed port, no Docker NAT rules |
| D6 | Docker from Debian's packages, `live-restore` on | no third-party repo; the DB survives dockerd restarts |
| D7 | CA keys wrapped with Argon2id + XChaCha20-Poly1305 | much harder to brute-force than OpenSSL's PKCS#8 encryption |
| D8 | **Firewall on every port** (confirmed in review); private ranges, then the allow sets, pass first; kernel timeouts | hard block; LAN admins and authorised addresses are never cut off; nothing stays blocked if the agent dies |
| D9 | Replies to connections the box opened pass the firewall (`--ctdir REPLY`) | a blocklist can never break apt, ACME, DNS or the AI calls |
| D10 | Separate users `pspm` (php-fpm) and `pspm-render`; nginx stays `www-data` | the web app cannot write code or nginx config |
| D11 | All assets vendored, strict CSP | no CDN dependency; the UI works by IP and through the SSH tunnel |
| D12 | **IP access from private addresses until a host name is in effect** (confirmed in review). "In effect" means served with a valid certificate | setting a host name can never lock anyone out |
| D13 | **An access link opens exactly one site** (review) and lives on that site's host name (`/.pspm/access/<uuid>`) | the cleared address is the one the browser really uses for the site; works without an admin host name; recipients never learn it |
| D14 | Blocklists are runtime state, fetched unprivileged; the last good list is kept; entries expire after the maximum age | automatic and safe against broken or poisoned lists |
| D15 | Three roles: admin, operator, viewer (confirmed in review) | §9.1 |
| D16 | The UI may **read** system state that holds no secret (§5.3); root-only facts still come from the agent; rendering uses only root's facts | accurate views and drift detection without write access, secrets or Docker for the web user |
| D17 | Drift is detected and shown, never adopted; an apply replaces it only after explicit confirmation and keeps the edited release | hand edits never vanish silently, and raw directives never enter the model |
| D18 | Bootstrap with a read-only GitHub **deploy key per box**; `install.sh update` = fast-forward pull + full run | one documented path from bare Debian to a running proxy; each box can be revoked on its own; no merge surprises |
| D19 | `install.sh` sets up a proxy baseline (time sync, sysctl, limits, security updates) but leaves sshd alone | everything a proxy needs, without the risk of locking out SSH |
| D20 | **Microsoft sign-in through oauth2-proxy** in auth-request mode with sessions in Redis (review), one container per provider, host network on 127.0.0.1; the check runs in `gate.lua` | sign-in combines with the other conditions as OR or AND; no NAT; exact trusted proxy |
| D21 | Identity headers always set or blanked on every route; session cookies stripped before the backend; exact redirect whitelist | closes the header-injection and cookie-replay holes common in oauth2-proxy setups (§12.7) |
| D22 | PSPM's own UI does not use OAuth | the way into PSPM never depends on an external identity provider |
| D23 | Authorisation through links, certificates and sign-ins opens **only the web ports** in the firewall | a leaked link or certificate never opens SSH |
| D24 | Behaviour analysis: deterministic features and detectors, the AI only assesses. Risky untrusted addresses are reported and blocked when nobody reacts in time (review); authorised actors are reported, never blocked automatically | finds risky behaviour without locking out legitimate users; also works without AI |
| D25 | No OTP recovery codes; `reset-otp.sh` only (review) | one recovery path, which needs SSH |
| D26 | The loopback listener `127.0.0.1:9443` always runs; the SSH login message shows the tunnel command (review) | a way back into the UI that survives DNS, certificate and policy failures, reachable only through SSH |
| D27 | Sign-in sessions in a plain Redis container (docker compose, 127.0.0.1, password, data volume), no extra session handling (review) | server-side sessions and small cookies with nothing special to build or run |
| D28 | **E-mail through an SMTP relay** (review), sent only by `pspm` from an outbox; deduplicated, digested, capped; no action links | admins hear about findings before the deadline; mail can never trigger an action or leak a secret |

---

## 21. Questions

### 21.1 Answered in reviews (2026-11-09)

| Question | Answer | Effect |
|---|---|---|
| Migrate the nginx-proxy-h62 setup? | No, the projects have nothing in common | §2; no migration phase; generic examples and fixtures |
| Roles | admin / operator / viewer | §9.1 |
| Admin host name | by IP from private addresses only while no host name is configured; then only by host name | R13, §8.2 |
| Firewall scope | every port; private addresses come first in the rules | R5, §14.2 |
| *(new)* | external blocklists, downloaded and applied automatically | R12, §14.5 |
| OTP recovery codes? | No, the script is enough | R10, §9.3 |
| Repository hosting and clone authentication | GitHub; an SSH key created on the server and added to the repository | R15, §6.6 |
| Should `install.sh` pull the code? | `install.sh` is the deployment workflow: `install.sh update` | §6.7 |
| *(new)* | the UI may read the nginx configuration and other state, e.g. to notice hand edits | R14, §5.3, §6.8 |
| *(new)* | `install.sh` provides everything Debian 13 needs as a proxy | R15, §6.2 |
| *(new)* | an access link authorises a single site | R16, §11.1 |
| *(new)* | the AI also analyses behaviour and identifies risky behaviour | R17, §15.7 |
| *(new)* | OAuth sign-in for selected sites, with oauth2-proxy | R18, §12 |
| Let's Encrypt keys in the export (Q1) | CLI only: `scripts/export.sh --with-tls` and `scripts/import.sh` | §16 |
| Blocklist presets (Q6) | none; lists are entered by URL in the UI | §14.5 |
| Identity providers (Q8) | Microsoft (Entra ID) only for now | R18, §12 |
| Risky behaviour of untrusted addresses (Q9) | reported; blocked if nobody reacts | §15.7 |
| Loopback listener once a host name is in effect (Q5) | always running; shown in the SSH login message | R13, §6.5, §8.2 |
| Storage of sign-in sessions (Q7) | Redis in Docker, via docker compose, nothing special | §12.2, §12.6 |
| Notifying admins about findings (Q10) | e-mail through an SMTP relay | R19, §8.6 |

### 21.2 Open

None at the moment.
