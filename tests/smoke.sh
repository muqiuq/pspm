#!/bin/bash
# UI smoke test: PostgreSQL container + PHP built-in server in the Debian test image.
# Run by tests/run-smoke.sh.
set -euo pipefail
export PSPM_ETC=/tmp/etc PSPM_VAR=/tmp/var PSPM_LOGDIR=/tmp/log
mkdir -p "$PSPM_ETC" "$PSPM_VAR/state" "$PSPM_VAR/status" "$PSPM_LOGDIR"
openssl rand -base64 32 >"$PSPM_ETC/app.key"
printf 'POSTGRES_USER=pspm\nPOSTGRES_DB=pspm\nPOSTGRES_PASSWORD=testpw\n' >"$PSPM_ETC/db.env"
export PSPM_DB_DSN='pgsql:host=pspm-pg-test;dbname=pspm'
for i in $(seq 1 30); do php -r 'new PDO(getenv("PSPM_DB_DSN"), "pspm", "testpw");' 2>/dev/null && break; sleep 1; done
php /src/app/bin/migrate.php /src/db/migrations
php /src/app/bin/migrate.php /src/db/migrations
php /src/app/bin/selftest.php
pw=$(php /src/app/bin/user.php bootstrap | sed -n 's/^PASSWORD=//p')
[[ -n $pw ]] || { echo "no bootstrap password"; exit 1; }
# certificates for the overview on the Certificates page: a Let's Encrypt one that should have been renewed, the IP one
d=/etc/letsencrypt/live/pspm-smoke-pspm-test; mkdir -p "$d" "$PSPM_ETC/tls"
openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=smoke.pspm.test" -addext "subjectAltName=DNS:smoke.pspm.test" -days 20 -keyout "$d/privkey.pem" -out "$d/cert.pem" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=PSPM smoke" -addext "subjectAltName=IP:127.0.0.1" -days 3650 -keyout /dev/null -out "$PSPM_ETC/tls/ip.crt" 2>/dev/null
# a package report as the agent writes it, for the dashboard tile
cat >"$PSPM_VAR/status/apt.json" <<JSON
{"checked": "$(date -u +%FT%TZ)", "last_update": "$(date -u -d '-3 hours' +%FT%TZ)", "update_error": null, "ok": true, "upgradable": 2, "security": 1,
 "packages": [{"name": "libssl3t64", "suite": "stable-security", "to": "3.5.7-1~deb13u4", "from": "3.5.7-1~deb13u3", "security": true},
              {"name": "nginx", "suite": "stable", "to": "1.26.3-3+deb13u11", "from": "1.26.3-3+deb13u10", "security": false}],
 "reboot_required": true, "reboot_packages": ["linux-image-6.12.117+deb13-amd64"], "security_since": "$(date -u +%FT%TZ)"}
JSON
php -S 127.0.0.1:8099 /src/tests/fake-ai.php >/tmp/fake-ai-server.log 2>&1 &   # an OpenAI-compatible fake for the AI checks
php -S 127.0.0.1:8080 /src/app/public/index.php >/tmp/server.log 2>&1 &
sleep 1
ADMIN_PW=$pw php /src/tests/smoke-client.php
echo "--- render the committed revision"
php /src/app/bin/revision.php export >/tmp/rev.json
jq -n --slurpfile r /tmp/rev.json --slurpfile f /src/tests/fixtures/facts.json '{revision: $r[0], facts: $f[0]}' | php /src/app/bin/render.php >/tmp/out.json
jq -r '.summary | {sites: [.sites[].host], admin, pending_certs}' /tmp/out.json
php /src/app/bin/state.php || true
echo "--- PKI"
php /src/tests/pki-check.php
echo "--- security"
php /src/tests/security-check.php
echo "--- AI (fake API): log, verdicts, behaviour, errors"
php /src/tests/ai-check.php
echo "--- honeypots: the 300 best"
php /src/tests/traps-check.php
echo "--- access links (site and admin UI)"
php /src/tests/access-check.php
echo "--- export/import"
php /src/tests/export-check.php export
PSPM_DB_DSN='pgsql:host=pspm-pg-test;dbname=pspm2' php /src/app/bin/migrate.php /src/db/migrations >/dev/null
PSPM_DB_DSN='pgsql:host=pspm-pg-test;dbname=pspm2' php /src/tests/export-check.php import
cp -r /src/nginx/static /tmp/pki-release/static && cp -r /src/lua /tmp/pki-release/lua
mkc() { mkdir -p "$(dirname "$1")"; openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=$3" -days 2 -keyout "$2" -out "$1" >/dev/null 2>&1; }
mkc /etc/letsencrypt/live/pspm-app-example-ch/fullchain.pem /etc/letsencrypt/live/pspm-app-example-ch/privkey.pem app.example.ch
mkc /etc/letsencrypt/live/pspm-admin/fullchain.pem /etc/letsencrypt/live/pspm-admin/privkey.pem proxy.example.ch
mkc /etc/pspm/tls/ip.crt /etc/pspm/tls/ip.key 127.0.0.1
mkdir -p /var/lib/pspm/state /var/www/acme && nginx -t -q -p /tmp/pki-release/ -c nginx.conf && echo "ok   nginx -t with the client CA bundle"
ls -la "$PSPM_VAR/state"
php /src/app/bin/user.php list
php /src/app/bin/user.php reset-otp admin
grep -i -E 'fatal|warning|deprecated|notice' /tmp/server.log && { echo "PHP printed warnings (above)"; exit 1; } || echo "no PHP warnings in the server log"
