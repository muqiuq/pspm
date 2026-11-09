#!/bin/bash
# The PHP side of tests/screenshots.sh, inside the Debian test image: database, seed data,
# certificates and a package report for the overview pages, then the UI on port 8080.
set -euo pipefail
export PSPM_ETC=/tmp/etc PSPM_VAR=/tmp/var PSPM_LOGDIR=/tmp/log PSPM_DB_DSN='pgsql:host=pspm-shots-pg;dbname=pspm'
mkdir -p "$PSPM_ETC/tls" "$PSPM_VAR/state" "$PSPM_VAR/status" "$PSPM_LOGDIR"
openssl rand -base64 32 >"$PSPM_ETC/app.key"
printf 'POSTGRES_USER=pspm\nPOSTGRES_DB=pspm\nPOSTGRES_PASSWORD=testpw\n' >"$PSPM_ETC/db.env"
for _ in $(seq 1 30); do php -r 'new PDO(getenv("PSPM_DB_DSN"), "pspm", "testpw");' 2>/dev/null && break; sleep 1; done
php /src/app/bin/migrate.php /src/db/migrations >/dev/null
php /src/app/bin/user.php bootstrap >/dev/null
for h in app.pspm.test wiki.pspm.test; do
    d=/etc/letsencrypt/live/pspm-$(echo "$h" | tr . -); mkdir -p "$d"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$h" -addext "subjectAltName=DNS:$h" \
        -days "$([[ $h == wiki.pspm.test ]] && echo 12 || echo 80)" -keyout /dev/null -out "$d/cert.pem" 2>/dev/null
done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=PSPM screens" -addext "subjectAltName=IP:10.0.0.2,IP:127.0.0.1" \
    -days 3650 -keyout /dev/null -out "$PSPM_ETC/tls/ip.crt" 2>/dev/null
cat >"$PSPM_VAR/status/apt.json" <<JSON
{"checked": "$(date -u +%FT%TZ)", "last_update": "$(date -u -d '-5 hours' +%FT%TZ)", "ok": true, "upgradable": 3, "security": 1,
 "packages": [{"name": "libssl3t64", "suite": "stable-security", "to": "3.5.7-1~deb13u4", "from": "3.5.7-1~deb13u3", "security": true},
              {"name": "nginx", "suite": "stable", "to": "1.26.3-3+deb13u11", "from": "1.26.3-3+deb13u10", "security": false},
              {"name": "tzdata", "suite": "stable", "to": "2026b-1", "from": "2026a-1", "security": false}],
 "reboot_required": false, "reboot_packages": [], "security_since": "$(date -u +%FT%TZ)"}
JSON
php /src/tests/screens-seed.php
exec php -S 0.0.0.0:8080 /src/tests/screens-router.php
