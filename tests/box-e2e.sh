#!/bin/bash
# End-to-end checks inside the systemd test box (after a successful install.sh run).
set -uo pipefail
ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; FAILS=$((${FAILS:-0} + 1)); }
pp() { runuser -u pspm -- php /src/tests/box-e2e.php "$@"; }
# fake Let's Encrypt certificates for the test names (the box cannot get real ones)
for h in cert.pspm.test sso.pspm.test auth.pspm.test; do
    n=pspm-$(echo "$h" | tr . -); [[ $h == auth.pspm.test ]] && n=pspm-signin-x
    d=/etc/letsencrypt/live/$n; mkdir -p "$d"
    openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=$h" -addext "subjectAltName=DNS:$h" -days 30 -keyout "$d/privkey.pem" -out "$d/cert.pem" 2>/dev/null
    cp "$d/cert.pem" "$d/fullchain.pem"
done
pp setup || exit 1
/opt/pspm/install.sh apply --yes > /root/apply-e2e.out 2>&1; echo "apply exit $?"
grep -E "OPENS|✓|!|✗|Result" /root/apply-e2e.out | grep -v "^    [+@ -]"
docker ps --format '{{.Names}} {{.Status}}' | grep -E "oauth|redis" && ok "sign-in containers run" || bad "sign-in containers"
code=$(curl -sk -o /dev/null -w '%{http_code}' --resolve cert.pspm.test:443:127.0.0.1 https://cert.pspm.test/)
[[ $code == 403 ]] && ok "cert-only site without a certificate: 403" || bad "cert-only site without a certificate: $code"
pp issue
openssl pkcs12 -in /var/lib/pspm/tmp/e2e.p12 -passin "pass:$(cat /var/lib/pspm/tmp/e2e.pass)" -nodes -out /tmp/e2e.pem 2>/dev/null
code=$(curl -sk -o /dev/null -w '%{http_code}' --cert /tmp/e2e.pem --resolve cert.pspm.test:443:127.0.0.1 https://cert.pspm.test/)
[[ $code == 502 || $code == 504 ]] && ok "with the issued certificate the gate lets it in (backend unreachable: $code)" || bad "with the certificate: $code"
pp revoke
code=$(curl -sk -o /dev/null -w '%{http_code}' --cert /tmp/e2e.pem --resolve cert.pspm.test:443:127.0.0.1 https://cert.pspm.test/)
[[ $code == 403 ]] && ok "revoked certificate refused on the next request: 403" || bad "revoked certificate: $code"
loc=$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Accept: text/html' --resolve sso.pspm.test:443:127.0.0.1 https://sso.pspm.test/page)
[[ $loc == "302 https://auth.pspm.test/oauth2/start?rd=https%3A%2F%2Fsso.pspm.test%2Fpage" ]] && ok "sign-in required: a browser goes to the sign-in host" || bad "sign-in redirect: $loc"
code=$(curl -sk -o /dev/null -w '%{http_code}' -H 'Accept: application/json' --resolve sso.pspm.test:443:127.0.0.1 https://sso.pspm.test/api)
[[ $code == 401 ]] && ok "sign-in required: an API client gets 401" || bad "API client: $code"
loc=$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' --resolve auth.pspm.test:443:127.0.0.1 'https://auth.pspm.test/oauth2/start?rd=https%3A%2F%2Fsso.pspm.test%2F')
[[ $loc == "302 https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/"* ]] && ok "the sign-in host hands over to Microsoft (with PKCE)" || bad "sign-in host: $loc"
pp blocklist >/dev/null
php /usr/local/lib/pspm/pspm-agent.php sync >/dev/null
n=$(ipset list pspm-feed4 | sed -n '/^Members:/,$p' | grep -c timeout)
[[ $n == 2 ]] && ok "blocklist in the firewall: 2 entries (the private one refused)" || bad "blocklist entries: $n"
systemctl start pspm-secscan.service; sleep 2
st=$(runuser -u pspm -- php -r 'require "/srv/pspm/app/current/lib/bootstrap.php"; echo DB::val("SELECT stats FROM scan_runs ORDER BY id DESC LIMIT 1");')
[[ $st == *'"lines"'* ]] && ok "the scan read the real nginx security log: $st" || bad "scan: $st"
systemctl is-active -q pspm-secscan.timer pspm-notify.timer pspm-blocklists.timer pspm-backup.timer && ok "timers active" || bad "timers"
systemctl start pspm-backup.service && ls /var/lib/pspm/backups/nightly-*/db.dump >/dev/null && ok "nightly backup writes a dump" || bad "backup"
echo "${FAILS:-0} failures"
