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
# response header buffer of a backend (nginx's own 4k default answered 502 for the 12 KB header)
php -S 127.0.0.1:8099 /src/tests/box-backend.php >/dev/null 2>&1 & bigpid=$!
big() { curl -s -o /dev/null -w '%{http_code}' --resolve big.pspm.test:80:127.0.0.1 "http://big.pspm.test/?n=$1"; }
pp bigheader 16 >/dev/null && /opt/pspm/install.sh apply --yes >/root/apply-big.out 2>&1
c=$(big 12000); [[ $c == 200 ]] && ok "12 KB response header with the default buffer (16k): 200" || bad "12 KB header, default buffer: $c"
c=$(big 40000); [[ $c == 502 ]] && ok "40 KB response header with the default buffer: 502" || bad "40 KB header, default buffer: $c"
grep -q "upstream sent too big header" /var/log/nginx/error.log && ok "that 502 is logged as 'upstream sent too big header'" || bad "no 'too big header' in error.log"
pp bigheader 64 >/dev/null && /opt/pspm/install.sh apply --yes >/root/apply-big2.out 2>&1
grep -q "~ backend big: response header buffer 16k → 64k" /root/apply-big2.out && ok "the review names the buffer change" || bad "review: $(grep 'backend big' /root/apply-big2.out)"
c=$(big 40000); [[ $c == 200 ]] && ok "40 KB response header with the backend set to 64k: 200" || bad "40 KB header, 64k buffer: $c"
kill "$bigpid" 2>/dev/null
# entries longer than the kernel's ipset limit are capped, and the set is reloaded before the cap runs out
tmo() { ipset list "$1" | awk -v ip="$2" '$1 == ip {print $3}'; }
pp longterm >/dev/null
php /usr/local/lib/pspm/pspm-agent.php sync >/dev/null 2>/root/agent-e2e.err && ok "agent sync with 30-day entries: exit 0" || bad "agent sync with 30-day entries: $(cat /root/agent-e2e.err)"
t1=$(tmo pspm-allowweb4 203.0.113.7); b1=$(tmo pspm-block4 192.0.2.77)
[[ -n $t1 && $t1 -le 2147483 && $t1 -gt 2147000 ]] && ok "30-day authorisation in the allow-web set, capped: timeout $t1" || bad "allow-web timeout: '${t1}'"
[[ -n $b1 && $b1 -le 2147483 && $b1 -gt 2147000 ]] && ok "30-day block in the block set, capped: timeout $b1" || bad "block timeout: '${b1}'"
sleep 3; php /usr/local/lib/pspm/pspm-agent.php sync >/dev/null 2>&1
t2=$(tmo pspm-allowweb4 203.0.113.7)
[[ -n $t2 && $t2 -lt $t1 ]] && ok "unchanged set is not reloaded before its deadline ($t1 → $t2)" || bad "unexpected reload: $t1 → $t2"
jq '.reload["pspm-allowweb4"] = 0' /var/lib/pspm/agent-state.json > /root/agent-state.json && cat /root/agent-state.json > /var/lib/pspm/agent-state.json
php /usr/local/lib/pspm/pspm-agent.php sync >/dev/null 2>&1
t3=$(tmo pspm-allowweb4 203.0.113.7)
[[ -n $t3 && $t3 -gt $t2 ]] && ok "past its reload deadline the set is reloaded ($t2 → $t3)" || bad "no reload at the deadline: $t2 → $t3"
jq -e '.errors == [] and .sets["pspm-allowweb4"] >= 1 and .sets["pspm-block4"] >= 1' /var/lib/pspm/status/firewall.json >/dev/null \
    && ok "firewall status: no errors" || bad "firewall status: $(jq -c '{sets, errors}' /var/lib/pspm/status/firewall.json)"
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
