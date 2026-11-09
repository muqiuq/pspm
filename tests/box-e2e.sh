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
# start → callback round trip: oauth2-proxy must get back the CSRF cookie it set at /oauth2/start.
# With it, the fake code fails at Microsoft (500); without it, oauth2-proxy answers 403.
cb() {
    local jar=/tmp/cb.jar loc state
    rm -f "$jar"
    loc=$(curl -sk -c "$jar" -o /dev/null -w '%{redirect_url}' --resolve "auth.pspm.test:443:$1" 'https://auth.pspm.test/oauth2/start?rd=https%3A%2F%2Fsso.pspm.test%2F')
    state=$(sed -n 's/.*[?&]state=\([^&]*\).*/\1/p' <<<"$loc")
    curl -sk -b "$jar" -o /dev/null -w '%{http_code}' --resolve "auth.pspm.test:443:$1" "https://auth.pspm.test/oauth2/callback?code=e2e-fake&state=$state"
}
c=$(cb 127.0.0.1); [[ $c == 500 ]] && ok "sign-in host: the callback gets the CSRF cookie (fake code refused by Microsoft: $c)" || bad "sign-in host callback: $c (403 = CSRF cookie lost)"
pp blocklist >/dev/null
php /usr/local/lib/pspm/pspm-agent.php sync >/dev/null
n=$(ipset list pspm-feed4 | sed -n '/^Members:/,$p' | grep -c timeout)
[[ $n == 2 ]] && ok "blocklist in the firewall: 2 entries (the private one refused)" || bad "blocklist entries: $n"
systemctl start pspm-secscan.service; sleep 2
st=$(runuser -u pspm -- php -r 'require "/srv/pspm/app/current/lib/bootstrap.php"; echo DB::val("SELECT stats FROM scan_runs ORDER BY id DESC LIMIT 1");')
[[ $st == *'"lines"'* ]] && ok "the scan read the real nginx security log: $st" || bad "scan: $st"
systemctl is-active -q pspm-secscan.timer pspm-notify.timer pspm-blocklists.timer pspm-backup.timer && ok "timers active" || bad "timers"
systemctl start pspm-backup.service && ls /var/lib/pspm/backups/nightly-*/db.dump >/dev/null && ok "nightly backup writes a dump" || bad "backup"
# the admin host name shared with the sign-in host: one server; the UI keeps the admin access, /oauth2/ is public
lanip=$(ip -o -4 addr show scope global | awk '$2 !~ /^(docker|br-|veth)/ {sub(/\/.*/, "", $4); print $4; exit}')
pp adminhost auth.pspm.test >/dev/null && /opt/pspm/install.sh apply --yes >/root/apply-admin.out 2>&1; rc=$?
grep -q "Rolling back" /var/log/pspm/install-latest.log && bad "admin host = sign-in host: rolled back ($(grep -m1 'Rolling back' /var/log/pspm/install-latest.log))" \
    || { [[ $rc == 0 || $rc == 2 ]] && ok "admin host = sign-in host applies (exit $rc), TLS check uses the certificate in use" || bad "admin host apply exit $rc"; }
# UI probes use / (303 to the login page once the gate lets in, 403 otherwise): /login is limited to 10/min
ui() { curl -sk -o /dev/null -w '%{http_code}' --resolve "auth.pspm.test:443:$1" https://auth.pspm.test/; }
c=$(ui "$lanip"); [[ $c == 303 ]] && ok "shared host: the UI answers from the LAN ($lanip): $c" || bad "shared host UI from LAN: $c"
c=$(ui 127.0.0.1); [[ $c == 403 ]] && ok "shared host: the UI refuses a non-LAN address: $c" || bad "shared host UI from 127.0.0.1: $c"
loc=$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' --resolve auth.pspm.test:443:127.0.0.1 'https://auth.pspm.test/oauth2/start?rd=https%3A%2F%2Fsso.pspm.test%2F')
[[ $loc == "302 https://login.microsoftonline.com/"* ]] && ok "shared host: /oauth2/ is public and hands over to Microsoft" || bad "shared host /oauth2/: $loc"
c=$(cb 127.0.0.1); [[ $c == 500 ]] && ok "shared host: the callback gets the CSRF cookie (fake code refused by Microsoft: $c)" || bad "shared host callback: $c (403 = CSRF cookie lost)"
# access links for the admin UI: a non-LAN address gets the UI only after using the link
pp adminrevoke >/dev/null   # a clean start when the test runs again
pp adminhost auth.pspm.test lan,cleared,cert >/dev/null && /opt/pspm/install.sh apply --yes >/root/apply-adminlink.out 2>&1
grep -q "OPENS: admin UI reachable by: lan, cleared, cert" /root/apply-adminlink.out && ok "review: admin UI reachable by access links (OPENS)" || bad "review line for admin links missing"
c=$(ui 127.0.0.1); [[ $c == 403 ]] && ok "admin UI before the link, non-LAN address: $c" || bad "admin UI before the link: $c"
tok=$(pp adminlink)
loc=$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' --resolve auth.pspm.test:443:127.0.0.1 "https://auth.pspm.test/.pspm/access/$tok")
[[ $loc == "303 https://auth.pspm.test/" ]] && ok "the admin link clears the address and opens the UI" || bad "admin link: $loc"
c=$(ui 127.0.0.1); [[ $c == 303 ]] && ok "admin UI after the link, same address: $c (to its sign-in page)" || bad "admin UI after the link: $c"
c=$(curl -sk -o /dev/null -w '%{http_code}' --resolve cert.pspm.test:443:127.0.0.1 "https://cert.pspm.test/.pspm/access/$tok")
[[ $c != 303 ]] && ok "the admin link does not work on a site host: $c" || bad "admin link on a site host: $c"
pp adminrevoke >/dev/null
c=$(ui 127.0.0.1); [[ $c == 403 ]] && ok "revoked: the admin UI refuses that address again: $c" || bad "admin UI after revoking the link: $c"
# a release in which two servers answer one name is refused (nginx -t only warns)
dupdir=/tmp/dup-release; rm -rf "$dupdir"; cp -a "$(readlink -f /etc/pspm/nginx/current)" "$dupdir"
printf 'server {\n    listen 80;\n    server_name cert.pspm.test;\n    return 404;\n}\n' >> "$dupdir/conf/signin.conf"
d=$(bash -c '. /opt/pspm/installer/common.sh; nginx_duplicate_names "$1"' _ "$dupdir")
[[ $d == '"cert.pspm.test" on 0.0.0.0:80'* ]] && ok "duplicate host names are detected: $d" || bad "duplicate host names: '$d'"
rm -rf "$dupdir"
pp adminhost '' >/dev/null && /opt/pspm/install.sh apply --yes >/dev/null 2>&1
echo "${FAILS:-0} failures"
