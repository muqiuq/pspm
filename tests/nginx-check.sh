#!/bin/bash
# Run inside the Debian test image: render the fixture and run nginx -t on it.
set -euo pipefail
rel=/tmp/release
rm -rf "$rel"; mkdir -p "$rel"
php /src/tests/render-fixture.php "$rel"
cp -r /src/nginx/static "$rel/static"
cp -r /src/lua "$rel/lua"
mkcert() { mkdir -p "$(dirname "$1")"; openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=$3" -days 2 -keyout "$2" -out "$1" >/dev/null 2>&1; }
mkcert /etc/letsencrypt/live/pspm-app-example-ch/fullchain.pem /etc/letsencrypt/live/pspm-app-example-ch/privkey.pem app.example.ch
mkcert /etc/letsencrypt/live/pspm-admin/fullchain.pem /etc/letsencrypt/live/pspm-admin/privkey.pem proxy.example.ch
mkcert /etc/pspm/tls/ip.crt /etc/pspm/tls/ip.key 192.168.1.10
mkcert /etc/letsencrypt/live/pspm-signin-peeeeeeee/fullchain.pem /etc/letsencrypt/live/pspm-signin-peeeeeeee/privkey.pem auth.example.ch
mkdir -p /var/lib/pspm/state /var/www/acme /run/php
echo "10.0.0.5 app.internal" >> /etc/hosts
printf '# pspm snapshot blocked\n# serial 1\n# lens4 32\n# lens6 \n203.0.113.7/32\t0\tfw\n' > /var/lib/pspm/state/blocked.tsv
# nginx -t only warns about two servers with one name (and ignores one): fail on it here
ngt() { local out; out=$(nginx -t -p "$1/" -c nginx.conf 2>&1); local rc=$?; echo "$out"; [[ $rc == 0 ]] || return "$rc"; ! grep -q 'conflicting server name' <<<"$out"; }
ngt "$rel"
# the admin host name shared with the sign-in host: one server for both
shared=/tmp/release-shared
rm -rf "$shared"; mkdir -p "$shared"
php /src/tests/render-fixture.php "$shared" shared >/dev/null
cp -r /src/nginx/static "$shared/static"; cp -r /src/lua "$shared/lua"
ngt "$shared"
# an application with its own sign-in: its callbacks pass without PSPM's
own=/tmp/release-own
rm -rf "$own"; mkdir -p "$own"
php /src/tests/render-fixture.php "$own" own >/dev/null
cp -r /src/nginx/static "$own/static"; cp -r /src/lua "$own/lua"
ngt "$own"
grep -A3 'location = /signin-oidc' "$own/sites/app.example.ch.conf"
# without the prefix (plan §7.3): nginx -t, then a running nginx in front of an application at /
strip=/tmp/release-strip
rm -rf "$strip"; mkdir -p "$strip"
php /src/tests/render-fixture.php "$strip" strip >/dev/null
cp -r /src/nginx/static "$strip/static"; cp -r /src/lua "$strip/lua"
ngt "$strip"
php -S 127.0.0.1:8097 /src/tests/echo-backend.php >/tmp/echo-backend.log 2>&1 & echopid=$!
nginx -p "$strip/" -c nginx.conf
sleep 1
fails=0
ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fails=$((fails + 1)); }
pr() { curl -s --resolve printer.example.ch:80:127.0.0.1 "$@"; }
get() { pr "http://printer.example.ch$1"; }
hdr() { pr -o /dev/null -D - "http://printer.example.ch$1" | tr -d '\r' | grep -i "^$2:" | cut -d' ' -f2- || true; }
j=$(get '/site1/page?x=1')
jq -e '.uri == "/page?x=1" and .prefix == "/site1" and .host == "printer.example.ch"' <<<"$j" >/dev/null \
    && ok "/site1/page?x=1 reaches the application as /page?x=1, with X-Forwarded-Prefix /site1 and the host name" || bad "/site1/page: $j"
j=$(get '/site2/'); jq -e '.uri == "/" and .prefix == "/site2"' <<<"$j" >/dev/null && ok "/site2/ reaches it as /" || bad "/site2/: $j"
j=$(get '/site1/a%20b'); jq -e '.uri == "/a%20b"' <<<"$j" >/dev/null && ok "an encoded path stays encoded" || bad "/site1/a%20b: $j"
j=$(pr -H 'X-Forwarded-Prefix: /evil' 'http://printer.example.ch/site1/'); jq -e '.prefix == "/site1"' <<<"$j" >/dev/null && ok "a client cannot send its own X-Forwarded-Prefix there" || bad "client prefix: $j"
l=$(hdr '/site1?q=2' location); [[ $l == "http://printer.example.ch/site1/?q=2" ]] && ok "/site1 redirects to /site1/ (query kept)" || bad "/site1: $l"
j=$(get '/site1abc'); jq -e '.uri == "/site1abc" and .prefix == ""' <<<"$j" >/dev/null && ok "/site1abc is not taken: the site's route, path unchanged" || bad "/site1abc: $j"
j=$(get '/other/x'); jq -e '.uri == "/other/x" and .prefix == ""' <<<"$j" >/dev/null && ok "other paths: unchanged, no X-Forwarded-Prefix" || bad "/other/x: $j"
# nginx makes a relative Location absolute (absolute_redirect, on every route)
l=$(hdr /site1/go location); [[ $l == http://printer.example.ch/site1/login ]] && ok "a relative redirect goes under the prefix" || bad "redirect /login: $l"
l=$(hdr /site1/abs location); [[ $l == http://printer.example.ch/site1/login ]] && ok "a redirect to its host name goes under the prefix" || bad "redirect http://host/login: $l"
l=$(hdr /site1/in location); [[ $l == http://printer.example.ch/site1/done ]] && ok "a redirect already under the prefix stays (no /site1/site1/)" || bad "redirect /site1/done: $l"
l=$(hdr /site1/ext location); [[ $l == https://login.microsoftonline.com/tenant/authorize ]] && ok "a redirect to another host stays" || bad "external redirect: $l"
c=$(hdr /site1/cookies set-cookie | paste -sd'|' -)
[[ $c == "a=1; Path=/site1/|b=2; Path=/site1|c=3; Path=/site1/api; HttpOnly" ]] && ok "cookie paths go under the prefix, those already under it stay" || bad "cookies: $c"
nginx -p "$strip/" -c nginx.conf -s stop
kill "$echopid" 2>/dev/null || true
[[ $fails == 0 ]] || { echo "$fails strip-prefix checks failed"; exit 1; }
echo "--- files"; (cd "$rel" && find . -type f | sort | grep -v -e '^./static' -e '^./lua')
