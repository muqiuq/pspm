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
mkdir -p /var/lib/pspm/state /var/www/acme /run/php
echo "10.0.0.5 app.internal" >> /etc/hosts
printf '# pspm snapshot blocked\n# serial 1\n# lens4 32\n# lens6 \n203.0.113.7/32\t0\tfw\n' > /var/lib/pspm/state/blocked.tsv
nginx -t -p "$rel/" -c nginx.conf
echo "--- files"; (cd "$rel" && find . -type f | sort | grep -v -e '^./static' -e '^./lua')
