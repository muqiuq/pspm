#!/bin/bash
# Screenshots of the UI in light and dark mode, for reviewing contrast and layout (dev machine).
# PHP and PostgreSQL run in containers; Chromium (Playwright) shares the PHP container's network,
# so the UI is http://localhost:8080 and the Secure session cookie works.
#   tests/screenshots.sh [out dir, default .tmp/screens] [page …]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
out=${1:-.tmp/screens}; shift || true
pages=("$@"); [[ ${#pages[@]} -gt 0 ]] || pages=(/ /settings /certificates /access /security /backends)
mkdir -p "$out"
cleanup() { docker rm -f pspm-shots-ui pspm-shots-pg >/dev/null 2>&1; docker network rm pspmshots >/dev/null 2>&1; }
cleanup; trap cleanup EXIT
docker network create pspmshots >/dev/null
docker run -d --name pspm-shots-pg --network pspmshots -e POSTGRES_USER=pspm -e POSTGRES_PASSWORD=testpw -e POSTGRES_DB=pspm postgres:18.3 >/dev/null
docker run -d --name pspm-shots-ui --network pspmshots -v "$PWD:/src:ro" pspm-test:trixie bash /src/tests/screens-server.sh >/dev/null
token=
for _ in $(seq 1 120); do
    token=$(docker logs pspm-shots-ui 2>/dev/null | sed -n 's/^TOKEN=//p')
    [[ -n $token ]] && break; sleep 1
done
[[ -n $token ]] || { echo "the UI did not start:"; docker logs pspm-shots-ui; exit 1; }
for mode in light dark; do
    printf '{"cookies":[{"name":"__Host-pspm","value":"%s","domain":"localhost","path":"/","expires":-1,"httpOnly":true,"secure":true,"sameSite":"Strict"}],"origins":[{"origin":"http://localhost:8080","localStorage":[{"name":"pspm-theme","value":"%s"}]}]}' \
        "$token" "$mode" >"$out/state-$mode.json"
done
list=$(printf '%s\n' "${pages[@]}")
docker run --rm --network container:pspm-shots-ui -v "$PWD/$out:/out" -e LIST="$list" mcr.microsoft.com/playwright:v1.57.0-noble bash -c '
    cd /tmp && npm i -s playwright@1.57.0 >/dev/null 2>&1
    while read -r p; do
        n=$(echo "$p" | tr -c "a-z0-9\n" "_" | sed "s/^_*$/dashboard/;s/^_//")
        for mode in light dark; do
            npx playwright screenshot -b chromium --viewport-size=1440,900 --full-page --load-storage="/out/state-$mode.json" \
                "http://localhost:8080$p" "/out/$n-$mode.png" >/dev/null 2>&1 && echo "$n-$mode.png" || echo "FAILED $p ($mode)"
        done
    done <<<"$LIST"'
rm -f "$out"/state-*.json
