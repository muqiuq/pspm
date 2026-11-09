#!/bin/bash
# Start PostgreSQL and run the UI smoke test in the Debian test image. Run on the dev machine.
set -uo pipefail
cd "$(dirname "$0")/.."
docker network create pspmtest >/dev/null 2>&1 || true
docker rm -f pspm-pg-test >/dev/null 2>&1
docker run -d --name pspm-pg-test --network pspmtest -e POSTGRES_USER=pspm -e POSTGRES_PASSWORD=testpw -e POSTGRES_DB=pspm postgres:18.3 >/dev/null
docker run --rm --network pspmtest -v "$PWD:/src:ro" pspm-test:trixie bash /src/tests/smoke.sh
rc=$?
docker rm -f pspm-pg-test >/dev/null 2>&1
docker network rm pspmtest >/dev/null 2>&1
exit $rc
