#!/bin/bash
# Nightly backup (pspm-backup.timer): pg_dump and the JSON export (secrets encrypted with
# the backup passphrase from Settings). Keeps 14 days.
. "$(dirname "$(readlink -f "$0")")/_common.sh"
dir=/var/lib/pspm/backups/nightly-$(date +%Y%m%d)
install -d -m 0750 -o root -g pspm "$dir"
PGPASSWORD=$(grep '^POSTGRES_PASSWORD=' /etc/pspm/db.env | cut -d= -f2-) docker exec -e PGPASSWORD pspm-postgres pg_dump -U pspm -d pspm -Fc >"$dir/db.dump" \
    || { echo "pg_dump failed" >&2; exit 1; }
if runuser -u pspm -- env PSPM_ACTOR="system (nightly backup)" php "$APP/bin/export.php" --backup >"$dir/export.json.tmp" 2>"$dir/export.err"; then
    mv "$dir/export.json.tmp" "$dir/export.json"; rm -f "$dir/export.err"
else
    rm -f "$dir/export.json.tmp"; echo "JSON export skipped: $(cat "$dir/export.err")" >&2
fi
chgrp pspm "$dir"/*; chmod 0640 "$dir"/*
find /var/lib/pspm/backups -maxdepth 1 -type d -name 'nightly-*' -mtime +14 -exec rm -rf {} +
echo "backup written to $dir"
