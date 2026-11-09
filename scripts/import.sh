#!/bin/bash
# Import an export file on a running box (plan §16.4): preview, confirm with IMPORT, then
# everything in one transaction; Let's Encrypt material is restored by root.
#   sudo import.sh file.json
. "$(dirname "$(readlink -f "$0")")/_common.sh"
file=${1:-}
[[ -r $file ]] || { echo "usage: $0 file.json" >&2; exit 64; }
work=$(mktemp -d); chmod 0755 "$work"; cp "$file" "$work/import.json"; chmod 0644 "$work/import.json"
trap 'rm -rf "$work"' EXIT
read -r -s -p "Export passphrase: " pass; echo
run_import() { runuser -u pspm -- env PSPM_IMPORT_PASSPHRASE="$pass" PSPM_IMPORTER="${PSPM_IMPORTER:-}" PSPM_ACTOR="root (${SUDO_USER:-root} via import.sh)" php "$APP/bin/import.php" "$@"; }
run_import preview "$work/import.json" || exit $?
read -r -p "This replaces the configuration and runtime state of this box. Type IMPORT to continue: " ok
[[ $ok == IMPORT ]] || { echo "Nothing changed."; exit 0; }
mkdir -p /var/lib/pspm/backups
bk=/var/lib/pspm/backups/pre-import-$(date +%Y%m%d-%H%M%S).dump
PGPASSWORD=$(grep '^POSTGRES_PASSWORD=' /etc/pspm/db.env | cut -d= -f2-) docker exec -e PGPASSWORD pspm-postgres pg_dump -U pspm -d pspm -Fc >"$bk" && echo "Backup of the current state: $bk"
run_import apply "$work/import.json" || exit $?
restore_tls "$work/import.json"
log_script "import of $file"
echo "Imported. Runtime state is live; the configuration is in the working copy: mark it ready on Changes, then run sudo /opt/pspm/install.sh"
