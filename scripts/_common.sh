# shellcheck shell=bash
# Shared by the recovery scripts: they need only the database, not nginx or the UI.
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $*" >&2; exit 1; }
APP=/srv/pspm/app/current
[[ -d $APP ]] || APP=$(cd "$(dirname "$(readlink -f "$0")")/../app" && pwd)
pspm_php() { runuser -u pspm -- env PSPM_ACTOR="root (${SUDO_USER:-root} via $(basename "$0"))" php "$APP/bin/user.php" "$@"; }
log_script() {
    mkdir -p /var/log/pspm
    printf '%s %s %s: %s\n' "$(date '+%F %T')" "${SUDO_USER:-root}" "$(basename "$0")" "$*" >>/var/log/pspm/scripts.log
}
