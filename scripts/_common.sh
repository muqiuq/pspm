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

# Restore Let's Encrypt material and never-block from an export (if it has them).
restore_tls() {
    local f=$1 tls
    tls=$(runuser -u pspm -- env PSPM_IMPORT_PASSPHRASE="$pass" php "$APP/bin/import.php" tls "$f") || return 1
    [[ $tls == null || -z $tls ]] && return 0
    local le
    le=$(jq -r '.letsencrypt // ""' <<<"$tls")
    if [[ -n $le ]]; then
        [[ -d /etc/letsencrypt ]] && cp -a /etc/letsencrypt "/etc/letsencrypt.pre-import-$(date +%Y%m%d-%H%M%S)"
        mkdir -p /etc/letsencrypt && base64 -d <<<"$le" | tar -C /etc/letsencrypt -xzf - && echo "Let's Encrypt material restored."
    fi
    jq -r '.never_block // empty' <<<"$tls" >/etc/pspm/never-block.imported && [[ -s /etc/pspm/never-block.imported ]] && mv /etc/pspm/never-block.imported /etc/pspm/never-block
    rm -f /etc/pspm/never-block.imported
}
