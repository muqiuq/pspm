#!/bin/bash
# Export the whole configuration as one JSON file (plan §16.3). CLI only can include the
# Let's Encrypt material (--with-tls), so a new box can serve TLS before DNS points to it.
#   sudo export.sh [--with-tls] [--no-history] -o file.json
. "$(dirname "$(readlink -f "$0")")/_common.sh"
out="" tls=0 args=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -o) out=${2:-}; shift ;;
        --with-tls) tls=1 ;;
        --no-history) args+=(--no-history) ;;
        *) echo "usage: $0 [--with-tls] [--no-history] -o file.json" >&2; exit 64 ;;
    esac
    shift
done
[[ -n $out ]] || { echo "usage: $0 [--with-tls] [--no-history] -o file.json" >&2; exit 64; }
read -r -s -p "Export passphrase (at least 16 characters): " p1; echo
read -r -s -p "Repeat: " p2; echo
[[ $p1 == "$p2" ]] || { echo "The passphrases differ." >&2; exit 1; }
tmp=$(mktemp); chmod 0600 "$tmp"
if [[ $tls == 1 ]]; then
    le=$(tar -C /etc/letsencrypt -czf - . 2>/dev/null | base64 -w0)
    jq -n --arg le "$le" --rawfile nb /etc/pspm/never-block '{letsencrypt: $le, never_block: $nb}' \
        | runuser -u pspm -- env PSPM_EXPORT_PASSPHRASE="$p1" PSPM_ACTOR="root (${SUDO_USER:-root} via export.sh)" php "$APP/bin/export.php" --tls-stdin "${args[@]}" >"$tmp" || { rm -f "$tmp"; exit 1; }
else
    runuser -u pspm -- env PSPM_EXPORT_PASSPHRASE="$p1" PSPM_ACTOR="root (${SUDO_USER:-root} via export.sh)" php "$APP/bin/export.php" "${args[@]}" >"$tmp" || { rm -f "$tmp"; exit 1; }
fi
(umask 077; cp "$tmp" "$out"); rm -f "$tmp"
log_script "export to $out (tls=$tls)"
echo "Written: $out ($(du -h "$out" | cut -f1)). Keep it and the passphrase apart."
