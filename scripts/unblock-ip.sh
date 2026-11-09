#!/bin/bash
# Lift login bans and blocks for an address or network, in nginx and in the firewall.
#   sudo unblock-ip.sh <address or network>
. "$(dirname "$(readlink -f "$0")")/_common.sh"
ip=${1:-}; [[ -n $ip ]] || { echo "usage: $0 <address or network>" >&2; exit 64; }
pspm_php unblock "$ip" || exit $?
php /usr/local/lib/pspm/pspm-agent.php sync >/dev/null 2>&1 && echo "Firewall sets reloaded." || echo "The agent sync failed; the firewall follows within a minute."
log_script "unblocked $ip"
