#!/bin/bash
# Reset a user's password. The user must choose a new one at the next sign-in; their
# sessions end.   sudo reset-password.sh <user> [--generate]
. "$(dirname "$(readlink -f "$0")")/_common.sh"
user=${1:-}; [[ -n $user ]] || { echo "usage: $0 <user> [--generate]" >&2; exit 64; }
if [[ ${2:-} == --generate ]]; then
    out=$(pspm_php reset-password "$user" --generate) || exit $?
    grep -v '^PASSWORD=' <<<"$out"
    echo "New password for $user (shown once): $(sed -n 's/^PASSWORD=//p' <<<"$out")"
else
    read -r -s -p "New password for $user: " pw1; echo
    read -r -s -p "Repeat: " pw2; echo
    [[ $pw1 == "$pw2" ]] || { echo "The passwords differ." >&2; exit 1; }
    printf '%s\n' "$pw1" | pspm_php reset-password "$user" || exit $?
fi
log_script "password reset for $user"
echo "Done. $user must change the password at the next sign-in."
