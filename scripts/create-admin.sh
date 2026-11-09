#!/bin/bash
# Recovery when no admin can sign in: create (or re-enable) an admin with a generated
# password.   sudo create-admin.sh <user>
. "$(dirname "$(readlink -f "$0")")/_common.sh"
user=${1:-}; [[ -n $user ]] || { echo "usage: $0 <user>" >&2; exit 64; }
out=$(pspm_php create-admin "$user") || exit $?
echo "Admin $user, password (shown once): $(sed -n 's/^PASSWORD=//p' <<<"$out")"
echo "They choose their own password and enrol an authenticator at the first sign-in."
log_script "admin $user created or reset"
