#!/bin/bash
# Delete a user's TOTP secret; they enrol a new authenticator at the next sign-in.
# Their sessions end.   sudo reset-otp.sh <user>
. "$(dirname "$(readlink -f "$0")")/_common.sh"
user=${1:-}; [[ -n $user ]] || { echo "usage: $0 <user>" >&2; exit 64; }
pspm_php reset-otp "$user" || exit $?
log_script "OTP reset for $user"
