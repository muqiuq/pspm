# shellcheck shell=bash
# Paths, constants and helpers shared by the installer modules.

ETC=/etc/pspm
VAR=/var/lib/pspm
APP_ROOT=/srv/pspm/app
NGX=$ETC/nginx
STATE=$VAR/state
STATUS=$VAR/status
BACKUPS=$VAR/backups
LIBDIR=/usr/local/lib/pspm
ACME_ROOT=/var/www/acme
LOCK_FILE=/run/lock/pspm.lock
JOURNAL=$VAR/apply.journal
DROPIN=/etc/systemd/system/nginx.service.d/pspm.conf
PHP_VERSION=8.4
FPM_SERVICE=php$PHP_VERSION-fpm
FPM_SOCK=/run/php/pspm-fpm.sock
COMPOSE_PROJECT=pspm
KEEP_RELEASES=20
KEEP_APP_RELEASES=10
KEEP_BACKUPS=20

PACKAGES=(nginx libnginx-mod-http-lua luajit
          "php$PHP_VERSION-fpm" "php$PHP_VERSION-cli" "php$PHP_VERSION-pgsql" "php$PHP_VERSION-mbstring"
          "php$PHP_VERSION-curl" "php$PHP_VERSION-intl"
          openssl ca-certificates curl jq certbot ipset iptables acl
          docker.io docker-cli docker-compose git unattended-upgrades)

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# Run PHP as the web user, with the paths of this box.
as_pspm() { runuser -u pspm -- env PSPM_ACTOR="root (${SUDO_USER:-root} via install.sh)" "$@"; }

# The app release that is live (or the repo copy before the first release).
app_dir() {
    if [[ -e $APP_ROOT/current ]]; then readlink -f "$APP_ROOT/current"; else echo "$PSPM_REPO/app"; fi
}

compose() {
    if docker compose version >/dev/null 2>&1; then docker compose "$@"
    elif need_cmd docker-compose; then docker-compose "$@"
    else echo "neither 'docker compose' nor 'docker-compose' is available" >&2; return 127; fi
}

# Write a file only when its content changes. Returns 0 if changed, 1 if unchanged.
write_if_changed() {
    local path=$1 mode=$2 content=$3 tmp
    if [[ -f $path ]] && [[ "$(cat "$path")" == "$content" ]]; then return 1; fi
    tmp=$(mktemp "$path.XXXXXX" 2>/dev/null || mktemp)
    printf '%s\n' "$content" >"$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$path"
    _log FILE "wrote $path (mode $mode)"
    return 0
}

# The box's addresses, one per line (global scope, without prefix length).
# Container bridges (docker0, br-…, veth…, virbr…) are not addresses of the box.
box_addresses() {
    ip -o addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|veth|virbr|lxcbr|podman|cni)/ {print $4}' | cut -d/ -f1 | sort -u
}

is_private_addr() {
    case $1 in
        10.*|192.168.*|127.*|fc*|fd*|fe80:*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    esac
    return 1
}

ipv6_available() { [[ -s /proc/net/if_inet6 ]]; }

nginx_master_cmdline() {
    local pid
    pid=$(cat /run/nginx.pid 2>/dev/null) || return 1
    [[ -r /proc/$pid/cmdline ]] || return 1
    tr '\0' ' ' </proc/"$pid"/cmdline
}

nginx_runs_pspm() { nginx_master_cmdline | grep -q -- "-p $NGX/current/"; }

nginx_test() { nginx -t -q -p "$1/" -c nginx.conf; }
# Host names that two servers of a release answer ("name" on addr:port …); nginx -t only
# warns about them and ignores one of the servers, so apply refuses such a release.
nginx_duplicate_names() {
    nginx -t -p "$1/" -c nginx.conf 2>&1 | { grep -o 'conflicting server name "[^"]*" on [^ ,]*' || true; } \
        | sed 's/conflicting server name //' | sort -u | paste -sd ' ' -
}

ip_cert_fingerprint() {
    openssl x509 -in "$ETC/tls/ip.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}

json_get() { jq -r "$2" "$1" 2>/dev/null; }

# What the agent's last report says is wrong with the firewall, in one line (empty when
# nothing is). Same wording as Status::firewallProblem in the UI.
firewall_problem() {
    jq -r '
      ([.rules // {} | to_entries[] | select(.value == "error") | .key]) as $broken
      | ([.sets // {} | to_entries[] | select(.value == -1) | .key]) as $failed
      | (.errors // []) as $e
      | (($e[0] // "see the log") + (if ($e | length) > 1 then " (and \(($e | length) - 1) more)" else "" end)) as $first
      | if ($broken | length) > 0 then "The firewall chain could not be set up (\($broken | join(", "))): \($first) nginx still blocks."
        elif ($failed | length) > 0 then "The firewall works, but \(if ($failed | length) == 1 then "set" else "sets" end) \($failed | join(", ")) could not be loaded: \($first)"
        elif ($e | length) > 0 then "The firewall agent reports: \($first)"
        else empty end' "$STATUS/firewall.json" 2>/dev/null
}

# agent_sync "description": runs the agent sync. A failure becomes one warning that says
# what failed; the same problem is warned about once per run (timeouts in the message
# change every second, so digits are ignored when comparing).
agent_sync() {
    local desc=$1 msg w
    run_quiet "$desc" php "$LIBDIR/pspm-agent.php" sync && return 0
    msg=$(firewall_problem)
    msg=${msg:-"The firewall agent failed (see log)."}
    for w in "${WARNINGS[@]}"; do [[ ${w//[0-9]/} == "${msg//[0-9]/}" ]] && return 1; done
    warn "$msg"
    return 1
}

confirm() {
    local prompt=$1 answer
    [[ ${ASSUME_YES:-0} == 1 ]] && return 0
    if [[ ! -t 0 ]]; then error "$prompt — no terminal to ask; use --yes"; return 1; fi
    printf '  %s [y/N] ' "$prompt"
    read -r answer
    _log ASK "$prompt -> $answer"
    [[ $answer == y || $answer == Y || $answer == yes ]]
}

# Ask for the word "yes" typed out (for replacing hand edits). --yes is not enough.
confirm_word() {
    local prompt=$1 answer
    [[ ${DISCARD_DRIFT:-0} == 1 ]] && return 0
    if [[ ! -t 0 ]]; then error "$prompt — no terminal to ask; use --discard-drift"; return 1; fi
    printf '  %s Type yes to continue: ' "$prompt"
    read -r answer
    _log ASK "$prompt -> $answer"
    [[ $answer == yes ]]
}

# Print a secret to the terminal only (never to the log). Without a terminal, into a
# root-only file whose path is logged.
show_secret() {
    local label=$1 value=$2
    if [[ -t 1 ]]; then
        printf '\n  %s%s:%s %s\n' "$C_BLD" "$label" "$C_OFF" "$value"
        _log SECRET "$label shown on the terminal (not logged)"
    else
        local f
        f=/root/pspm-$(echo "$label" | tr 'A-Z ' 'a-z-' | tr -cd 'a-z0-9-' | cut -c1-40).txt
        (umask 077; printf '%s: %s\n' "$label" "$value" >"$f")
        _log SECRET "$label written to $f (not logged)"
        printf '  %s: written to %s\n' "$label" "$f"
    fi
}

write_install_status() {
    local code=$1 result=$2 phases warns
    [[ -d $STATUS ]] || return 0
    phases=$(printf '%s\n' "${PHASE_RESULTS[@]}" | jq -R . | jq -s .)
    warns=$(printf '%s\n' "${WARNINGS[@]}" | jq -R . | jq -s 'map(select(length > 0))')
    jq -n --arg started "$(date -u -d "@$RUN_START" +%FT%TZ)" --arg finished "$(date -u +%FT%TZ)" \
        --arg result "$result" --argjson exit "$code" --arg log "$LOG_FILE" --arg cmd "${COMMAND:-install}" \
        --argjson phases "$phases" --argjson warnings "$warns" \
        '{started: $started, finished: $finished, command: $cmd, result: $result, exit: $exit, log: $log, phases: $phases, warnings: $warnings}' \
        >"$STATUS/install.json.tmp" 2>/dev/null && mv -f "$STATUS/install.json.tmp" "$STATUS/install.json"
    chgrp pspm "$STATUS/install.json" 2>/dev/null; chmod 0640 "$STATUS/install.json" 2>/dev/null
    return 0
}
