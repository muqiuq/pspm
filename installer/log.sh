# shellcheck shell=bash
# Logging for install.sh. Every run writes one complete transcript:
#   /var/log/pspm/install-<YYYYmmdd-HHMMSS>.log   (install-latest.log points to the newest)
# The terminal shows a short version; the log has every command, its output, exit code
# and duration, the phase markers, failing lines (ERR trap) and a summary.
# Secrets never go to the log: generated passwords are printed to the terminal only.

PSPM_LOG_DIR=${PSPM_LOG_DIR:-/var/log/pspm}
LOG_FILE=""
VERBOSE=${VERBOSE:-0}
WARNINGS=()
PHASE_RESULTS=()
CURRENT_PHASE=""
PHASE_START=0
PHASE_TOTAL=14
RUN_START=$(date +%s)
if [[ -t 1 ]]; then C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLD=$'\e[1m'; C_DIM=$'\e[2m'; C_OFF=$'\e[0m'
else C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_DIM=""; C_OFF=""; fi

log_init() {
    local kind=${1:-install}
    mkdir -p "$PSPM_LOG_DIR"
    chmod 0750 "$PSPM_LOG_DIR"
    getent group pspm >/dev/null && chgrp pspm "$PSPM_LOG_DIR"
    LOG_FILE="$PSPM_LOG_DIR/$kind-$(date +%Y%m%d-%H%M%S).log"
    [[ -e $LOG_FILE ]] && LOG_FILE="${LOG_FILE%.log}-$$.log"
    : >"$LOG_FILE"
    chmod 0640 "$LOG_FILE"
    getent group pspm >/dev/null && chgrp pspm "$LOG_FILE"
    [[ $kind == install ]] && ln -sfn "$(basename "$LOG_FILE")" "$PSPM_LOG_DIR/install-latest.log"
    exec 3>>"$LOG_FILE"
    # fd 4 = the terminal's stderr. Everything else written to stderr (bash's own error
    # messages included) is copied into the log with an STDERR prefix.
    exec 4>&2
    ERR_FD=4
    exec 2> >(while IFS= read -r l; do printf '%s STDERR %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$l" >&3; printf '%s\n' "$l" >&4; done)
}

_ts() { date '+%Y-%m-%d %H:%M:%S'; }
_log() { [[ -n $LOG_FILE ]] && printf '%s %-5s %s\n' "$(_ts)" "$1" "$2" >&3; return 0; }
log_raw() { [[ -n $LOG_FILE ]] && printf '%s\n' "$*" >&3; return 0; }

info()  { _log INFO "$*";  printf '  %s\n' "$*"; }
ok()    { _log OK "$*";    printf '  %s✓%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
note()  { _log INFO "$*";  printf '  %s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }
warn()  { _log WARN "$*";  WARNINGS+=("$*"); printf '  %s!%s %s\n' "$C_YEL" "$C_OFF" "$*" >&"${ERR_FD:-2}"; }
error() { _log ERROR "$*"; printf '  %s✗ %s%s\n' "$C_RED" "$*" "$C_OFF" >&"${ERR_FD:-2}"; }
debug() { _log DEBUG "$*"; [[ $VERBOSE == 1 ]] && printf '    %s%s%s\n' "$C_DIM" "$*" "$C_OFF"; return 0; }

# Unexpected non-zero exits are logged with line and call stack (they do not abort by
# themselves; every important step checks its own result).
_on_err() {
    local rc=$1 line=$2 cmd=$3
    _log TRACE "exit $rc at line $line: $cmd  [${FUNCNAME[*]:1}]"
}

# run "description" cmd args…   Runs a command; stdout+stderr go to the log (and to the
# terminal with --verbose). Returns the command's exit code. On failure the last lines
# of output are also shown on the terminal.
run() {
    local desc=$1; shift
    local tmp rc start ms
    tmp=$(mktemp)
    start=$(date +%s%3N)
    _log CMD "$desc :: $(printf '%q ' "$@")"
    if [[ $VERBOSE == 1 ]]; then
        "$@" 2>&1 | tee "$tmp" | sed 's/^/    | /'
        rc=${PIPESTATUS[0]}
    else
        "$@" >"$tmp" 2>&1
        rc=$?
    fi
    ms=$(( $(date +%s%3N) - start ))
    sed 's/^/    | /' "$tmp" >&3
    _log RC "$desc :: exit $rc after $((ms / 1000)).$(printf '%03d' $((ms % 1000)))s"
    if [[ $rc -ne 0 && $VERBOSE != 1 ]]; then
        printf '  %s%s failed (exit %s). Last output:%s\n' "$C_RED" "$desc" "$rc" "$C_OFF" >&"${ERR_FD:-2}"
        tail -n 15 "$tmp" | sed 's/^/    | /' >&"${ERR_FD:-2}"
    fi
    rm -f "$tmp"
    return "$rc"
}

# run_quiet: like run, but failures are expected and not shown on the terminal.
run_quiet() {
    local desc=$1; shift
    local tmp rc
    tmp=$(mktemp)
    _log CMD "$desc :: $(printf '%q ' "$@")"
    "$@" >"$tmp" 2>&1
    rc=$?
    sed 's/^/    | /' "$tmp" >&3
    _log RC "$desc :: exit $rc"
    rm -f "$tmp"
    return "$rc"
}

# capture VAR "description" cmd args…   Stores stdout in VAR (stderr goes to the log).
capture() {
    local __var=$1 desc=$2; shift 2
    local tmp_out tmp_err rc
    tmp_out=$(mktemp); tmp_err=$(mktemp)
    _log CMD "$desc :: $(printf '%q ' "$@")"
    "$@" >"$tmp_out" 2>"$tmp_err"
    rc=$?
    if [[ -s $tmp_err ]]; then sed 's/^/    ! /' "$tmp_err" >&3; fi
    _log RC "$desc :: exit $rc ($(wc -c <"$tmp_out") bytes of output)"
    printf -v "$__var" '%s' "$(cat "$tmp_out")"
    if [[ $rc -ne 0 && -s $tmp_err ]]; then tail -n 10 "$tmp_err" | sed 's/^/    ! /' >&"${ERR_FD:-2}"; fi
    rm -f "$tmp_out" "$tmp_err"
    return "$rc"
}

phase() {
    CURRENT_PHASE="$1 $2"
    PHASE_START=$(date +%s)
    log_raw ""
    _log PHASE "===== [$1/$PHASE_TOTAL] $2 ====="
    printf '\n%s[%s/%s] %s%s\n' "$C_BLD" "$1" "$PHASE_TOTAL" "$2" "$C_OFF"
}

# phase_end ok|warn|skip|fail [message]
phase_end() {
    local st=$1 msg=${2:-} dur
    dur=$(( $(date +%s) - PHASE_START ))
    PHASE_RESULTS+=("$(printf '%-28s %-5s %5ss  %s' "$CURRENT_PHASE" "$st" "$dur" "$msg")")
    _log PHASE "----- $CURRENT_PHASE: $st (${dur}s) $msg"
    CURRENT_PHASE=""
}

# fail "message" [exit code]: end the current phase as failed, print the summary, exit.
fail() {
    local msg=$1 code=${2:-1}
    error "$msg"
    [[ -n $CURRENT_PHASE ]] && phase_end fail "$msg"
    summary "$code"
    exit "$code"
}

summary() {
    local code=${1:-0} result
    [[ -n ${SUMMARY_DONE:-} ]] && return 0
    SUMMARY_DONE=1
    if [[ $code -eq 3 ]]; then result="NOT APPLIED (cancelled, exit 3)"
    elif [[ $code -eq 2 && ${#WARNINGS[@]} -gt 0 ]]; then result="OK WITH WARNINGS (exit 2)"
    elif [[ $code -ne 0 ]]; then result="FAILED (exit $code)"
    elif [[ ${#WARNINGS[@]} -gt 0 ]]; then result="OK WITH WARNINGS"
    else result="OK"; fi
    log_raw ""
    _log PHASE "===== Summary ====="
    local p w
    for p in "${PHASE_RESULTS[@]}"; do log_raw "  $p"; done
    for w in "${WARNINGS[@]}"; do log_raw "  warning: $w"; done
    _log RESULT "$result after $(( $(date +%s) - RUN_START ))s"
    printf '\n%sResult: %s%s\n' "$C_BLD" "$result" "$C_OFF"
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        printf '%sWarnings:%s\n' "$C_YEL" "$C_OFF"
        for w in "${WARNINGS[@]}"; do printf '  - %s\n' "$w"; done
    fi
    if [[ -n ${ADMIN_PASSWORD:-} ]]; then
        printf '\n%sThe user admin was created in this run. Its password (shown once, not logged):%s %s\n' "$C_BLD" "$C_OFF" "$ADMIN_PASSWORD"
        [[ $code -ne 0 && $code -ne 2 ]] && printf 'Fix the problem above and run install.sh again; the password stays valid.\n'
    fi
    [[ -n $LOG_FILE ]] && printf 'Log: %s\n' "$LOG_FILE"
    [[ $code -eq 1 ]] && printf 'For help, send the log, or run %ssudo %s report%s and send the file it writes.\n' "$C_BLD" "$PSPM_REPO/install.sh" "$C_OFF"
    type write_install_status >/dev/null 2>&1 && write_install_status "$code" "$result"
    return 0
}

# Everything about the machine that helps debugging, into the log only.
log_system_header() {
    log_raw "===================================================================="
    log_raw "PSPM install.sh — $(_ts)"
    log_raw "command:   $0 ${ORIG_ARGS[*]}"
    log_raw "code:      $(git -C "$PSPM_REPO" describe --always --dirty 2>/dev/null || echo 'not a git checkout') ($(git -C "$PSPM_REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '-'))"
    log_raw "version:   $(cat "$PSPM_REPO/app/VERSION" 2>/dev/null || echo '?')"
    log_raw "user:      ${SUDO_USER:-$(id -un)} (uid $EUID)  ssh: ${SSH_CONNECTION:-none}"
    log_raw "host:      $(hostname -f 2>/dev/null || hostname)  $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
    log_raw "kernel:    $(uname -srm)  uptime: $(uptime -p 2>/dev/null || true)"
    log_raw "time:      $(date -u '+%Y-%m-%dT%H:%M:%SZ')  ntp-sync: $(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo '?')"
    log_raw "disk:"
    df -hP / /var 2>/dev/null | sed 's/^/    /' >&3
    log_raw "memory:    $(free -m 2>/dev/null | awk '/^Mem:/ {print $2 " MB total, " $7 " MB available"}')"
    log_raw "addresses: $(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
    local pkgs="nginx libnginx-mod-http-lua php8.4-fpm docker.io docker-compose certbot ipset iptables"
    log_raw "packages:  $(dpkg-query -W -f='${Package}=${Version} ' $pkgs 2>/dev/null)"
    log_raw "nginx:     $(tr '\0' ' ' 2>/dev/null </proc/"$(cat /run/nginx.pid 2>/dev/null || echo 0)"/cmdline || echo 'not running')"
    log_raw "release:   $(readlink /etc/pspm/nginx/current 2>/dev/null || echo none)"
    log_raw "journal:   $(tr '\n' ' ' 2>/dev/null </var/lib/pspm/apply.journal || echo none)"
    log_raw "===================================================================="
}
