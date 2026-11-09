#!/bin/bash
# PSPM — the single entry point: install, update, apply, rollback, status, doctor (plan §6).
#
#   sudo /opt/pspm/install.sh                      install or update everything, then apply the newest committed revision
#   sudo /opt/pspm/install.sh update [--to <c>]    deploy new code: fast-forward pull, then the full run
#   sudo /opt/pspm/install.sh apply [--revision N] apply only (skips packages and the app release)
#   sudo /opt/pspm/install.sh rollback             back to the previous release (works without the database)
#   sudo /opt/pspm/install.sh status | doctor      read-only
#   sudo /opt/pspm/install.sh firewall off|on      kill switch for the firewall layer
#   sudo /opt/pspm/install.sh report               one text file with everything needed for debugging
#
#   options: --yes  --dry-run  --discard-drift  --retry-certs  --verbose  --skip-upgrade  --force-os
#
# Every run writes /var/log/pspm/install-<timestamp>.log (install-latest.log points to it).
# Exit status: 0 ok · 1 failed (live state unchanged, or rolled back) · 2 applied with
# warnings · 3 cancelled, nothing applied.
#
# The body is a function called on the last line, so bash reads the whole file before it
# runs anything: a git pull during a run cannot change what this run does.

main() {
    set -uo pipefail
    set -E
    umask 022
    export LC_ALL=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    PSPM_REPO=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
    ORIG_ARGS=("$@")
    local f
    for f in log common phases apply commands; do
        # shellcheck source=/dev/null
        . "$PSPM_REPO/installer/$f.sh" || { echo "cannot load $PSPM_REPO/installer/$f.sh" >&2; exit 1; }
    done

    COMMAND=install
    ASSUME_YES=0 DRY_RUN=0 DISCARD_DRIFT=0 RETRY_CERTS=0 SKIP_UPGRADE=0 FORCE_OS=0
    APPLY_REVISION="" UPDATE_TO="" UPDATED_FROM="" FIREWALL_ARG=""
    UPDATE_PASS_ARGS=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            install|apply|rollback|status|doctor|update|report) COMMAND=$1 ;;
            firewall) COMMAND=firewall; FIREWALL_ARG=${2:-}; shift ;;
            --revision) APPLY_REVISION=${2:-}; shift; [[ $APPLY_REVISION =~ ^[0-9]+$ ]] || { echo "--revision needs a number" >&2; exit 64; } ;;
            --to) UPDATE_TO=${2:-}; shift ;;
            --yes|-y) ASSUME_YES=1; UPDATE_PASS_ARGS+=(--yes) ;;
            --dry-run) DRY_RUN=1 ;;
            --discard-drift) DISCARD_DRIFT=1; UPDATE_PASS_ARGS+=(--discard-drift) ;;
            --retry-certs) RETRY_CERTS=1; UPDATE_PASS_ARGS+=(--retry-certs) ;;
            --verbose|-v) VERBOSE=1; UPDATE_PASS_ARGS+=(--verbose) ;;
            --skip-upgrade) SKIP_UPGRADE=1 ;;
            --force-os) FORCE_OS=1; UPDATE_PASS_ARGS+=(--force-os) ;;
            --updated-from) UPDATED_FROM=${2:-}; shift ;;
            --import) echo "install.sh --import comes with the export/import phase (plan §16); it is not built yet." >&2; exit 64 ;;
            -h|--help) sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
            *) echo "unknown argument: $1 (see install.sh --help)" >&2; exit 64 ;;
        esac
        shift
    done
    [[ $EUID -eq 0 ]] || { echo "Run as root: sudo $PSPM_REPO/install.sh ${ORIG_ARGS[*]}" >&2; exit 1; }

    case $COMMAND in
        status) cmd_status; exit $? ;;
        doctor) log_init doctor; cmd_doctor; exit $? ;;
        report) log_init report; cmd_report; exit $? ;;
    esac

    log_init install
    trap '_on_err $? $LINENO "$BASH_COMMAND"' ERR
    trap 'rc=$?; [[ -z ${SUMMARY_DONE:-} ]] && { _log ABORT "stopped at exit $rc in phase ${CURRENT_PHASE:-none}"; summary "$rc"; }' EXIT
    log_system_header
    [[ -n $UPDATED_FROM ]] && _log INFO "updated from commit $UPDATED_FROM"
    printf '%sPSPM%s · Secure Proxy Manager — %s (log: %s)\n' "$C_BLD" "$C_OFF" "$COMMAND" "$LOG_FILE"

    case $COMMAND in
        install)
            phase_preflight
            phase_packages
            phase_baseline
            phase_users_dirs
            phase_database
            phase_backup
            phase_migrations
            phase_app_release
            phase_units
            phase_firewall
            phase_bootstrap
            phase_apply
            phase_certificates
            phase_report
            ;;
        apply)
            PHASE_TOTAL=14
            phase_preflight
            phase_apply
            phase_certificates
            phase_report
            ;;
        rollback)
            phase_preflight
            phase 12 "Roll back"
            cmd_rollback && phase_end ok || fail "Rollback failed" 1
            ;;
        update)
            phase_preflight
            phase 0 "Update the code"
            cmd_update
            ;;
        firewall)
            phase_preflight
            phase 10 "Firewall $FIREWALL_ARG"
            cmd_firewall "$FIREWALL_ARG"
            phase_end ok
            ;;
    esac
    local code=0
    [[ ${#WARNINGS[@]} -gt 0 ]] && code=2   # applied, with warnings
    [[ ${APPLY_CANCELLED:-0} == 1 ]] && code=3   # cancelled: nothing was applied
    summary "$code"
    exit "$code"
}

main "$@"
