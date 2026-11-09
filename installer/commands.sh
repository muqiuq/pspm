# shellcheck shell=bash
# install.sh status | doctor | update | firewall | report

cmd_status() {
    local cur sum
    cur=$(basename "$(readlink -f "$NGX/current" 2>/dev/null)" 2>/dev/null || true)
    sum=$NGX/current/summary.json
    printf '%sPSPM%s · Secure Proxy Manager · code %s\n' "$C_BLD" "$C_OFF" "$(cat "$APP_ROOT/current/COMMIT" 2>/dev/null || echo '?')"
    printf '  live release:    %s (revision %s)\n' "${cur:-none}" "$(jq -r .id "$NGX/current/revision.json" 2>/dev/null || echo '-')"
    printf '  nginx loaded:    %s\n' "$(curl -s --max-time 2 http://127.0.0.1:9080/pspm-release || echo 'not answering')"
    local latest
    latest=$(as_pspm php "$(app_dir)/bin/revision.php" latest-id 2>/dev/null || echo '?')
    printf '  newest revision: %s\n' "$latest"
    local u
    for u in nginx "$FPM_SERVICE" docker pspm-agent.timer certbot.timer; do
        printf '  %-16s %s\n' "$u:" "$(systemctl is-active "$u" 2>/dev/null)"
    done
    printf '  postgres:        %s\n' "$(docker inspect -f '{{.State.Health.Status}}' pspm-postgres 2>/dev/null || echo 'not running')"
    printf '  firewall:        %s\n' "$(iptables -C INPUT -j PSPM-INPUT 2>/dev/null && echo 'active' || echo 'not active')"
    if [[ -f $sum && "$(jq -r .admin.in_effect "$sum")" == true ]]; then
        printf '  UI:              https://%s/\n' "$(jq -r .admin.host "$sum")"
    else
        local a
        for a in $(box_addresses); do is_private_addr "$a" && printf '  UI:              https://%s/\n' "$([[ $a == *:* ]] && echo "[$a]" || echo "$a")"; done
    fi
    printf '  tunnel:          ssh -L 9443:127.0.0.1:9443 %s@%s  then https://localhost:9443/\n' "${SUDO_USER:-root}" "$(hostname -f 2>/dev/null || hostname)"
    printf '  IP certificate:  SHA-256 %s\n' "$(ip_cert_fingerprint)"
    printf '  last run:        %s\n' "$(jq -r '"\(.finished) \(.command): \(.result) — \(.log)"' "$STATUS/install.json" 2>/dev/null || echo '-')"
    if [[ -f $NGX/current/MANIFEST.sha256 ]]; then
        local d
        d=$(cd "$NGX/current" && sha256sum --quiet -c MANIFEST.sha256 2>/dev/null | wc -l)
        [[ $d -gt 0 ]] && printf '  %sdrift:           %s files of the live release changed by hand%s\n' "$C_YEL" "$d" "$C_OFF"
    fi
    return 0
}

cmd_doctor() {
    local probs=0
    check() { # check "label" level(cmd result) message
        if "${@:3}" >/dev/null 2>&1; then printf '  %s✓%s %s\n' "$C_GRN" "$C_OFF" "$1"; _log OK "doctor: $1"
        else printf '  %s%s%s %s — %s\n' "$([[ $2 == warn ]] && echo "$C_YEL!" || echo "$C_RED✗")" "" "$C_OFF" "$1" "${DOCTOR_HINT:-}"; _log WARN "doctor: $1"; probs=$((probs + 1)); fi
        DOCTOR_HINT=""
    }
    DOCTOR_HINT="systemctl status nginx"; check "nginx is running" err systemctl is-active -q nginx
    DOCTOR_HINT="run install.sh"; check "nginx runs PSPM's configuration" err nginx_runs_pspm
    DOCTOR_HINT="nginx -t -p $NGX/current/ -c nginx.conf"; check "the live configuration passes nginx -t" err nginx_test "$NGX/current"
    DOCTOR_HINT="journalctl -u $FPM_SERVICE"; check "php-fpm is running" err systemctl is-active -q "$FPM_SERVICE"
    DOCTOR_HINT="docker logs pspm-postgres"; check "PostgreSQL is healthy" err sh -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' pspm-postgres)\" = healthy ]"
    DOCTOR_HINT="curl http://127.0.0.1:9080/healthz"; check "the UI answers /healthz" err sh -c '[ "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:9080/healthz)" = 200 ]'
    DOCTOR_HINT="systemctl enable --now certbot.timer"; check "certificate renewal timer is active" err systemctl is-active -q certbot.timer
    local f exp days
    for f in /etc/letsencrypt/live/*/cert.pem; do
        [[ -f $f ]] || continue
        exp=$(date -d "$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)" +%s)
        days=$(( (exp - $(date +%s)) / 86400 ))
        DOCTOR_HINT="certbot renew --dry-run"; check "certificate $(basename "$(dirname "$f")") valid for $days more days" warn test "$days" -gt 14
    done
    DOCTOR_HINT="install.sh firewall on"; check "firewall chain PSPM-INPUT is the first rule of INPUT" warn sh -c 'iptables -S INPUT | sed -n 2p | grep -q -- "-j PSPM-INPUT"'
    DOCTOR_HINT="Docker and PSPM must use the same iptables backend"; check "iptables uses nf_tables" warn sh -c 'iptables --version | grep -q nf_tables'
    DOCTOR_HINT="systemctl status pspm-agent"; check "agent heartbeat younger than 5 minutes" warn sh -c "[ \$(( \$(date +%s) - \$(stat -c %Y $STATUS/firewall.json) )) -lt 300 ]"
    DOCTOR_HINT="timedatectl"; check "the clock is synchronised" warn sh -c '[ "$(timedatectl show -p NTPSynchronized --value)" = yes ]'
    DOCTOR_HINT="free some space"; check "more than 2 GB free on /var" warn sh -c '[ $(df -Pk /var | awk "NR==2 {print \$4}") -gt 2097152 ]'
    DOCTOR_HINT="/etc/docker/daemon.json"; check "docker live-restore is on" warn sh -c 'docker info -f "{{.LiveRestoreEnabled}}" | grep -q true'
    DOCTOR_HINT="/etc/apt/apt.conf.d/20auto-upgrades"; check "automatic security updates are on" warn sh -c 'apt-config dump | grep -q "APT::Periodic::Unattended-Upgrade \"1\""'
    DOCTOR_HINT="is the deploy key still on GitHub? (plan §6.6)"; check "the repository is reachable (git ls-remote)" warn timeout 20 git -C "$PSPM_REPO" ls-remote -q origin HEAD
    DOCTOR_HINT="consider key-only logins: PasswordAuthentication no"; check "sshd does not accept passwords" warn sh -c '! sshd -T 2>/dev/null | grep -qi "^passwordauthentication yes"'
    DOCTOR_HINT="PermitRootLogin prohibit-password"; check "sshd does not accept root passwords" warn sh -c '! sshd -T 2>/dev/null | grep -qi "^permitrootlogin yes"'
    if [[ -f /var/run/reboot-required ]]; then printf '  %s!%s a reboot is pending (/var/run/reboot-required)\n' "$C_YEL" "$C_OFF"; fi
    printf '\n%s problems found.\n' "$probs"
    [[ $probs -eq 0 ]]
}

# install.sh update [--to <commit>]: fast-forward pull, then the full run (plan §6.7).
cmd_update() {
    git -C "$PSPM_REPO" rev-parse --git-dir >/dev/null 2>&1 || fail "$PSPM_REPO is not a git checkout." 1
    local dirty branch upstream old new
    dirty=$(git -C "$PSPM_REPO" status --porcelain --untracked-files=no)
    [[ -z $dirty ]] || { log_raw "$dirty"; fail "$PSPM_REPO has local changes; commit, stash or discard them first (git -C $PSPM_REPO status)." 1; }
    old=$(git -C "$PSPM_REPO" rev-parse HEAD)
    run "git fetch" git -C "$PSPM_REPO" fetch --prune origin || fail "git fetch failed (network, or the deploy key: ssh -T git@github.com)." 1
    if [[ -n ${UPDATE_TO:-} ]]; then
        new=$(git -C "$PSPM_REPO" rev-parse --verify "${UPDATE_TO}^{commit}" 2>/dev/null) || fail "Unknown commit: $UPDATE_TO" 1
        branch=$(git -C "$PSPM_REPO" rev-parse --abbrev-ref HEAD)
        upstream=$(git -C "$PSPM_REPO" rev-parse --abbrev-ref '@{u}' 2>/dev/null || echo "origin/$branch")
        git -C "$PSPM_REPO" merge-base --is-ancestor "$new" "$upstream" || fail "$UPDATE_TO is not on $upstream." 1
    else
        branch=$(git -C "$PSPM_REPO" rev-parse --abbrev-ref HEAD)
        [[ $branch != HEAD ]] || fail "$PSPM_REPO is not on a branch (detached HEAD). Run: git -C $PSPM_REPO checkout main" 1
        upstream=$(git -C "$PSPM_REPO" rev-parse --abbrev-ref '@{u}' 2>/dev/null) || fail "Branch $branch has no upstream." 1
        new=$(git -C "$PSPM_REPO" rev-parse "$upstream")
    fi
    if [[ $old == "$new" ]]; then ok "Already at $(git -C "$PSPM_REPO" rev-parse --short "$new")."
    else
        info "New commits:"
        git -C "$PSPM_REPO" log --oneline "$old..$new" | sed 's/^/    /' | tee -a "$LOG_FILE"
        local mig
        mig=$(git -C "$PSPM_REPO" diff --name-only "$old" "$new" -- db/migrations | sed 's/^/    /')
        [[ -n $mig ]] && { info "New database migrations (a backup is taken first):"; printf '%s\n' "$mig"; }
        confirm "Deploy $(git -C "$PSPM_REPO" rev-parse --short "$new")?" || { info "Nothing changed."; exit 0; }
        if [[ -n ${UPDATE_TO:-} ]]; then run "git checkout" git -C "$PSPM_REPO" checkout -q --detach "$new" || fail "checkout failed" 1
        else run "git merge --ff-only" git -C "$PSPM_REPO" merge --ff-only "$upstream" || fail "Not a fast-forward; nothing changed." 1; fi
    fi
    info "Running the new install.sh…"
    _log INFO "exec $PSPM_REPO/install.sh ${UPDATE_PASS_ARGS[*]} --updated-from ${old:0:12}"
    exec 3>&-
    flock -u 9 2>/dev/null; exec 9>&-
    exec "$PSPM_REPO/install.sh" "${UPDATE_PASS_ARGS[@]}" --updated-from "${old:0:12}"
}

cmd_firewall() {
    case ${1:-} in
        off) touch "$ETC/firewall-off"; run "firewall off" php "$LIBDIR/pspm-agent.php" off && ok "The firewall layer is off (jump removed). nginx still blocks. Turn on: install.sh firewall on" ;;
        on)  rm -f "$ETC/firewall-off"; run "firewall setup" php "$LIBDIR/pspm-agent.php" setup && run "firewall sync" php "$LIBDIR/pspm-agent.php" sync && ok "The firewall layer is on." ;;
        *) fail "usage: install.sh firewall on|off" 64 ;;
    esac
}

# One text file with everything needed for debugging; secrets are redacted.
cmd_report() {
    local out
    out=$PSPM_LOG_DIR/report-$(date +%Y%m%d-%H%M%S).txt
    {
        section() { printf '\n\n######## %s\n' "$1"; }
        section "status";        cmd_status 2>&1
        section "doctor";        cmd_doctor 2>&1
        section "latest install log ($(readlink -f "$PSPM_LOG_DIR/install-latest.log" 2>/dev/null))"; cat "$PSPM_LOG_DIR/install-latest.log" 2>/dev/null
        section "previous install logs"; ls -la "$PSPM_LOG_DIR" 2>/dev/null
        section "versions";      dpkg-query -W -f='${Package}=${Version}\n' "${PACKAGES[@]}" 2>/dev/null; uname -a; cat /etc/os-release
        section "units";         systemctl --no-pager status nginx "$FPM_SERVICE" docker pspm-agent.service pspm-agent.timer pspm-firewall.service 2>&1 | head -n 120
        section "journal nginx"; journalctl -u nginx -n 80 --no-pager 2>&1
        section "journal php-fpm"; journalctl -u "$FPM_SERVICE" -n 80 --no-pager 2>&1
        section "journal agent"; journalctl -u pspm-agent -u pspm-firewall -n 60 --no-pager 2>&1
        section "nginx error.log (tail)"; tail -n 120 /var/log/nginx/error.log 2>&1
        section "nginx master";  nginx_master_cmdline; echo; cat "$DROPIN" 2>&1
        section "releases";      ls -la "$NGX" "$NGX/releases" 2>&1 | tail -n 40; cat "$JOURNAL" 2>&1
        section "live summary";  cat "$NGX/current/summary.json" 2>&1
        section "drift";         (cd "$NGX/current" && sha256sum --quiet -c MANIFEST.sha256) 2>&1
        section "nginx -T";      nginx -T -p "$NGX/current/" -c nginx.conf 2>&1 | head -n 3000
        section "docker";        docker ps -a 2>&1; docker logs --tail 80 pspm-postgres 2>&1
        section "firewall";      iptables -S PSPM-INPUT 2>&1; iptables -S INPUT 2>&1 | head -n 5; ip6tables -S PSPM-INPUT 2>&1; ipset list -t 2>&1; cat "$STATUS/firewall.json" 2>&1
        section "status files";  for f in "$STATUS"/*.json; do echo "== $f"; cat "$f"; echo; done
        section "listening";     ss -tlnp 2>&1
        section "files";         ls -la "$ETC" "$VAR" "$STATE" "$APP_ROOT" 2>&1
        section "disk";          df -h 2>&1
    } 2>&1 | sed -E \
        -e 's/(POSTGRES_PASSWORD|PASSWORD|PGPASSWORD|password|secret|token|Authorization)([=: ]+)[^ ]+/\1\2[redacted]/Ig' \
        -e 's#(/\.pspm/access/)[A-Za-z0-9_-]+#\1[redacted]#g' >"$out"
    chmod 0640 "$out"
    ok "Report written: $out ($(du -h "$out" | cut -f1)). Passwords and tokens are redacted; check it before you share it."
}
