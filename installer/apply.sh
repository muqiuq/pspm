# shellcheck shell=bash
# Phase 12: render, review, test, switch, reload, verify, roll back (plan §6.3).
# Every step is atomic, so nginx always runs either the previous or the new, tested config.

phase_apply() {
    phase 12 "Apply the configuration"
    local rc=0
    apply_configuration "${APPLY_REVISION:-}" || rc=$?
    case $rc in
        0) phase_end ok "${APPLY_RESULT:-}" ;;
        2) phase_end fail "rolled back: ${APPLY_RESULT:-}"; summary 1; exit 1 ;;
        3) phase_end skip "${APPLY_RESULT:-}"; [[ ${DRY_RUN:-0} == 1 ]] || APPLY_CANCELLED=1 ;;
        *) phase_end fail "${APPLY_RESULT:-}"; summary 1; exit 1 ;;
    esac
}

# Returns 0 applied (or nothing to do), 1 failed before the switch (live unchanged),
# 2 failed after the switch and rolled back, 3 cancelled or dry run.
apply_configuration() {
    local want_rev=$1 app rev_json rel rel_dir prev started out rc
    app=$(app_dir)
    started=$(date -u +%FT%TZ)
    APPLY_RESULT=""

    if [[ ${INTERRUPTED:-0} == 1 ]]; then
        info "Checking the release that was being switched when the last run stopped…"
        if verify_release "$(basename "$(readlink -f "$NGX/current")")"; then ok "It is live and healthy."
        else warn "It does not verify; this run applies again (and rolls back if needed)."; fi
        INTERRUPTED=0
    fi

    # 1. Read the revision (newest committed, or --revision N).
    if [[ "$(as_pspm php "$app/bin/revision.php" latest-id 2>/dev/null)" == 0 ]]; then
        info "No revision yet: committing the initial (empty) configuration."
        run "initial revision" as_pspm php "$app/bin/revision.php" commit-working "initial configuration" \
            || { APPLY_RESULT="cannot create the initial revision"; return 1; }
    fi
    local rev_args=(export)
    [[ -n $want_rev ]] && rev_args+=(--id "$want_rev")
    capture rev_json "read revision" as_pspm php "$app/bin/revision.php" "${rev_args[@]}" \
        || { APPLY_RESULT="cannot read the revision from the database"; error "$APPLY_RESULT"; return 1; }
    local rev_id
    rev_id=$(jq -r .id <<<"$rev_json")
    info "Revision $rev_id by $(jq -r .author <<<"$rev_json") ($(jq -r '.message // ""' <<<"$rev_json"))"

    rel="$(date +%Y%m%d-%H%M%S)-r$rev_id"
    rel_dir=$NGX/releases/$rel
    prev=""
    [[ -L $NGX/current && -d $(readlink -f "$NGX/current") ]] && prev=$(basename "$(readlink -f "$NGX/current")")

    # Drift: hand edits in the live release (plan §6.8).
    local drift=""
    if [[ -n $prev && -f $NGX/current/MANIFEST.sha256 ]]; then
        drift=$(cd "$NGX/current" && sha256sum --quiet -c MANIFEST.sha256 2>&1 | grep -v '^sha256sum: WARNING' || true)
        local extra
        extra=$(cd "$NGX/current" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | sort | comm -23 - <(awk '{print $2}' MANIFEST.sha256 | sed 's#^\*##; s#^\./##' | sort))
        [[ -n $extra ]] && drift="$drift"$'\n'"$(sed 's/$/: ADDED/' <<<"$extra")"
        drift=$(sed '/^$/d' <<<"$drift")
    fi

    # 2. Facts and render (as the unprivileged pspm-render).
    install -d -m 0755 "$rel_dir"
    printf '%s\n' "$rev_json" >"$rel_dir/revision.json"
    collect_facts "$rel" "$rev_json" >"$rel_dir/facts.json" || { APPLY_RESULT="collecting facts failed"; rm -rf "$rel_dir"; return 1; }
    # A private directory: root opens both files and hands them to the renderer as
    # stdin/stdout, so pspm-render needs no file access at all.
    local work input output
    work=$(mktemp -d /run/pspm/render.XXXXXX)
    input=$work/input.json; output=$work/output.json
    jq -n --slurpfile r "$rel_dir/revision.json" --slurpfile f "$rel_dir/facts.json" '{revision: $r[0], facts: $f[0]}' >"$input"
    runuser -u pspm-render -- php "$app/bin/render.php" <"$input" >"$output" 2>>"$LOG_FILE"
    rc=$?
    rm -f "$input"
    if [[ $rc -eq 2 ]]; then
        error "The revision is not valid:"
        jq -r '.errors[]' "$output" | sed 's/^/    - /' | tee -a "$LOG_FILE" >&2
        APPLY_RESULT="revision $rev_id is invalid"; rm -rf "$rel_dir" "$work"; return 1
    elif [[ $rc -ne 0 ]]; then
        APPLY_RESULT="the renderer failed (exit $rc, see log)"; error "$APPLY_RESULT"; rm -rf "$rel_dir" "$work"; return 1
    fi
    while IFS= read -r w; do [[ -n $w ]] && warn "$w"; done < <(jq -r '.warnings[]' "$output")
    # Root writes only whitelisted relative paths.
    local p n=0
    while IFS= read -r p; do
        if [[ ! $p =~ ^(nginx\.conf|(conf|sites|ca|oauth2-proxy)/[A-Za-z0-9][A-Za-z0-9._-]*)$ ]]; then
            APPLY_RESULT="the renderer produced a path that is not allowed: $p"; error "$APPLY_RESULT"; rm -rf "$rel_dir" "$work"; return 1
        fi
        install -d -m 0755 "$rel_dir/$(dirname "$p")"
        jq -j --arg p "$p" '.files[$p]' "$output" >"$rel_dir/$p"
        n=$((n + 1))
    done < <(jq -r '.files | keys[]' "$output")
    jq '.summary' "$output" >"$rel_dir/summary.json"
    rm -rf "$work"
    cp -r "$PSPM_REPO/nginx/static" "$rel_dir/static"
    cp -r "$PSPM_REPO/lua" "$rel_dir/lua"
    chown -R root:root "$rel_dir"; find "$rel_dir" -type d -exec chmod 0755 {} +; find "$rel_dir" -type f -exec chmod 0644 {} +
    (cd "$rel_dir" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | sort | xargs sha256sum >MANIFEST.sha256)
    local manifest_sha
    manifest_sha=$(sha256sum "$rel_dir/MANIFEST.sha256" | cut -c1-64)
    ok "Rendered $n files into $rel"

    # 3. Review.
    local diff_out
    if [[ -n $prev ]]; then
        diff_out=$(diff -ruN -x MANIFEST.sha256 -x revision.json -x facts.json -x summary.json -x release.conf "$NGX/releases/$prev" "$rel_dir" || true)
    else
        diff_out="(first configuration)"
    fi
    if [[ -n $prev && -z $diff_out && -z $drift && ${CERT_REAPPLY:-0} != 1 ]] && nginx_runs_pspm; then
        rm -rf "$rel_dir"
        APPLY_RESULT="nothing changed; release $prev stays live"
        ok "No changes: release $prev (revision $rev_id) is live."
        verify_release "$prev" || warn "The live release does not verify (see above)."
        return 0
    fi
    review_changes "$prev" "$rel_dir" "$diff_out"
    if [[ -n $drift ]]; then
        printf '\n  %sChanged outside PSPM in the live release %s:%s\n' "$C_YEL" "$prev" "$C_OFF"
        sed 's/^/    /' <<<"$drift"
        log_raw "drift: $drift"
        info "The new release replaces these edits. The edited release stays on disk as $NGX/releases/$prev."
        if ! confirm_word "Replace the hand edits?"; then
            rm -rf "$rel_dir"; APPLY_RESULT="cancelled: hand edits kept"; warn "$APPLY_RESULT"; return 3
        fi
    fi
    if [[ ${DRY_RUN:-0} == 1 ]]; then
        if nginx_test "$rel_dir" >>"$LOG_FILE" 2>&1; then ok "nginx -t passes (dry run: nothing switched)"; else error "nginx -t fails (see log)"; fi
        record_apply "$rev_id" "$rel" "$manifest_sha" dry_run "dry run" "$started"
        rm -rf "$rel_dir"; APPLY_RESULT="dry run"; return 3
    fi
    # Nothing is live before the first release, so the first apply does not ask.
    if [[ ${CERT_REAPPLY:-0} != 1 && -n $prev ]] && ! confirm "Apply revision $rev_id?"; then
        rm -rf "$rel_dir"; APPLY_RESULT="cancelled"; warn "Cancelled; nothing changed."; return 3
    fi

    # 4. Test.
    if ! run "nginx -t" nginx -t -p "$rel_dir/" -c nginx.conf; then
        record_apply "$rev_id" "$rel" "$manifest_sha" failed "nginx -t failed" "$started"
        mv "$rel_dir" "$rel_dir.failed"
        APPLY_RESULT="nginx -t rejected the new configuration; nothing was switched (kept as $rel.failed)"; error "$APPLY_RESULT"; return 1
    fi
    local lf
    for lf in "$rel_dir"/lua/*.lua; do
        if ! run_quiet "lua syntax $(basename "$lf")" luajit -b "$lf" /dev/null; then
            record_apply "$rev_id" "$rel" "$manifest_sha" failed "Lua syntax error" "$started"
            APPLY_RESULT="Lua syntax error in $(basename "$lf")"; error "$APPLY_RESULT"; rm -rf "$rel_dir"; return 1
        fi
    done
    # CA bundle: every entry CA:TRUE, self-signed, not expired, fingerprint as in the revision.
    local caf caid want have
    for caf in "$rel_dir"/ca/client-*.pem; do
        [[ -f $caf ]] || continue
        caid=$(basename "$caf" .pem); caid=${caid#client-}
        want=$(jq -r --arg id "$caid" '.document.cas[]? | select(.id == $id) | .fingerprint_sha256' "$rel_dir/revision.json")
        have=$(openssl x509 -in "$caf" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')
        if ! openssl x509 -in "$caf" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE' \
            || ! openssl verify -no-CApath -no-CAfile -CAfile "$caf" "$caf" >/dev/null 2>&1 \
            || ! openssl x509 -in "$caf" -noout -checkend 0 >/dev/null 2>&1 || [[ -z $want || $want != "$have" ]]; then
            record_apply "$rev_id" "$rel" "$manifest_sha" failed "CA bundle check failed for $caid" "$started"
            APPLY_RESULT="the client-certificate CA $caid fails the bundle checks (CA:TRUE, self-signed, valid, fingerprint)"; error "$APPLY_RESULT"; rm -rf "$rel_dir"; return 1
        fi
    done
    ok "nginx -t, the Lua syntax check and the CA bundle checks pass"

    # 5.–7. Journal, switch, reload.
    printf 'rel=%s\nprevious=%s\nstate=switching\nstarted=%s\nuser=%s\n' "$rel" "$prev" "$started" "${SUDO_USER:-root}" >"$JOURNAL"
    trap '' HUP INT
    local errlog_size
    errlog_size=$(stat -c %s /var/log/nginx/error.log 2>/dev/null || echo 0)
    switch_current "$rel"
    apply_signin "$rel_dir"
    if ! reload_nginx; then
        rollback_to "$prev" "$rel" "nginx did not reload"
        trap - HUP INT
        record_apply "$rev_id" "$rel" "$manifest_sha" rolled_back "nginx did not reload" "$started"
        APPLY_RESULT="nginx did not reload"; return 2
    fi

    # 8. Verify.
    if ! verify_release "$rel" "$errlog_size"; then
        local why=$VERIFY_ERROR
        rollback_to "$prev" "$rel" "$why"
        trap - HUP INT
        record_apply "$rev_id" "$rel" "$manifest_sha" rolled_back "$why" "$started"
        APPLY_RESULT="$why"; return 2
    fi
    trap - HUP INT
    verify_signin "$rel_dir"

    # 10. Record.
    sed -i 's/^state=.*/state=done/' "$JOURNAL"
    local result=applied
    [[ ${#WARNINGS[@]} -gt 0 ]] && result=warnings
    record_apply "$rev_id" "$rel" "$manifest_sha" "$result" "" "$started"
    jq -r '.webports | map(tostring) | join("\n")' "$NGX/current/summary.json" >"$ETC/webports" 2>/dev/null
    run_quiet "publish state" as_pspm php "$app/bin/state.php" || true
    run_quiet "agent sync" php "$LIBDIR/pspm-agent.php" sync || true
    prune_releases
    APPLY_RESULT="revision $rev_id is live as $rel"
    ok "Revision $rev_id is live"
    return 0
}

# Sign-in containers (plan §12.2): configs from the release, secrets root-only, one Redis.
# Problems here are warnings, never a rollback: sites that require sign-in fail closed.
apply_signin() {
    local rel_dir=$1 dir=$ETC/oauth2-proxy sum n i id slug env pw changed=()
    sum=$rel_dir/summary.json
    n=$(jq '.providers | length' "$sum" 2>/dev/null || echo 0)
    if [[ $n == 0 ]]; then
        if [[ -f $dir/compose.yml ]]; then
            run "sign-in containers down" compose -p pspm-signin -f "$dir/compose.yml" down --remove-orphans || warn "Could not stop the sign-in containers."
            rm -f "$dir/compose.yml"
        fi
        return 0
    fi
    install -d -m 0755 "$dir" "$VAR/redis"
    if [[ ! -f $dir/redis.env ]]; then (umask 077; printf 'REDISCLI_AUTH=%s\n' "$(openssl rand -hex 24)" >"$dir/redis.env"); fi
    pw=$(sed -n 's/^REDISCLI_AUTH=//p' "$dir/redis.env")
    if write_if_changed "$dir/redis.conf" 0400 "# PSPM: Redis for the sign-in sessions (written by install.sh)
bind 127.0.0.1 -::1
port 6379
protected-mode yes
requirepass $pw
dir /data"; then changed+=(redis); fi
    chown 999:999 "$dir/redis.conf"
    for ((i = 0; i < n; i++)); do
        id=$(jq -r ".providers[$i].id" "$sum"); slug=$(jq -r ".providers[$i].slug" "$sum")
        install -d -m 0755 "$dir/$slug"
        if ! cmp -s "$rel_dir/oauth2-proxy/$slug.cfg" "$dir/$slug/oauth2-proxy.cfg"; then
            install -m 0644 "$rel_dir/oauth2-proxy/$slug.cfg" "$dir/$slug/oauth2-proxy.cfg"; changed+=("oauth-$slug")
        fi
        if ! capture env "sign-in secrets $slug" as_pspm php "$(app_dir)/bin/signin.php" env "$id"; then
            warn "Cannot read the secrets of sign-in provider $slug; it is not started."; continue
        fi
        if [[ "$(cat "$dir/$slug.env" 2>/dev/null)" != "$env"$'\n'"OAUTH2_PROXY_REDIS_PASSWORD=$pw" ]]; then
            (umask 077; printf '%s\nOAUTH2_PROXY_REDIS_PASSWORD=%s\n' "$env" "$pw" >"$dir/$slug.env"); changed+=("oauth-$slug")
        fi
    done
    install -m 0644 "$rel_dir/oauth2-proxy/compose.yml" "$dir/compose.yml"
    run "sign-in images" compose -p pspm-signin -f "$dir/compose.yml" pull --quiet || warn "Could not pull the sign-in images."
    run "sign-in containers" compose -p pspm-signin -f "$dir/compose.yml" up -d --remove-orphans || warn "Could not start the sign-in containers (see log)."
    local c
    for c in $(printf '%s\n' "${changed[@]}" | sort -u); do
        run "recreate $c" compose -p pspm-signin -f "$dir/compose.yml" up -d --force-recreate --no-deps "$c" || warn "Could not restart $c."
    done
    # configuration directories of removed providers
    local d
    for d in "$dir"/p*/; do
        [[ -d $d ]] || continue
        slug=$(basename "$d")
        jq -e --arg s "$slug" '.providers[] | select(.slug == $s)' "$sum" >/dev/null || rm -rf "$d" "$dir/$slug.env"
    done
}

verify_signin() {
    local sum=$1/summary.json n i port host tenant ok loc
    n=$(jq '.providers | length' "$sum" 2>/dev/null || echo 0)
    for ((i = 0; i < n; i++)); do
        port=$(jq -r ".providers[$i].port" "$sum"); host=$(jq -r ".providers[$i].signin_host" "$sum"); tenant=$(jq -r ".providers[$i].tenant_id" "$sum")
        ok=0
        for _ in $(seq 1 30); do
            [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$port/ready")" == 200 ]] && { ok=1; break; }
            sleep 1
        done
        if [[ $ok != 1 ]]; then warn "Sign-in $host: oauth2-proxy does not answer /ready (is login.microsoftonline.com reachable? docker logs pspm-oauth-$(jq -r ".providers[$i].slug" "$sum"))."; continue; fi
        loc=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 5 -H "Host: $host" -H 'X-Forwarded-Proto: https' -H "X-Forwarded-Host: $host" \
            "http://127.0.0.1:$port/oauth2/start?rd=https%3A%2F%2F$host%2F")
        if [[ $loc == "https://login.microsoftonline.com/$tenant/"* ]]; then ok "Sign-in $host redirects to Microsoft"
        else warn "Sign-in $host: /oauth2/start does not redirect to Microsoft (got: ${loc:-nothing})."; fi
    done
    return 0
}

# Collect what the renderer needs and the database cannot know (plan §6.3 step 1).
collect_facts() {
    local rel=$1 rev_json=$2 certs='[]' f d name end sans resolved='{}' h mods='[]' m addrs ssh_ports
    for f in /etc/letsencrypt/live/*/cert.pem; do
        [[ -f $f ]] || continue
        d=$(dirname "$f"); name=$(basename "$d")
        end=$(date -u -d "$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)" +%FT%TZ 2>/dev/null) || continue
        sans=$(openssl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr ',' '\n' | sed -n 's/^ *DNS://p' | jq -R . | jq -s .)
        certs=$(jq --arg n "$name" --arg fc "$d/fullchain.pem" --arg k "$d/privkey.pem" --arg na "$end" --argjson s "$sans" \
            '. + [{name: $n, fullchain: $fc, key: $k, sans: $s, not_after: $na}]' <<<"$certs")
    done
    for h in $(jq -r '.document.backends[]?.servers[]?.addr' <<<"$rev_json" | sed -E 's/:[0-9]+$//' | grep -v -E '^\[|^[0-9.]+$' | sort -u); do
        if getent ahosts "$h" >/dev/null; then resolved=$(jq --arg h "$h" '.[$h] = true' <<<"$resolved")
        else resolved=$(jq --arg h "$h" '.[$h] = false' <<<"$resolved"); warn "Backend host $h does not resolve."; fi
    done
    for m in $(cat /etc/nginx/modules-enabled/*.conf 2>/dev/null | sed -n -E 's/^[[:space:]]*load_module[[:space:]]+([^;]+);.*/\1/p'); do
        [[ $m == /* ]] || m=/usr/share/nginx/$m
        [[ -f $m ]] && mods=$(jq --arg m "$m" '. + [$m]' <<<"$mods")
    done
    addrs=$(box_addresses | jq -R . | jq -s .)
    ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | jq -R 'tonumber' | jq -s . 2>/dev/null || echo '[22]')
    jq -n --arg rel "$rel" --arg now "$(date -u +%FT%TZ)" --argjson certs "$certs" --argjson resolved "$resolved" \
        --argjson mods "$mods" --argjson addrs "$addrs" --argjson ssh "${ssh_ports:-[22]}" --argjson v6 "$(ipv6_available && echo true || echo false)" \
        --arg nginx "$(nginx -v 2>&1 | cut -d/ -f2)" --arg sock "$FPM_SOCK" \
        '{release: $rel, now: $now, certs: $certs, resolved: $resolved, modules: $mods, addresses: $addrs, ssh_ports: $ssh,
          ipv6: $v6, ca_bundle: false, nginx_version: $nginx,
          paths: {app_public: "/srv/pspm/app/current/public", app_assets: "/srv/pspm/app/current/assets", php_socket: $sock,
                  acme_root: "/var/www/acme", state_dir: "/var/lib/pspm/state", ip_cert: "/etc/pspm/tls/ip.crt", ip_key: "/etc/pspm/tls/ip.key"}}'
}

review_changes() {
    local prev=$1 rel_dir=$2 diff_out=$3 app lines
    app=$(app_dir)
    printf '\n'
    local old_doc=/dev/null
    [[ -n $prev && -f $NGX/releases/$prev/revision.json ]] && old_doc=$NGX/releases/$prev/revision.json
    runuser -u pspm-render -- php "$app/bin/review.php" "$old_doc" "$rel_dir/revision.json" 2>>"$LOG_FILE" \
        | tee -a "$LOG_FILE" | sed -e "s/^OPENS/  ${C_RED}OPENS/" -e "s/\$/${C_OFF}/" -e 's/^\([^ ]\)/  \1/'
    log_raw "----- diff -ru live new"
    log_raw "$diff_out"
    lines=$(wc -l <<<"$diff_out")
    if [[ ${SHOW_DIFF:-1} == 1 && -n $diff_out ]]; then
        printf '\n  %snginx files (%s diff lines; all of them are in the log):%s\n' "$C_DIM" "$lines" "$C_OFF"
        head -n 200 <<<"$diff_out" | sed -e "s/^+.*/${C_GRN}&${C_OFF}/" -e "s/^-.*/${C_RED}&${C_OFF}/" -e 's/^/    /'
        (( lines > 200 )) && printf '    … %s more lines in the log\n' "$((lines - 200))"
    fi
    printf '\n'
}

switch_current() {
    ln -sfn "releases/$1" "$NGX/current.new"
    mv -T "$NGX/current.new" "$NGX/current"
    _log SWITCH "current -> releases/$1"
}

# Reload, or restart when nginx does not run PSPM's configuration yet (first apply, or
# someone changed the unit): a reload would re-read the old file.
reload_nginx() {
    install_nginx_dropin
    if nginx_runs_pspm && [[ ${DROPIN_CHANGED:-0} != 1 ]]; then
        run "reload nginx" systemctl reload nginx
    else
        info "nginx does not run PSPM's configuration yet: restarting it once."
        run "restart nginx" systemctl restart nginx
    fi
}

# Verify a live release (≤ 30 s). Sets VERIFY_ERROR on failure.
verify_release() {
    local rel=$1 errlog_from=${2:-} i got="" host cert want have sum
    VERIFY_ERROR=""
    if ! systemctl is-active -q nginx; then VERIFY_ERROR="nginx is not running"; error "$VERIFY_ERROR"; return 1; fi
    for i in $(seq 1 30); do
        got=$(curl -s --max-time 2 http://127.0.0.1:9080/pspm-release || true)
        [[ $got == "$rel" ]] && break
        sleep 1
    done
    if [[ $got != "$rel" ]]; then VERIFY_ERROR="nginx answers release '${got:-nothing}' instead of $rel"; error "$VERIFY_ERROR"; return 1; fi
    if [[ -n $errlog_from && -f /var/log/nginx/error.log ]]; then
        local new
        new=$(tail -c +$((errlog_from + 1)) /var/log/nginx/error.log | grep -E '\[(emerg|alert|crit)\]|lua (entry thread aborted|runtime error)|failed to load' || true)
        if [[ -n $new ]]; then log_raw "$new"; VERIFY_ERROR="nginx logged errors after the reload: $(head -n1 <<<"$new" | cut -c1-200)"; error "$VERIFY_ERROR"; return 1; fi
    fi
    sum=$NGX/releases/$rel/summary.json
    while IFS=$'\t' read -r host cert; do
        [[ -n $host && -n $cert && $cert != null ]] || continue
        want=$(openssl x509 -in "/etc/letsencrypt/live/$cert/cert.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
        have=$(openssl s_client -connect 127.0.0.1:443 -servername "$host" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
        if [[ -z $have || $have != "$want" ]]; then VERIFY_ERROR="TLS for $host does not present certificate $cert"; error "$VERIFY_ERROR"; return 1; fi
    done < <(jq -r '(.sites[] | [.host, (.cert // "")] | @tsv), (if .admin.in_effect then [.admin.host, "pspm-admin"] | @tsv else empty end)' "$sum" 2>/dev/null)
    local code
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 https://127.0.0.1:9443/login || true)
    if [[ $code != 200 && $code != 503 ]]; then VERIFY_ERROR="the UI on 127.0.0.1:9443 answers HTTP $code"; error "$VERIFY_ERROR"; return 1; fi
    [[ $code == 503 ]] && warn "The UI answers 'maintenance' (database or schema); nginx itself is fine."
    ok "Verified: nginx serves $rel, TLS names present their certificates, the UI answers"
    return 0
}

rollback_to() {
    local prev=$1 failed=$2 why=$3
    error "Rolling back: $why"
    if [[ -n $prev && -d $NGX/releases/$prev ]]; then
        switch_current "$prev"
        apply_signin "$NGX/releases/$prev"
        reload_nginx || run "restart nginx" systemctl restart nginx
        if verify_release "$prev"; then ok "Back on release $prev; nothing else changed."
        else error "The previous release $prev does not verify either. Check 'systemctl status nginx' and the log."; fi
    else
        info "There is no previous PSPM release: going back to Debian's nginx configuration."
        rm -f "$NGX/current" "$DROPIN"
        systemctl daemon-reload
        run "restart nginx (Debian config)" systemctl restart nginx || error "nginx does not start with Debian's configuration either."
    fi
    [[ -d $NGX/releases/$failed ]] && mv "$NGX/releases/$failed" "$NGX/releases/$failed.failed"
    sed -i 's/^state=.*/state=rolled_back/' "$JOURNAL" 2>/dev/null
}

record_apply() {
    local rev=$1 rel=$2 msha=$3 result=$4 msg=$5 started=$6
    jq -n --argjson rev "${rev:-0}" --arg rel "$rel" --arg m "$msha" --arg c "${CODE_COMMIT:-}" --arg u "${SUDO_USER:-root}" \
        --arg r "$result" --arg msg "$msg" --arg log "$LOG_FILE" --arg s "$started" \
        --arg ex "$(tail -n 60 "$LOG_FILE" 2>/dev/null)" \
        '{revision_id: $rev, release: $rel, manifest_sha: $m, code_commit: $c, ssh_user: $u, result: $r, message: $msg, log_file: $log, log_excerpt: $ex, started_at: $s}' \
        | as_pspm php "$(app_dir)/bin/revision.php" record-apply >>"$LOG_FILE" 2>&1 \
        || warn "Could not record the apply in the database (it is in this log)."
}

prune_releases() {
    local cur prevrel
    cur=$(basename "$(readlink -f "$NGX/current")")
    prevrel=$(sed -n 's/^previous=//p' "$JOURNAL" 2>/dev/null)
    find "$NGX/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' | sort -rn | awk '{print $2}' \
        | tail -n +$((KEEP_RELEASES + 1)) | while read -r d; do
            [[ $d == "$cur" || $d == "$prevrel" ]] || rm -rf "${NGX:?}/releases/$d"
        done
}

# install.sh rollback: back to the previous release, without the database if need be.
cmd_rollback() {
    local cur target
    cur=""
    [[ -L $NGX/current ]] && cur=$(basename "$(readlink -f "$NGX/current")")
    target=$(sed -n 's/^previous=//p' "$JOURNAL" 2>/dev/null)
    if [[ -z $target || ! -d $NGX/releases/$target || $target == "$cur" ]]; then
        target=$(find "$NGX/releases" -mindepth 1 -maxdepth 1 -type d ! -name '*.failed' ! -name "$cur" -printf '%T@ %f\n' | sort -rn | head -n1 | awk '{print $2}')
    fi
    [[ -n $target ]] || fail "There is no earlier release to roll back to." 1
    info "Live: $cur"
    info "Roll back to: $target (revision $(jq -r .id "$NGX/releases/$target/revision.json" 2>/dev/null))"
    local tdrift
    tdrift=$(cd "$NGX/releases/$target" && sha256sum --quiet -c MANIFEST.sha256 2>/dev/null || true)
    if [[ -n $tdrift ]]; then
        warn "Release $target was changed by hand after it was rendered:"
        sed 's/^/    /' <<<"$tdrift"
        confirm_word "Roll back to an edited release?" || { info "Nothing changed."; return 0; }
    fi
    confirm "Roll back?" || { info "Nothing changed."; return 0; }
    nginx_test "$NGX/releases/$target" >>"$LOG_FILE" 2>&1 || fail "nginx -t fails for $target; not switching." 1
    printf 'rel=%s\nprevious=%s\nstate=switching\nstarted=%s\nuser=%s\n' "$target" "$cur" "$(date -u +%FT%TZ)" "${SUDO_USER:-root}" >"$JOURNAL"
    switch_current "$target"
    reload_nginx || fail "nginx did not reload" 1
    if verify_release "$target"; then
        sed -i 's/^state=.*/state=done/' "$JOURNAL"
        record_apply "$(jq -r .id "$NGX/releases/$target/revision.json" 2>/dev/null || echo 0)" "$target" "" applied "rollback from $cur" "$(date -u +%FT%TZ)"
        ok "Release $target is live again."
    else
        error "$target does not verify: $VERIFY_ERROR"
        return 1
    fi
}
