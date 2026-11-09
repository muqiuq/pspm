# shellcheck shell=bash
# install.sh phases 1–11 and 13–14 (plan §6.2). Phase 12 (apply) is in apply.sh.

# ---------------------------------------------------------------- 1 preflight
phase_preflight() {
    phase 1 "Preflight"
    [[ $EUID -eq 0 ]] || fail "Run as root: sudo $PSPM_REPO/install.sh" 1
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ ${ID:-} != debian || ${VERSION_ID:-} != 13 ]]; then
            [[ ${FORCE_OS:-0} == 1 ]] || fail "This is ${PRETTY_NAME:-unknown}; PSPM supports Debian 13 only (override: --force-os)." 1
            warn "Running on ${PRETTY_NAME:-unknown}, not Debian 13 (--force-os)."
        fi
    fi
    [[ -d /run/systemd/system ]] || fail "systemd is not running; PSPM needs a normal Debian system with systemd." 1

    exec 9>"$LOCK_FILE"
    if ! flock -w 120 9; then fail "Another install.sh (or a certificate renewal) holds $LOCK_FILE." 1; fi
    export PSPM_INSTALL_LOCKED=1
    _log INFO "lock $LOCK_FILE acquired"

    local free_kb
    free_kb=$(df -Pk /var | awk 'NR==2 {print $4}')
    if (( free_kb < 2 * 1024 * 1024 )); then
        fail "Less than 2 GB free on /var ($((free_kb / 1024)) MB). Free some space first." 1
    fi

    if git -C "$PSPM_REPO" rev-parse --git-dir >/dev/null 2>&1; then
        CODE_COMMIT=$(git -C "$PSPM_REPO" rev-parse --short=12 HEAD)
        local dirty
        dirty=$(git -C "$PSPM_REPO" status --porcelain --untracked-files=no 2>/dev/null)
        if [[ -n $dirty ]]; then
            warn "The checkout in $PSPM_REPO has local changes (they will be deployed as they are):"
            log_raw "$dirty"
            CODE_COMMIT="$CODE_COMMIT-dirty"
        fi
    else
        CODE_COMMIT="nogit-$(find "$PSPM_REPO/app" "$PSPM_REPO/nginx" "$PSPM_REPO/lua" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-12)"
        note "$PSPM_REPO is not a git checkout; code id $CODE_COMMIT"
    fi
    SSH_CLIENT_ADDR=""
    [[ -n ${SSH_CONNECTION:-} ]] && SSH_CLIENT_ADDR=${SSH_CONNECTION%% *}
    FIRST_RUN=0
    [[ -f $ETC/installed ]] || FIRST_RUN=1
    if [[ -f $JOURNAL ]] && grep -q '^state=switching' "$JOURNAL"; then
        warn "The previous apply was interrupted; its result is checked first."
        INTERRUPTED=1
    fi
    ok "Debian 13, root, lock held, $((free_kb / 1024 / 1024)) GB free; code $CODE_COMMIT$([[ $FIRST_RUN == 1 ]] && echo '; first installation')"
    phase_end ok
}

# ---------------------------------------------------------------- 2 packages
phase_packages() {
    phase 2 "Packages"
    export DEBIAN_FRONTEND=noninteractive
    local apt_opts=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    if [[ $FIRST_RUN == 1 && ${SKIP_UPGRADE:-0} != 1 ]]; then
        info "First run: updating the base system once (nothing is live yet)…"
        run "apt-get update" apt-get update || fail "apt-get update failed. Check the network and /etc/apt/sources.list*." 1
        run "apt-get full-upgrade" apt-get "${apt_opts[@]}" full-upgrade || fail "The system upgrade failed." 1
        [[ -f /var/run/reboot-required ]] && warn "A reboot is recommended after this run (new kernel or libraries)."
    fi
    local missing=() p
    for p in "${PACKAGES[@]}"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
    done
    if ! timedatectl show -p NTP --value 2>/dev/null | grep -q yes && ! systemctl is-active -q chrony ntpsec openntpd 2>/dev/null; then
        dpkg-query -W -f='${Status}' systemd-timesyncd 2>/dev/null | grep -q 'install ok installed' || missing+=(systemd-timesyncd)
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing: ${missing[*]}"
        [[ $FIRST_RUN == 1 ]] || run "apt-get update" apt-get update || fail "apt-get update failed." 1
        run "apt-get install" apt-get "${apt_opts[@]}" --no-install-recommends install "${missing[@]}" \
            || fail "Installing packages failed. See the log for apt's message." 1
        ok "Installed ${#missing[@]} packages"
    else
        ok "All packages present (no upgrade: PSPM never runs apt upgrade on a live box)"
    fi
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "$PHP_VERSION")
    FPM_SERVICE=php$PHP_VERSION-fpm
    log_raw "versions: $(dpkg-query -W -f='${Package}=${Version} ' "${PACKAGES[@]}" 2>/dev/null)"
    phase_end ok
}

# ---------------------------------------------------------------- 3 system baseline
phase_baseline() {
    phase 3 "System baseline"
    local changed=0
    # Time: TOTP and certificates depend on it.
    if ! systemctl is-active -q chrony ntpsec openntpd 2>/dev/null; then
        run "enable time sync" timedatectl set-ntp true || warn "Could not enable time synchronisation (timedatectl set-ntp true)."
    fi
    # Kernel settings for a proxy.
    run_quiet "load nf_conntrack" modprobe nf_conntrack || true
    write_if_changed /etc/modules-load.d/pspm.conf 0644 "# PSPM: connection tracking for the firewall reply rule
nf_conntrack" || true
    if write_if_changed /etc/sysctl.d/90-pspm.conf 0644 "# PSPM reverse proxy tuning (written by install.sh)
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_syncookies = 1
net.netfilter.nf_conntrack_max = 262144"; then changed=1; fi
    run "apply sysctl" sysctl -p /etc/sysctl.d/90-pspm.conf || warn "Some kernel settings could not be applied (see log)."
    # Security updates from the Debian security archive only; set up once.
    if [[ ! -f /etc/apt/apt.conf.d/52pspm-unattended-upgrades ]]; then
        write_if_changed /etc/apt/apt.conf.d/20auto-upgrades 0644 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' || true
        write_if_changed /etc/apt/apt.conf.d/52pspm-unattended-upgrades 0644 '// PSPM: security updates only. Remove this file and 20auto-upgrades to turn them off.
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};' || true
        info "Automatic security updates set up (Debian security archive only)"
    fi
    # journald: cap its size.
    mkdir -p /etc/systemd/journald.conf.d
    if write_if_changed /etc/systemd/journald.conf.d/pspm.conf 0644 "[Journal]
SystemMaxUse=1G"; then run "restart journald" systemctl restart systemd-journald || true; fi
    if sshd -T 2>/dev/null | grep -qi '^passwordauthentication yes'; then
        note "sshd allows password logins; PSPM leaves sshd alone ('install.sh doctor' lists this)."
    fi
    ok "Time sync, kernel settings, security updates, journal size"
    phase_end ok
}

# ---------------------------------------------------------------- 4 users, dirs, secrets
phase_users_dirs() {
    phase 4 "Users, directories, secrets"
    getent group pspm >/dev/null || run "group pspm" groupadd --system pspm || fail "Cannot create group pspm" 1
    getent passwd pspm >/dev/null || run "user pspm" useradd --system --gid pspm --home-dir "$VAR" --no-create-home --shell /usr/sbin/nologin pspm || fail "Cannot create user pspm" 1
    getent passwd pspm-render >/dev/null || run "user pspm-render" useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin pspm-render || fail "Cannot create user pspm-render" 1

    install -d -m 0751 -o root -g pspm "$ETC"
    install -d -m 0755 -o root -g root "$NGX" "$NGX/releases" "$ETC/oauth2-proxy" "$LIBDIR" "$APP_ROOT" "$APP_ROOT/releases" "$ACME_ROOT" /srv/pspm
    install -d -m 0700 -o root -g root "$ETC/tls"
    install -d -m 0755 -o root -g root "$VAR"
    install -d -m 2750 -o pspm -g www-data "$STATE"
    install -d -m 0750 -o root -g pspm "$STATUS" "$BACKUPS"
    install -d -m 0750 -o pspm -g pspm "$VAR/tmp"
    install -d -m 0755 "$VAR/postgres"
    install -d -m 0755 /run/pspm /run/pspm/postgres
    [[ -f $ETC/never-block ]] || printf '# Addresses or networks that the firewall never blocks (one per line).\n# Private ranges are never blocked anyway.\n' >"$ETC/never-block"

    # Secrets: generated once, never overwritten.
    if [[ ! -f $ETC/db.env ]]; then
        (umask 027; printf 'POSTGRES_USER=pspm\nPOSTGRES_DB=pspm\nPOSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" >"$ETC/db.env")
        info "Generated the database password ($ETC/db.env)"
    fi
    if [[ ! -f $ETC/app.key ]]; then
        (umask 027; openssl rand -base64 32 >"$ETC/app.key")
        info "Generated the application key ($ETC/app.key)"
    fi
    chown root:pspm "$ETC/db.env" "$ETC/app.key"; chmod 0640 "$ETC/db.env" "$ETC/app.key"

    write_if_changed "$ETC/pspm.conf" 0644 "# Install-time facts, written by install.sh (not secret).
BOX_FQDN=$(hostname -f 2>/dev/null || hostname)
DB_SOCKET_DIR=/run/pspm/postgres
PHP_VERSION=$PHP_VERSION
REPO=$PSPM_REPO" || true

    # Self-signed certificate for access by IP and through the SSH tunnel (plan §8.2).
    local addrs want
    addrs=$( (box_addresses; echo 127.0.0.1) | sort -u | tr '\n' ' ')
    want="$addrs"
    if [[ ! -f $ETC/tls/ip.crt || "$(cat "$ETC/tls/ip.addrs" 2>/dev/null)" != "$want" ]]; then
        local san="DNS:localhost" a
        for a in $addrs; do san="$san,IP:$a"; done
        run "IP certificate" openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
            -subj "/CN=PSPM $(hostname -s)" -addext "subjectAltName=$san" -addext "basicConstraints=critical,CA:FALSE" \
            -addext "extendedKeyUsage=serverAuth" -keyout "$ETC/tls/ip.key.new" -out "$ETC/tls/ip.crt.new" \
            || fail "Cannot create the IP certificate" 1
        chmod 0600 "$ETC/tls/ip.key.new"; chmod 0644 "$ETC/tls/ip.crt.new"
        mv -f "$ETC/tls/ip.key.new" "$ETC/tls/ip.key"; mv -f "$ETC/tls/ip.crt.new" "$ETC/tls/ip.crt"
        printf '%s' "$want" >"$ETC/tls/ip.addrs"
        info "IP certificate for: $addrs"
        IP_CERT_CHANGED=1
    fi
    # the public certificate for the overview on the Certificates page ($ETC/tls is root-only: the key is there)
    install -m 0644 "$ETC/tls/ip.crt" "$STATUS/ip.crt"

    # Read access for the UI (plan §5.3): nginx logs, public certificate files.
    install -d -m 0755 /var/log/nginx
    touch /var/log/nginx/pspm-security.log
    chown www-data:adm /var/log/nginx/pspm-security.log 2>/dev/null; chmod 0640 /var/log/nginx/pspm-security.log
    run_quiet "acl nginx logs" setfacl -m u:pspm:rx -d -m u:pspm:r /var/log/nginx || warn "setfacl on /var/log/nginx failed"
    run_quiet "acl nginx log files" sh -c 'setfacl -m u:pspm:r /var/log/nginx/*.log' || true
    letsencrypt_acls
    ok "Users pspm and pspm-render, directories, secrets, IP certificate ($(ip_cert_fingerprint | cut -c1-23)…)"
    phase_end ok
}

# The UI may read public certificate files; private keys stay root-only (their mode 0600
# masks the ACL).
letsencrypt_acls() {
    local d
    for d in /etc/letsencrypt /etc/letsencrypt/live /etc/letsencrypt/archive; do
        [[ -d $d ]] && setfacl -m u:pspm:rx "$d" 2>/dev/null
    done
    for d in /etc/letsencrypt/live /etc/letsencrypt/archive; do
        [[ -d $d ]] && setfacl -d -m u:pspm:rx "$d" 2>/dev/null
        [[ -d $d ]] && find "$d" -mindepth 1 -maxdepth 1 -type d -exec setfacl -m u:pspm:rx {} + 2>/dev/null
    done
    return 0
}

# ---------------------------------------------------------------- 5 database
phase_database() {
    phase 5 "Database (PostgreSQL in Docker)"
    install -d -m 0755 /etc/docker
    local want='{"live-restore": true, "log-driver": "local"}' cur merged
    if [[ -f /etc/docker/daemon.json ]]; then
        cur=$(cat /etc/docker/daemon.json)
        merged=$(jq -S '. + {"live-restore": true, "log-driver": (."log-driver" // "local")}' /etc/docker/daemon.json 2>/dev/null) || merged=""
        [[ -z $merged ]] && { warn "/etc/docker/daemon.json is not valid JSON; leaving it alone"; merged=$cur; }
    else
        cur=""; merged=$(echo "$want" | jq -S .)
    fi
    if [[ "$(echo "$cur" | jq -S . 2>/dev/null)" != "$merged" ]]; then
        printf '%s\n' "$merged" >/etc/docker/daemon.json
        if docker ps -q 2>/dev/null | grep -q .; then run "reload docker" systemctl reload docker || true
        else run "restart docker" systemctl restart docker || fail "Docker does not start (journalctl -u docker)." 1; fi
    fi
    systemctl is-active -q docker || run "start docker" systemctl enable --now docker || fail "Docker does not start (journalctl -u docker)." 1
    compose version >/dev/null 2>&1 || fail "docker compose is not available." 1
    systemd-tmpfiles --create /etc/tmpfiles.d/pspm.conf >/dev/null 2>&1 || install -d -m 0755 /run/pspm/postgres

    run "compose up postgres" compose -p "$COMPOSE_PROJECT" -f "$PSPM_REPO/docker/compose.yml" up -d --quiet-pull --remove-orphans \
        || fail "Starting the PostgreSQL container failed (see log; 'docker logs pspm-postgres')." 1
    local i st=""
    for i in $(seq 1 60); do
        st=$(docker inspect -f '{{.State.Health.Status}}' pspm-postgres 2>/dev/null || echo missing)
        [[ $st == healthy && -S /run/pspm/postgres/.s.PGSQL.5432 ]] && break
        sleep 2
    done
    if [[ $st != healthy ]]; then
        run_quiet "postgres logs" docker logs --tail 80 pspm-postgres
        fail "PostgreSQL did not become healthy within 120 s (state: $st). Its log is in this run's log." 1
    fi
    ok "PostgreSQL healthy ($(docker inspect -f '{{.Config.Image}}' pspm-postgres 2>/dev/null)); socket /run/pspm/postgres"
    log_raw "postgres image digest: $(docker inspect -f '{{.Image}}' pspm-postgres 2>/dev/null)"
    phase_end ok
}

# ---------------------------------------------------------------- 6 backup
phase_backup() {
    phase 6 "Backup"
    local empty
    empty=$(PGPASSWORD=$(grep '^POSTGRES_PASSWORD=' "$ETC/db.env" | cut -d= -f2-) \
        docker exec -e PGPASSWORD pspm-postgres psql -U pspm -d pspm -tAc "SELECT to_regclass('public.schema_migrations') IS NULL" 2>/dev/null)
    if [[ $empty == t || -z $empty ]]; then
        note "The database is empty; nothing to back up."
        phase_end skip "empty database"
        return
    fi
    local dir
    dir=$BACKUPS/pre-install-$(date +%Y%m%d-%H%M%S)
    install -d -m 0750 -o root -g pspm "$dir"
    if PGPASSWORD=$(grep '^POSTGRES_PASSWORD=' "$ETC/db.env" | cut -d= -f2-) \
        docker exec -e PGPASSWORD pspm-postgres pg_dump -U pspm -d pspm -Fc >"$dir/db.dump" 2>"$dir/pg_dump.err"; then
        chmod 0640 "$dir/db.dump"; chgrp pspm "$dir/db.dump"
        rm -f "$dir/pg_dump.err"
        ok "Database dump: $dir/db.dump ($(du -h "$dir/db.dump" | cut -f1))"
        if as_pspm php "$PSPM_REPO/app/bin/export.php" --backup >"$dir/export.json" 2>>"$LOG_FILE"; then
            chmod 0640 "$dir/export.json"; chgrp pspm "$dir/export.json"; ok "JSON export: $dir/export.json"
        else
            rm -f "$dir/export.json"; note "No JSON export (set a backup passphrase in Settings to get one)."
        fi
    else
        log_raw "$(cat "$dir/pg_dump.err")"
        fail "pg_dump failed; no migration without a backup." 1
    fi
    # keep the newest $KEEP_BACKUPS pre-install backups
    find "$BACKUPS" -maxdepth 1 -type d -name 'pre-install-*' | sort -r | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -rf
    phase_end ok
}

# ---------------------------------------------------------------- 7 migrations
phase_migrations() {
    phase 7 "Database migrations"
    run "migrate" as_pspm php "$PSPM_REPO/app/bin/migrate.php" "$PSPM_REPO/db/migrations" \
        || fail "A migration failed. The database is unchanged by it (transactions). See the log." 1
    ok "Schema up to date"
    phase_end ok
}

# ---------------------------------------------------------------- 8 app release
phase_app_release() {
    phase 8 "App release"
    local id rel tmp prev
    id=$CODE_COMMIT
    [[ $id == *-dirty ]] && id="$id-$(date +%Y%m%d%H%M%S)"
    rel=$APP_ROOT/releases/$id
    prev=$(readlink -f "$APP_ROOT/current" 2>/dev/null || true)
    if [[ -d $rel && $prev == "$rel" ]]; then
        ok "App release $id is already live"
    else
        if [[ ! -d $rel ]]; then
            tmp=$rel.tmp.$$
            rm -rf "$tmp"
            cp -a "$PSPM_REPO/app/." "$tmp/" || fail "Copying the app failed" 1
            printf '%s\n' "$CODE_COMMIT" >"$tmp/COMMIT"
            chown -R root:root "$tmp"; chmod -R go-w "$tmp"
            local bad
            bad=$(find "$tmp" -name '*.php' -print0 | xargs -0 -n1 php -l 2>&1 | grep -v '^No syntax errors' || true)
            [[ -n $bad ]] && { log_raw "$bad"; rm -rf "$tmp"; fail "PHP syntax errors in the new release (see log)." 1; }
            mv "$tmp" "$rel"
        fi
        run "selftest" as_pspm php "$rel/bin/selftest.php" || fail "The selftest of the new app release failed; the live release is unchanged." 1
        write_fpm_pool
        ln -sfn "$rel" "$APP_ROOT/current.new" && mv -T "$APP_ROOT/current.new" "$APP_ROOT/current"
        run "reload php-fpm" systemctl reload-or-restart "$FPM_SERVICE" || {
            [[ -n $prev ]] && ln -sfn "$prev" "$APP_ROOT/current.new" && mv -T "$APP_ROOT/current.new" "$APP_ROOT/current"
            fail "php-fpm did not reload; switched back to the previous app release." 1; }
        if nginx_runs_pspm; then
            local i code=""
            for i in 1 2 3 4 5; do
                code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:9080/healthz || true)
                [[ $code == 200 ]] && break; sleep 1
            done
            if [[ $code != 200 ]]; then
                if [[ -n $prev && $prev != "$rel" ]]; then
                    ln -sfn "$prev" "$APP_ROOT/current.new" && mv -T "$APP_ROOT/current.new" "$APP_ROOT/current"
                    systemctl reload "$FPM_SERVICE"
                fi
                fail "The new app release does not answer /healthz (HTTP $code); switched back." 1
            fi
        fi
        ok "App release $id is live"
    fi
    # keep the newest releases, never the live one
    local live
    live=$(readlink -f "$APP_ROOT/current")
    find "$APP_ROOT/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn | awk '{print $2}' \
        | tail -n +$((KEEP_APP_RELEASES + 1)) | while read -r d; do [[ $d != "$live" ]] && rm -rf "$d"; done
    phase_end ok
}

write_fpm_pool() {
    local pool=/etc/php/$PHP_VERSION/fpm/pool.d/pspm.conf
    if write_if_changed "$pool" 0644 "; PSPM web UI pool (written by install.sh)
[pspm]
user = pspm
group = pspm
listen = $FPM_SOCK
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 16
pm.process_idle_timeout = 60s
pm.max_requests = 500
request_terminate_timeout = 300
catch_workers_output = yes
decorate_workers_output = no
clear_env = yes
env[PATH] = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_flag[expose_php] = off
php_admin_value[memory_limit] = 256M
php_admin_value[post_max_size] = 64M
php_admin_value[upload_max_filesize] = 64M
php_admin_value[upload_tmp_dir] = $VAR/tmp
php_admin_value[sys_temp_dir] = $VAR/tmp
php_admin_value[session.save_path] = $VAR/tmp
php_admin_value[max_execution_time] = 300"; then
        run "php-fpm config test" "php-fpm$PHP_VERSION" -t || fail "php-fpm rejects the pool configuration (see log)." 1
    fi
}

# ---------------------------------------------------------------- 9 system units
phase_units() {
    phase 9 "System units"
    local f changed=0
    install -m 0755 "$PSPM_REPO/agent/pspm-agent.php" "$LIBDIR/pspm-agent.php"
    install -m 0755 "$PSPM_REPO/motd/50-pspm" /etc/update-motd.d/50-pspm
    install -m 0644 "$PSPM_REPO/systemd/tmpfiles.d/pspm.conf" /etc/tmpfiles.d/pspm.conf
    for f in "$PSPM_REPO"/systemd/*.service "$PSPM_REPO"/systemd/*.timer "$PSPM_REPO"/systemd/*.path; do
        [[ -f $f ]] || continue
        if ! cmp -s "$f" "/etc/systemd/system/$(basename "$f")"; then
            install -m 0644 "$f" "/etc/systemd/system/$(basename "$f")"; changed=1
            _log FILE "installed unit $(basename "$f")"
        fi
    done
    # The nginx drop-in only once a release exists; the first apply installs it (apply.sh).
    [[ -e $NGX/current ]] && install_nginx_dropin
    install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
    install -m 0755 "$PSPM_REPO/systemd/certbot-deploy-hook" /etc/letsencrypt/renewal-hooks/deploy/50-pspm
    run "daemon-reload" systemctl daemon-reload
    run "enable units" systemctl enable --now pspm-agent.path pspm-agent.timer pspm-secscan.timer pspm-blocklists.timer pspm-notify.timer pspm-backup.timer \
        || warn "Could not enable the PSPM timers"
    systemctl enable -q pspm-firewall.service 2>/dev/null || warn "Could not enable pspm-firewall.service"
    systemctl enable -q --now certbot.timer 2>/dev/null || warn "certbot.timer is not active"
    ok "Agent, firewall service, MOTD, certbot hook, tmpfiles$([[ $changed == 1 ]] && echo ' (units updated)')"
    phase_end ok
}

install_nginx_dropin() {
    install -d -m 0755 "$(dirname "$DROPIN")"
    if write_if_changed "$DROPIN" 0644 "# PSPM: nginx runs the configuration in $NGX/current (written by install.sh).
# Debian's /etc/nginx/nginx.conf is not used. Remove this file to go back to it.
[Service]
ExecStartPre=
ExecStartPre=/usr/sbin/nginx -t -q -p $NGX/current/ -c nginx.conf -g 'daemon on; master_process on;'
ExecStart=
ExecStart=/usr/sbin/nginx -p $NGX/current/ -c nginx.conf -g 'daemon on; master_process on;'
ExecReload=
ExecReload=/usr/sbin/nginx -p $NGX/current/ -c nginx.conf -g 'daemon on; master_process on;' -s reload
LimitNOFILE=65535"; then
        systemctl daemon-reload
        DROPIN_CHANGED=1
    fi
}

# ---------------------------------------------------------------- 10 firewall
phase_firewall() {
    phase 10 "Firewall"
    if [[ $FIRST_RUN == 1 && -n ${SSH_CLIENT_ADDR:-} ]] && ! is_private_addr "$SSH_CLIENT_ADDR"; then
        if ! grep -qxF "$SSH_CLIENT_ADDR" "$ETC/never-block"; then
            printf '%s   # SSH client of the first install.sh run (%s)\n' "$SSH_CLIENT_ADDR" "$(date +%F)" >>"$ETC/never-block"
            info "Your SSH address $SSH_CLIENT_ADDR was added to $ETC/never-block (remove it there if not wanted)."
        fi
    fi
    if ! iptables --version 2>/dev/null | grep -q nf_tables; then
        warn "iptables does not use the nf_tables backend ($(iptables --version 2>/dev/null)); Docker and PSPM must use the same one."
    fi
    if ! run "firewall setup" php "$LIBDIR/pspm-agent.php" setup; then
        warn "The firewall layer could not be set up (see log). nginx still blocks."
        phase_end warn "firewall not active"
    elif ! agent_sync "firewall sync"; then
        # the chain and jump are in place; name what is missing instead of "not active"
        phase_end warn "$(jq -r '[.sets // {} | to_entries[] | select(.value == -1) | .key]
            | if length > 0 then "active; not loaded: " + join(", ") else "active, with errors" end' "$STATUS/firewall.json" 2>/dev/null || echo "see log")"
    else
        ok "Chain PSPM-INPUT and its sets are in place; $(jq -r '[.sets[]? | select(. > 0)] | add // 0' "$STATUS/firewall.json" 2>/dev/null) entries loaded"
        phase_end ok
    fi
}

# ---------------------------------------------------------------- 11 bootstrap
phase_bootstrap() {
    phase 11 "Bootstrap"
    local out
    if capture out "bootstrap admin" as_pspm php "$(app_dir)/bin/user.php" bootstrap; then
        if [[ $out == PASSWORD=* ]]; then
            ADMIN_PASSWORD=${out#PASSWORD=}
            ok "User 'admin' created"
            show_secret "Password for user admin (change it at the first sign-in)" "$ADMIN_PASSWORD"
        else
            ok "Users exist"
        fi
    else
        fail "Creating the first user failed (see log)." 1
    fi
    run "publish state" as_pspm php "$(app_dir)/bin/state.php" || warn "Could not publish the snapshot files yet."
    touch "$ETC/installed"
    phase_end ok
}

# ---------------------------------------------------------------- 11b import (install.sh --import)
phase_import() {
    phase 11 "Import $(basename "$IMPORT_FILE")"
    local work pass out ok
    work=$(mktemp -d /run/pspm/import.XXXXXX); chmod 0755 "$work"
    cp "$IMPORT_FILE" "$work/import.json"; chmod 0644 "$work/import.json"
    [[ -t 0 ]] || fail "The import asks for the export passphrase; run it in a terminal." 1
    printf '  Export passphrase: '; read -r -s pass; printf '\n'
    _log INFO "import of $IMPORT_FILE (passphrase entered, not logged)"
    imp() { runuser -u pspm -- env PSPM_IMPORT_PASSPHRASE="$pass" PSPM_IMPORTER="" PSPM_ACTOR="root (${SUDO_USER:-root} via install.sh --import)" php "$(app_dir)/bin/import.php" "$@"; }
    if ! capture out "import preview" imp preview "$work/import.json"; then rm -rf "$work"; fail "The file cannot be imported (wrong passphrase, changed file or a newer format; see log)." 1; fi
    log_raw "$out"
    jq -r '"  exported: \(.exported_at)\n  users: \(.users | join(", "))\n  sites: \(.counts["sites.sites"]), backends: \(.counts["backends.backends"]), CAs: \(.counts["pki.cas"]), sign-in providers: \(.counts["signin.providers"])\n  Let'"'"'s Encrypt material: \(.tls)"' <<<"$out"
    jq -r '.conflicts[]? | "  conflict: " + .' <<<"$out"
    if [[ ${ASSUME_YES:-0} != 1 ]]; then printf '  This replaces everything on this box. Type IMPORT to continue: '; read -r ok; [[ $ok == IMPORT ]] || { rm -rf "$work"; fail "Import cancelled." 3; }; fi
    run "import" imp apply "$work/import.json" || { rm -rf "$work"; fail "The import failed; the database is unchanged (one transaction)." 1; }
    local tls le
    tls=$(imp tls "$work/import.json" 2>/dev/null || echo null)
    le=$(jq -r '.letsencrypt // ""' <<<"$tls" 2>/dev/null)
    if [[ -n $le ]]; then
        [[ -d /etc/letsencrypt ]] && cp -a /etc/letsencrypt "/etc/letsencrypt.pre-import-$(date +%Y%m%d-%H%M%S)"
        mkdir -p /etc/letsencrypt
        if base64 -d <<<"$le" | tar -C /etc/letsencrypt -xzf -; then ok "Let's Encrypt material restored"; letsencrypt_acls; else warn "The Let's Encrypt material could not be unpacked."; fi
        jq -r '.never_block // empty' <<<"$tls" >"$ETC/never-block.new" && [[ -s $ETC/never-block.new ]] && mv "$ETC/never-block.new" "$ETC/never-block"
        rm -f "$ETC/never-block.new"
    fi
    rm -rf "$work"
    run "commit imported configuration" as_pspm php "$(app_dir)/bin/revision.php" commit-working "imported from $(basename "$IMPORT_FILE")" \
        || warn "The imported configuration is not valid as it is; fix it on Changes."
    ADMIN_PASSWORD=""   # the users come from the file
    ASSUME_YES=1
    ok "Imported; the configuration is applied next"
    phase_end ok
}

# ---------------------------------------------------------------- 13 certificates
phase_certificates() {
    phase 13 "Certificates"
    local sum=$NGX/current/summary.json
    if [[ ! -f $sum ]]; then phase_end skip "no release"; return; fi
    local n issued=0 failed=0
    n=$(jq '.pending_certs | length' "$sum")
    if [[ $n == 0 ]]; then ok "Every site has its certificate"; phase_end ok; return; fi
    local email
    email=$(jq -r '.acme_email // ""' "$sum")
    local email_args=(--register-unsafely-without-email)
    [[ -n $email ]] && email_args=(--email "$email" --no-eff-email)
    local fails_file=$STATUS/cert-failures.json
    [[ -f $fails_file ]] || echo '{}' >"$fails_file"
    local i name hosts h dargs token ok_dns
    for ((i = 0; i < n; i++)); do
        name=$(jq -r ".pending_certs[$i].name" "$sum")
        hosts=$(jq -r ".pending_certs[$i].hosts[]" "$sum")
        local last
        last=$(jq -r --arg n "$name" '.[$n] // 0' "$fails_file")
        if [[ ${RETRY_CERTS:-0} != 1 ]] && (( $(date +%s) - last < 3600 )); then
            note "$name: failed less than an hour ago; skipped (Let's Encrypt rate limits). Retry: --retry-certs"
            continue
        fi
        dargs=(); ok_dns=1
        for h in $hosts; do
            if ! getent ahosts "$h" >/dev/null; then warn "$h does not resolve in DNS; its certificate waits."; ok_dns=0; fi
            dargs+=(-d "$h")
        done
        [[ $ok_dns == 1 ]] || continue
        # Self-check: does nginx serve the challenge path for every name?
        token=pspm-check-$(openssl rand -hex 8)
        install -d -m 0755 "$ACME_ROOT/.well-known/acme-challenge"
        printf '%s' "$token" >"$ACME_ROOT/.well-known/acme-challenge/$token"
        local selfok=1
        for h in $hosts; do
            if [[ "$(curl -s --max-time 5 --resolve "$h:80:127.0.0.1" "http://$h/.well-known/acme-challenge/$token")" != "$token" ]]; then
                warn "$h: nginx does not serve the ACME challenge path locally; its certificate waits."; selfok=0
            fi
        done
        rm -f "$ACME_ROOT/.well-known/acme-challenge/$token"
        [[ $selfok == 1 ]] || continue
        info "Requesting a certificate for $(echo "$hosts" | tr '\n' ' ')…"
        if run "certbot $name" certbot certonly --webroot -w "$ACME_ROOT" --cert-name "$name" "${dargs[@]}" \
            --non-interactive --agree-tos "${email_args[@]}" --keep-until-expiring --expand; then
            issued=$((issued + 1))
            jq --arg n "$name" 'del(.[$n])' "$fails_file" >"$fails_file.tmp" && mv "$fails_file.tmp" "$fails_file"
            ok "Certificate $name issued"
        else
            failed=$((failed + 1))
            jq --arg n "$name" --argjson t "$(date +%s)" '.[$n] = $t' "$fails_file" >"$fails_file.tmp" && mv "$fails_file.tmp" "$fails_file"
            warn "Let's Encrypt refused $name (see log for certbot's message). The site stays pending."
        fi
    done
    letsencrypt_acls
    local live=""
    if (( issued > 0 )); then
        info "New certificates: applying again so nginx uses them…"
        CERT_REAPPLY=1 ASSUME_YES=1 apply_configuration "${APPLY_REVISION:-}" || { phase_end fail "re-apply failed"; return 1; }
        live="; ${APPLY_RESULT:-applied again}"   # the summary row of phase 12 names the release before this one
    fi
    phase_end "$([[ $failed == 0 ]] && echo ok || echo warn)" "$issued issued, $failed failed$live"
}

# ---------------------------------------------------------------- 14 report
phase_report() {
    phase 14 "Report"
    local sum=$NGX/current/summary.json fp a
    fp=$(ip_cert_fingerprint)
    printf '\n'
    if [[ -f $sum && "$(jq -r '.admin.in_effect' "$sum")" == true ]]; then
        info "UI:      https://$(jq -r '.admin.host' "$sum")/"
    else
        for a in $(box_addresses); do
            is_private_addr "$a" || continue
            [[ $a == *:* ]] && info "UI:      https://[$a]/" || info "UI:      https://$a/"
        done
        [[ -f $sum && "$(jq -r '.admin.pending' "$sum")" == true ]] && note "The admin host name $(jq -r '.admin.host' "$sum") takes over once its certificate exists."
    fi
    info "Tunnel:  ssh -L 9443:127.0.0.1:9443 ${SUDO_USER:-root}@$(hostname -f 2>/dev/null || hostname)   then https://localhost:9443/"
    info "IP certificate SHA-256: $fp"
    agent_sync "agent refresh" || true
    phase_end ok
}
