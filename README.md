# PSPM

*Secure Proxy Manager* — Philipp's Secure Proxy Manager: a reverse-proxy appliance for one Debian 13 box. nginx terminates TLS for any number of sites and enforces per-site access rules (LAN, access links, client certificates); hostile addresses are blocked in nginx and in the kernel firewall. Everything is configured in the web UI; an admin applies it over SSH with `install.sh`, which tests every change and rolls back on its own.

The design is in [docs/pspm-plan.md](docs/pspm-plan.md).

## Install (from a fresh Debian 13)

1. Install Debian 13 (netinst): only **SSH server** and **standard system utilities**. Give the box a fixed address.
2. As root:
   ```bash
   apt-get update && apt-get install -y git
   install -d -m 700 /root/.ssh
   ssh-keygen -t ed25519 -N '' -C "pspm@$(hostname -f)" -f /root/.ssh/pspm_deploy
   cat >> /root/.ssh/config <<'CFG'
   Host github.com
       IdentityFile /root/.ssh/pspm_deploy
       IdentitiesOnly yes
   CFG
   cat /root/.ssh/pspm_deploy.pub
   ```
3. On GitHub: the repository's *Settings → Deploy keys → Add deploy key*; paste the key, **write access off**.
4. Clone and install:
   ```bash
   ssh -T git@github.com            # compare the fingerprint with GitHub's published ones
   git clone git@github.com:<owner>/pspm.git /opt/pspm
   /opt/pspm/install.sh
   ```
   The first run asks nothing. At the end it prints the URLs (by IP, from private addresses), the IP certificate's fingerprint and the password of the user `admin` (once). Sign in, choose a password, enrol an authenticator.

## Daily use

| | |
|---|---|
| Apply what is marked *Ready to apply* | `sudo /opt/pspm/install.sh` (or `… apply`) |
| Deploy new code | `sudo /opt/pspm/install.sh update` |
| Back to the previous configuration | `sudo /opt/pspm/install.sh rollback` |
| What is live, URLs | `sudo /opt/pspm/install.sh status` |
| Health checks | `sudo /opt/pspm/install.sh doctor` |
| Debug bundle (one text file, secrets redacted) | `sudo /opt/pspm/install.sh report` |
| Firewall kill switch | `sudo /opt/pspm/install.sh firewall off` / `on` |
| UI through SSH | `ssh -L 9443:127.0.0.1:9443 root@<box>`, then `https://localhost:9443/` |
| Recovery | `scripts/reset-password.sh`, `reset-otp.sh`, `create-admin.sh`, `unblock-ip.sh` |

Every `install.sh` run writes `/var/log/pspm/install-<time>.log` (`install-latest.log` points to the newest): the machine, every command with its output, exit code and duration, the phases and a summary.

## Status of the build

Built (plan phases P0–P3, in part):

- `install.sh`: all 14 phases, apply with review, `nginx -t`, atomic switch, verify and automatic rollback, drift detection, Let's Encrypt, `update`, `rollback`, `status`, `doctor`, `report`, `firewall on|off`
- PostgreSQL 18 in Docker (Unix socket only), migrations, pre-install dumps
- Web UI: dashboard, sites with routes, backends, access (single-site links, cleared addresses, bans, blocks), changes (preview diff, revisions, applies, live files, drift), settings, users, activity, help
- Sign-in with mandatory TOTP, sessions in the database, re-authentication, recovery scripts
- Lua gates (LAN, cleared, certificate, public; bans and blocks), snapshot files and sync
- Agent: firewall chain and sets on every port (allow, web-only allow, block), SSH login message, update check

Not built yet: client-certificate PKI (P3), Microsoft sign-in with oauth2-proxy and Redis (P4), security scan, AI verdicts, behaviour analysis, honeypots, external blocklists, e-mail notifications (P5), JSON export/import (P6).

## Development

```bash
docker build -t pspm-test:trixie tests/docker            # Debian 13 with nginx, Lua, PHP 8.4
docker run --rm -v "$PWD:/src:ro" pspm-test:trixie php /src/tests/unit/run.php
docker run --rm -v "$PWD:/src:ro" pspm-test:trixie bash /src/tests/nginx-check.sh
bash tests/run-smoke.sh                                   # UI flow against PostgreSQL 18
```
