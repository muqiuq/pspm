# Recovery

All of these run on the server as root and need only the database.

| Problem | Command |
|---|---|
| Forgotten password | `sudo /opt/pspm/scripts/reset-password.sh <user>` (or `--generate`) |
| Lost authenticator | `sudo /opt/pspm/scripts/reset-otp.sh <user>` |
| No admin can sign in | `sudo /opt/pspm/scripts/create-admin.sh <user>` |
| Your address is banned or blocked | `sudo /opt/pspm/scripts/unblock-ip.sh <address>` |
| The admin host name is broken | use the SSH tunnel: `ssh -L 9443:127.0.0.1:9443 root@<box>`, then `https://localhost:9443/` |
| A bad configuration is live | `sudo /opt/pspm/install.sh rollback` |
| The firewall locks something out | `sudo /opt/pspm/install.sh firewall off` |

There are no OTP recovery codes: a lost authenticator is always reset with the script. Each script run is recorded in the audit log.
