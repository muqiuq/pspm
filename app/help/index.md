# Getting started

PSPM is configured here and applied on the server. Nothing you change in the UI touches nginx until an admin runs `install.sh` over SSH.

## The flow

1. Add a **backend**: the server a site forwards to (*Backends → Add backend*).
2. Add a **site**: its host names, the backend, and who may reach it (*Sites → Add site*).
3. Open **Changes**, check the preview, and click **Ready to apply**.
4. On the server run `sudo /opt/pspm/install.sh`. It shows what changes, asks, tests the new configuration, switches to it, checks it, and rolls back by itself if anything fails.

A site with a Let's Encrypt certificate is first served on port 80 only (it shows *certificate pending*). The same `install.sh` run requests the certificate and applies again, as soon as the host name points to this box.

## Reaching the UI

- Without an admin host name: `https://<server address>/`, from private addresses only.
- With an admin host name (*Settings*) that has its certificate: only there.
- Always: through an SSH tunnel, `ssh -L 9443:127.0.0.1:9443 root@<box>`, then `https://localhost:9443/`. Every SSH login shows this command.

## More

- [Access policies and access links](/help/access)
- [Applying, rollback, drift](/help/applying)
- [Recovery](/help/recovery)
