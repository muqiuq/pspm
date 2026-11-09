# Applying, rollback, drift

## Applying

```
sudo /opt/pspm/install.sh            # everything: packages, database, app, then the configuration
sudo /opt/pspm/install.sh apply      # only the configuration
sudo /opt/pspm/install.sh update     # deploy new code (fast-forward pull), then everything
```

`install.sh` applies the **newest revision marked ready**. Edits made later are not included.

What a run does with the configuration:

1. renders it into a new release directory,
2. shows the changes; those that **open** access are marked,
3. tests it with `nginx -t`,
4. switches atomically and reloads nginx,
5. checks that nginx serves it, every TLS name presents its certificate and the UI answers,
6. rolls back to the previous release by itself if a check fails.

Every run writes `/var/log/pspm/install-<time>.log`. *Changes* lists the applies with their logs.

## Rollback

`sudo /opt/pspm/install.sh rollback` switches back to the previous release. It works without the database.

## Drift

If someone edits nginx files of the live release by hand, PSPM shows it on the dashboard and on *Changes*. The next `install.sh` run lists the edits, replaces them only after you type `yes`, and keeps the edited release on disk.

## When something goes wrong

`sudo /opt/pspm/install.sh doctor` checks the box. `sudo /opt/pspm/install.sh report` writes one text file with everything needed for debugging (passwords and tokens removed).
