# Access policies and access links

Every site has a policy: a request is let in when **any** of its conditions is true.

| Condition | Met when |
|---|---|
| LAN | the client address is in the LAN ranges (*Settings*) |
| Cleared | the address was cleared **for this site** with an access link |
| Client certificate | the client shows a valid certificate for this site |
| Public | always |

A route can have its own policy, for example one public path on an otherwise closed site.

## Access links

An access link opens **one site** for the address it is opened from.

- Create it on *Access*, for a site whose policy contains *Cleared*.
- The link lives on the site's own host name: `https://<site>/.pspm/access/<token>`. It is shown once; send it to the person it is for.
- A visit clears the visitor's address for the chosen time. Revoking the link ends the clearances it gave.
- In the firewall, a cleared address passes only on the web ports, never SSH.

## Bans and blocks

- 30 failed sign-ins within an hour ban an address for 24 hours (*Settings*).
- Blocks on *Access* apply in nginx and, unless marked *nginx only*, in the firewall on every port.
- Private, loopback and link-local addresses are never banned or blocked.
