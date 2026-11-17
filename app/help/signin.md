# Microsoft sign-in

A site can require a sign-in with a Microsoft (Entra ID) account. PSPM runs oauth2-proxy for this; nginx asks it for every request whether the session is valid.

## Set up Entra

1. *App registrations → New registration*: single tenant; platform **Web**; redirect URI `https://<sign-in host>/oauth2/callback` (for example `https://auth.example.ch/oauth2/callback`).
2. *Certificates & secrets*: create a client secret; note when it expires.
3. *API permissions*: Microsoft Graph, delegated: `openid`, `profile`, `email`, `offline_access`.
4. To restrict sites by group: *Token configuration → Add groups claim*, security groups, as group IDs. For large tenants use app roles instead and choose the claim `roles`.
5. *Enterprise applications* → the app → *Properties*: **Assignment required: Yes**; then assign the users or groups who may sign in.
6. DNS: the sign-in host name points to this box.

## In PSPM

1. *Sign-in → Add a provider*: tenant ID, client ID, client secret, sign-in host, accepted e-mail domains.
2. On a site: *Sign-in* — **alternative** (LAN *or* signed in) or **required** (*and* signed in); optionally the allowed groups or addresses, and which identity headers the backend gets.
3. *Changes → Ready to apply*, then `sudo /opt/pspm/install.sh`. It starts the containers, requests the sign-in host's certificate and checks that the sign-in redirects to Microsoft.

## Behaviour

- Sessions are kept in Redis. With the re-check interval, a user disabled in Entra loses access within that time.
- The backend gets the identity headers you chose; a client can never send its own. The session cookies never reach a backend.
- If oauth2-proxy or Microsoft cannot be reached, sites that **require** sign-in answer 503; LAN, access links and certificates still work.

## Applications with their own sign-in

An application behind a site can have its own Microsoft sign-in (its own app registration), for example ASP.NET Core with the callbacks `/signin-oidc` and `/signout-callback-oidc`. Microsoft returns to `/signin-oidc` with a form POST from its own domain. The browser does not send PSPM's session cookie with it (SameSite=Lax), so PSPM sends the request to the sign-in instead of to the application, and the application's login fails. Let the callbacks through:

1. On the site, *Add route*: match **exact**, paths `/signin-oidc /signout-callback-oidc`, action *proxy to backend*.
2. *Overrides for this route*: access **Public**, sign-in **none**. Other paths keep the site's policy. The callbacks go to the same backend with the same headers; the application checks state, nonce and PKCE itself. Bans and blocks still apply, and PSPM's session cookies still never reach the application. The install.sh review lists the route as opening access.
3. If the application sets large cookies, raise the *Response header buffer* of its backend (64k). Request headers are accepted up to 32k per line (the Cookie header) and 256k in total.
4. The application builds its redirect URIs from `Host` (keep *Host header upstream: the client's host name*) and `X-Forwarded-Proto` (`https`). PSPM sets `X-Forwarded-For` to the client's address only. The application has to trust PSPM's address for these headers (ASP.NET Core: `ForwardedHeadersOptions.KnownProxies`); otherwise it builds `http://` redirect URIs and sees every user as PSPM's address. PSPM's address towards the application: `ip route get <backend address>` on this box (the `src` field).
