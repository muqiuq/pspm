<?php
declare(strict_types=1);

/** Login bans, blocks, cleared addresses and access links (plan §11). */
final class Access
{
    public static function isBanned(string $ip): bool
    {
        if (IP::isPrivate($ip)) return false;
        return (bool)DB::val('SELECT 1 FROM banned_ips WHERE ip >>= ?::inet AND expires_at > now() LIMIT 1', [$ip]);
    }

    public static function ban(string $ip, string $reason, int $secs): void
    {
        if (IP::neverBlocked($ip)) return;
        DB::q('INSERT INTO banned_ips (ip, reason, expires_at) VALUES (?::cidr, ?, now() + make_interval(secs => ?))
               ON CONFLICT (ip) DO UPDATE SET reason = excluded.reason, expires_at = excluded.expires_at',
            [IP::clientCidr($ip), $reason, $secs]);
        Audit::log('ban', 'ip:' . IP::clientKey($ip), ['reason' => $reason, 'secs' => $secs]);
        try { State::publish('banned'); } catch (Throwable) { /* nginx picks it up at the next sync */ }
    }

    public static function unban(string $cidr): int
    {
        $n = DB::q('DELETE FROM banned_ips WHERE ip <<= ?::cidr OR ip >>= ?::cidr', [$cidr, $cidr])->rowCount();
        DB::q('DELETE FROM login_failures WHERE ip <<= ?::cidr', [$cidr]);
        return $n;
    }

    public static function unblock(string $cidr): int
    {
        return DB::q('DELETE FROM blocks WHERE ip <<= ?::cidr OR ip >>= ?::cidr', [$cidr, $cidr])->rowCount();
    }

    // ---- access links (one site each, plan §11.1)

    /** A link for one site, or for the admin UI ($siteId null). Returns [id, token]; the token is shown once. */
    public static function createLink(?string $siteId, string $label, ?int $grantSecs, ?string $validUntil, ?int $maxUses, string $after): array
    {
        $token = Crypto::token(24);
        $id = Crypto::uuid();
        DB::q('INSERT INTO access_links (id, token_hash, site_id, target, label, grant_secs, valid_until, max_uses, after_path, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$id, hash('sha256', $token), $siteId, $siteId === null ? 'admin' : 'site', $label, $grantSecs, $validUntil, $maxUses, $after, Audit::actor()]);
        Audit::log('link.create', "link:$id", ['site' => $siteId ?? 'admin UI', 'label' => $label]);
        return [$id, $token];
    }

    /** The admin host name that is live (the applied revision), else the working copy's. */
    public static function liveAdminHost(): string
    {
        $live = Live::revision()['document']['global']['admin_host'] ?? null;
        return (string)($live ?? Settings::global()['admin_host']);
    }

    public static function revokeLink(string $id): void
    {
        DB::tx(function () use ($id) {
            DB::q('UPDATE access_links SET revoked_at = now() WHERE id = ? AND revoked_at IS NULL', [$id]);
            DB::q('DELETE FROM cleared_ips WHERE link_id = ?', [$id]);
        });
        Audit::log('link.revoke', "link:$id");
        State::publish('cleared');
    }

    /**
     * A visit to https://<site host>/.pspm/access/<token>, or to the admin host name for a link
     * to the admin UI. A link works only on its own host names. Returns [ok, message, redirect path].
     */
    public static function useLink(string $host, string $token, string $ip): array
    {
        if (self::isBanned($ip)) return [false, 'Your address is blocked.', null];
        $host = strtolower($host);
        $l = DB::one('SELECT * FROM access_links WHERE token_hash = ?', [hash('sha256', $token)]);
        if ($l) {
            $hostOk = $l['target'] === 'admin'
                ? $host !== '' && $host === self::liveAdminHost()
                : (bool)DB::val('SELECT 1 FROM site_hosts WHERE site_id = ? AND host = ?', [$l['site_id'], $host]);
            if (!$hostOk) $l = null;
            else $l['host'] = $host;
        }
        if (!$l || $l['revoked_at'] || ($l['valid_until'] && strtotime($l['valid_until']) < time())
            || ($l['max_uses'] !== null && (int)$l['uses'] >= (int)$l['max_uses'])) {
            return [false, 'This link is not valid (any more).', null];
        }
        $cidr = IP::clientCidr($ip);
        $days = (int)(Settings::get('trust', [])['authorised_days'] ?? 30);
        DB::tx(function () use ($l, $cidr, $days) {
            DB::q('UPDATE access_links SET uses = uses + 1, last_used_at = now() WHERE id = ?', [$l['id']]);
            DB::q('INSERT INTO cleared_ips (site_id, ip, link_id, expires_at)
                   VALUES (?, ?::cidr, ?, CASE WHEN ?::int IS NULL THEN NULL ELSE now() + make_interval(secs => ?::int) END)
                   ON CONFLICT (scope, ip) DO UPDATE SET link_id = excluded.link_id, expires_at = excluded.expires_at',
                [$l['site_id'], $cidr, $l['id'], $l['grant_secs'], $l['grant_secs']]);
            if (!IP::isPrivate(explode('/', $cidr)[0])) {
                DB::q("INSERT INTO trusted_ips (ip, kind, source, last_seen, expires_at)
                       VALUES (?::cidr, 'authorised', ?, now(), now() + make_interval(days => ?))
                       ON CONFLICT (ip) DO UPDATE SET last_seen = now(),
                         expires_at = CASE WHEN trusted_ips.kind = 'trusted' THEN trusted_ips.expires_at
                                           ELSE greatest(trusted_ips.expires_at, excluded.expires_at) END",
                    [$cidr, 'link:' . $l['id'], $days]);
            }
        });
        putenv('PSPM_ACTOR=link:' . $l['label']);
        Audit::log('link.use', 'link:' . $l['id'], ['ip' => $cidr, 'site' => $l['host']]);
        State::publish('cleared', 'trusted');
        return [true, 'Access granted.', $l['after_path'] ?: '/'];
    }
}
