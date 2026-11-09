<?php
declare(strict_types=1);

/**
 * Snapshot files: PHP publishes runtime state, nginx (Lua) and the agent read it
 * (plan §11.3). Format, one entry per line:  key <TAB> expires-epoch (0 = never) <TAB> value
 * Header lines start with '#'. Lua builds the same keys (lua/pspm.lua).
 */
final class State
{
    public const NAMES = ['cleared', 'banned', 'blocked', 'trusted', 'certs'];

    /** Rebuild the named snapshots (all when none given), write them atomically, tell nginx. */
    public static function publish(string ...$names): array
    {
        $names = $names ?: self::NAMES;
        if (!is_dir(PSPM_STATE)) @mkdir(PSPM_STATE, 0750, true);
        foreach ($names as $n) {
            [$lines, $meta] = self::build($n);
            $serial = (int)DB::val('INSERT INTO snapshot_serials (name, serial) VALUES (?, 1)
                ON CONFLICT (name) DO UPDATE SET serial = snapshot_serials.serial + 1 RETURNING serial', [$n]);
            $head = "# pspm snapshot $n\n# serial $serial\n# generated " . gmdate('c') . "\n";
            foreach ($meta as $k => $v) $head .= "# $k $v\n";
            write_atomic(PSPM_STATE . "/$n.tsv", $head . implode('', $lines), 0640);
        }
        return self::sync();
    }

    /** @return array{0: string[], 1: array<string,string>} */
    public static function build(string $name): array
    {
        $lines = [];
        $lens = [4 => [], 6 => []];
        $add = function (string $key, ?string $expires, string $value) use (&$lines) {
            $exp = $expires ? (new DateTimeImmutable($expires))->getTimestamp() : 0;
            $lines[] = "$key\t$exp\t$value\n";
        };
        switch ($name) {
            case 'cleared':
                foreach (DB::all('SELECT site_id, host(ip) AS addr, masklen(ip) AS len, expires_at FROM cleared_ips
                                  WHERE expires_at IS NULL OR expires_at > now()') as $r) {
                    $add($r['site_id'] . '|' . IP::clientKey($r['addr']), $r['expires_at'], '1');
                }
                break;
            case 'banned':
            case 'blocked':
                $sql = $name === 'banned'
                    ? 'SELECT ip::text AS cidr, expires_at, \'login\' AS v FROM banned_ips WHERE expires_at > now()'
                    : 'SELECT ip::text AS cidr, expires_at, (CASE WHEN firewall THEN \'fw\' ELSE \'nginx\' END) AS v FROM blocks WHERE expires_at > now()';
                foreach (DB::all($sql) as $r) {
                    if (IP::neverBlocked($r['cidr'])) continue;   // defence in depth
                    [$key, $fam, $len] = self::cidrKey($r['cidr']);
                    $lens[$fam][$len] = true;
                    $add($key, $r['expires_at'], $r['v']);
                }
                break;
            case 'trusted':
                foreach (DB::all('SELECT ip::text AS cidr, kind, expires_at FROM trusted_ips WHERE expires_at IS NULL OR expires_at > now()') as $r) {
                    [$key] = self::cidrKey($r['cidr']);
                    $add($key, $r['expires_at'], $r['kind']);
                }
                break;
            case 'certs':
                if (DB::val("SELECT to_regclass('client_certs')")) {
                    foreach (DB::all('SELECT fingerprint_sha1, revoked_at, scope FROM client_certs') as $r) {
                        $add($r['fingerprint_sha1'], null, $r['revoked_at'] ? 'revoked' : ($r['scope'] ?: 'all'));
                    }
                }
                break;
            default:
                throw new InvalidArgumentException("unknown snapshot $name");
        }
        sort($lines);
        $meta = [];
        if (in_array($name, ['banned', 'blocked'], true)) {
            foreach ([4, 6] as $f) { $l = array_keys($lens[$f]); rsort($l); $meta["lens$f"] = implode(',', $l); }
        }
        return [$lines, $meta];
    }

    /**
     * Canonical key for a network: IPv4 "a.b.c.d/len"; IPv6 (at most /64) "a:b:c:d::/len".
     * @return array{0: string, 1: int, 2: int}
     */
    public static function cidrKey(string $cidr): array
    {
        [$bin, $len] = IP::parseCidr($cidr) ?? [inet_pton('0.0.0.0'), 32];
        if (strlen($bin) === 4) return [inet_ntop($bin) . "/$len", 4, $len];
        $len = min($len, 64);
        $g = unpack('n4', substr(IP::mask($bin, $len), 0, 8));
        return [sprintf('%x:%x:%x:%x::/%d', $g[1], $g[2], $g[3], $g[4], $len), 6, $len];
    }

    /** Ask nginx to reload its dicts from the files. Failure is not fatal: nginx loads them at the next reload. */
    public static function sync(): array
    {
        [$code, $body, $err] = http_get_local('http://127.0.0.1:9080/pspm-sync', 3.0);
        if ($code !== 200) return ['ok' => false, 'error' => $err ?: "HTTP $code"];
        try { return ['ok' => true] + (array)json_dec($body); } catch (Throwable) { return ['ok' => false, 'error' => 'bad answer']; }
    }

    public static function nginxStatus(): ?array
    {
        [$code, $body] = http_get_local('http://127.0.0.1:9080/pspm-sync?status=1', 1.5);
        if ($code !== 200) return null;
        try { return (array)json_dec($body); } catch (Throwable) { return null; }
    }
}
