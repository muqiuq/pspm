<?php
declare(strict_types=1);

/** Address helpers. IPv6 clients are handled per /64 (privacy addresses rotate inside it). */
final class IP
{
    /** Never blocked, anywhere (plan §14.2). Must match SQL, Lua and the firewall rules. */
    public const NEVER_BLOCKED = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
        '::1/128', 'fc00::/7', 'fe80::/10'];

    public static function valid(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /** Parse "addr" or "addr/len". Returns [binary network, prefix length] or null. */
    public static function parseCidr(string $cidr): ?array
    {
        $cidr = trim($cidr);
        $len = null;
        if (str_contains($cidr, '/')) {
            [$cidr, $l] = explode('/', $cidr, 2);
            if (!ctype_digit($l)) return null;
            $len = (int)$l;
        }
        $bin = @inet_pton($cidr);
        if ($bin === false) return null;
        $max = strlen($bin) * 8;
        $len ??= $max;
        if ($len < 0 || $len > $max) return null;
        return [self::mask($bin, $len), $len];
    }

    public static function mask(string $bin, int $len): string
    {
        $out = '';
        for ($i = 0; $i < strlen($bin); $i++) {
            $bits = max(0, min(8, $len - $i * 8));
            $out .= chr(ord($bin[$i]) & (0xff << (8 - $bits)) & 0xff);
        }
        return $out;
    }

    /** Canonical text form "net/len" (host bits cleared). */
    public static function normCidr(string $cidr): ?string
    {
        $p = self::parseCidr($cidr);
        return $p ? inet_ntop($p[0]) . '/' . $p[1] : null;
    }

    public static function family(string $cidr): int
    {
        $p = self::parseCidr($cidr);
        return $p && strlen($p[0]) === 16 ? 6 : 4;
    }

    /** Do the two networks overlap? */
    public static function overlaps(string $a, string $b): bool
    {
        $pa = self::parseCidr($a); $pb = self::parseCidr($b);
        if (!$pa || !$pb || strlen($pa[0]) !== strlen($pb[0])) return false;
        $len = min($pa[1], $pb[1]);
        return self::mask($pa[0], $len) === self::mask($pb[0], $len);
    }

    public static function contains(string $net, string $ip): bool
    {
        $pn = self::parseCidr($net); $pi = self::parseCidr($ip);
        if (!$pn || !$pi || strlen($pn[0]) !== strlen($pi[0])) return false;
        return self::mask($pi[0], $pn[1]) === $pn[0];
    }

    public static function neverBlocked(string $cidr): bool
    {
        foreach (self::NEVER_BLOCKED as $n) if (self::overlaps($n, $cidr)) return true;
        return false;
    }

    public static function isPrivate(string $ip): bool
    {
        foreach (self::NEVER_BLOCKED as $n) if (self::contains($n, $ip)) return true;
        return false;
    }

    /**
     * The key a client is tracked under: the IPv4 address, or the IPv6 /64 written as
     * "a:b:c:d::/64" with lower-case hex and no leading zeros. lua/pspm.lua builds the same.
     */
    public static function clientKey(string $ip): string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) return $ip;
        if (strlen($bin) === 4) return inet_ntop($bin);
        $g = unpack('n4', substr($bin, 0, 8));
        return sprintf('%x:%x:%x:%x::/64', $g[1], $g[2], $g[3], $g[4]);
    }

    /** The client key as a CIDR for the database (IPv4 /32 or IPv6 /64). */
    public static function clientCidr(string $ip): string
    {
        $k = self::clientKey($ip);
        return str_contains($k, '/') ? $k : $k . '/32';
    }

    public static function remote(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
}
