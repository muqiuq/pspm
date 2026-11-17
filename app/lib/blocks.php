<?php
declare(strict_types=1);

/**
 * Blocks with escalation and the guards no automatic decision can override (plan §15.4).
 */
final class Blocks
{
    public const DURATIONS = [86400, 7 * 86400, 30 * 86400];

    /**
     * The evidence an address needs in 24 h before the AI may judge it for a block, at
     * aggressiveness 0.5. Any one is enough; a mix counts in proportion. Probes are requests
     * by IP address or for host names no site serves (exploit paths included): scanners of
     * the whole internet send a few, so it takes several. Exploits are requests for exploit
     * paths at a site this proxy serves. Honeypots block on the first hit regardless.
     */
    public const EVIDENCE = ['probes' => 10, 'exploits' => 3, 'denied' => 20, 'not_found' => 40];

    /** Blocking aggressiveness (Settings → AI decisions): 0 cautious, 0.5 default, 1 eager. */
    public static function aggressiveness(): float
    {
        return max(0.0, min(1.0, (float)AI::settings()['aggressiveness']));
    }

    /** The confidence an AI block needs (both models): 0.95 at aggressiveness 0, 0.85 at 0.5, 0.75 at 1. */
    public static function minConfidence(?float $a = null): float
    {
        return round(0.95 - 0.2 * max(0.0, min(1.0, $a ?? self::aggressiveness())), 3);
    }

    /** The evidence minimums in effect: EVIDENCE × 4 at aggressiveness 0, × 1 at 0.5, × ¼ at 1 (rounded up). */
    public static function evidenceNeeded(?float $a = null): array
    {
        $f = 4 ** (1 - 2 * max(0.0, min(1.0, $a ?? self::aggressiveness())));
        return array_map(fn(int $n) => max(1, (int)ceil($n * $f - 1e-9)), self::EVIDENCE);
    }

    /** How much of the needed evidence an address has, 1 = enough. $counts has the keys of EVIDENCE. */
    public static function evidence(array $counts, ?array $needed = null): float
    {
        $s = 0.0;
        foreach ($needed ?? self::evidenceNeeded() as $k => $n) $s += max(0, (int)($counts[$k] ?? 0)) / $n;
        return round($s, 6);
    }

    /** Is the address trusted or authorised (cleared addresses included)? */
    public static function trusted(string $ip): bool
    {
        return (bool)DB::val("SELECT 1 FROM trusted_ips WHERE ip >>= ?::inet AND (expires_at IS NULL OR expires_at > now())
                              UNION ALL SELECT 1 FROM cleared_ips WHERE ip >>= ?::inet AND (expires_at IS NULL OR expires_at > now()) LIMIT 1", [$ip, $ip]);
    }

    public static function isBlocked(string $cidr): bool
    {
        return (bool)DB::val('SELECT 1 FROM blocks WHERE ip >>= ?::cidr AND expires_at > now() LIMIT 1', [$cidr]);
    }

    /** Escalation: 1 day, 7 days, 30 days, counted over 180 days of automatic blocks. */
    public static function escalated(string $cidr): int
    {
        $n = (int)DB::val("SELECT count(*) FROM block_history WHERE ip = ?::cidr AND source <> 'manual' AND created_at > now() - interval '180 days'", [$cidr]);
        return self::DURATIONS[min($n, 2)];
    }

    /**
     * The guards (plan §15.4). Returns null when the address may be blocked, else the reason
     * it is not. $checkConfidence is false for "no reaction means a block" (plan §15.7).
     */
    public static function guard(string $ip, string $verdict, float $confidence, bool $checkConfidence = true): ?string
    {
        $cidr = IP::clientCidr($ip);
        if (IP::neverBlocked($cidr)) return 'never-blocked range';
        if (self::trusted($ip)) return 'trusted or authorised';
        if (DB::val("SELECT 1 FROM block_history WHERE ip = ?::cidr AND removed_by IS NOT NULL AND removed_by NOT LIKE 'system%' AND removed_at > now() - interval '30 days'", [$cidr])) {
            return 'an admin removed a block on it in the last 30 days';
        }
        if (self::isBlocked($cidr)) return 'already blocked';
        if ($verdict !== 'block') return $verdict === 'watch' ? 'watch' : 'benign';
        if ($checkConfidence && $confidence < self::minConfidence()) return 'below threshold';
        return null;
    }

    /** Place an automatic block, honouring dry-run and the circuit breaker. Returns the outcome. */
    public static function auto(string $ip, string $source, string $reason, ?int &$runCount = null): string
    {
        $scan = Settings::get('scan', []);
        $mode = AI::settings()['mode'];
        if (($scan['breaker_tripped'] ?? false) || $mode === 'dry-run') return 'would block (dry-run)';
        $today = (int)DB::val("SELECT count(*) FROM block_history WHERE source NOT IN ('manual') AND created_by = 'system' AND created_at > now() - interval '24 hours'");
        if (($runCount ?? 0) >= 50 || $today >= 300) {
            Settings::set('scan', array_replace($scan, ['breaker_tripped' => true, 'breaker_at' => gmdate('c')]));
            Notify::event('health', 'Circuit breaker: the security scan switched to dry-run',
                "One run would have added more than 50 blocks, or the day more than 300. The scan now only reports what it would block.\nCheck the Security page and switch back when this is understood.", 'breaker');
            Audit::log('scan.breaker', null, ['run' => $runCount, 'day' => $today]);
            return 'capped (circuit breaker)';
        }
        self::add($ip, $source, $reason, null, true, 'system');
        if ($runCount !== null) $runCount++;
        return 'blocked';
    }

    /** Add or extend a block (CIDR-aware); records the history. */
    public static function add(string $ipOrCidr, string $source, string $reason, ?int $secs, bool $firewall, string $by): void
    {
        $cidr = str_contains($ipOrCidr, '/') ? (IP::normCidr($ipOrCidr) ?? $ipOrCidr) : IP::clientCidr($ipOrCidr);
        if (IP::neverBlocked($cidr)) return;
        $secs ??= self::escalated($cidr);
        DB::tx(function () use ($cidr, $source, $reason, $secs, $firewall, $by) {
            DB::q("INSERT INTO blocks (ip, source, reason, firewall, expires_at, created_by) VALUES (?::cidr, ?, ?, ?, now() + make_interval(secs => ?), ?)
                   ON CONFLICT (ip) DO UPDATE SET source = excluded.source, reason = excluded.reason, firewall = excluded.firewall,
                     expires_at = greatest(blocks.expires_at, excluded.expires_at)", [$cidr, $source, mb_substr($reason, 0, 300), $firewall, $secs, $by]);
            DB::q('INSERT INTO block_history (ip, source, reason, duration_secs, created_by) VALUES (?::cidr, ?, ?, ?, ?)', [$cidr, $source, mb_substr($reason, 0, 300), $secs, $by]);
        });
    }

    /** Remove blocks (admin): keeps the history and makes the guard skip it for 30 days. */
    public static function remove(string $cidr, string $reason, bool $trust): int
    {
        $n = DB::q('DELETE FROM blocks WHERE ip <<= ?::cidr OR ip >>= ?::cidr', [$cidr, $cidr])->rowCount();
        DB::q("UPDATE block_history SET removed_at = now(), removed_by = ?, removed_reason = ? WHERE (ip <<= ?::cidr OR ip >>= ?::cidr) AND removed_at IS NULL",
            [Audit::actor(), $reason ?: null, $cidr, $cidr]);
        if ($trust && !IP::neverBlocked($cidr)) {
            DB::q("INSERT INTO trusted_ips (ip, kind, source, note) VALUES (?::cidr, 'trusted', 'admin', ?) ON CONFLICT (ip) DO UPDATE SET kind = 'trusted', source = 'admin', expires_at = NULL",
                [$cidr, $reason ?: 'trusted when unblocked']);
        }
        Audit::log('unblock', "ip:$cidr", ['reason' => $reason, 'trust' => $trust]);
        State::publish('blocked', 'trusted');
        return $n;
    }
}
