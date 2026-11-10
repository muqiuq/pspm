<?php
declare(strict_types=1);

/**
 * Honeypots (plan §15.5): request paths only attackers ask for. The first request to an
 * active trap from an untrusted address blocks it at once (block.lua); the fast pass makes
 * the block permanent-ish and puts it into the firewall.
 */
final class Traps
{
    public const MAX_ACTIVE = 500;
    public const BREAKER_PER_HOUR = 200;
    public const MIN_PREFIX = 5;
    public const TRACKS = ['fast' => ['votes' => 1, 'attackers' => 2, 'shadow_secs' => 3600],
                           'standard' => ['votes' => 3, 'attackers' => 5, 'shadow_secs' => 12 * 3600]];

    public static function enabled(): bool { return (bool)(Settings::get('traps', [])['enabled'] ?? true); }

    public static function validPath(string $kind, string $path): ?string
    {
        $path = strtolower(trim($path));
        if (!preg_match('#^/[a-z0-9._~!*\'()@:+,=&%/-]*$#', $path) || str_starts_with($path, '/.pspm/') || str_starts_with($path, '/.well-known/acme-challenge')) return null;
        if ($kind === 'prefix' && strlen($path) < self::MIN_PREFIX) return null;
        if ($path === '/' || $path === '/index.html' || $path === '/favicon.ico' || $path === '/robots.txt') return null;
        return $path;
    }

    /**
     * What the backends answered for requests matching the trap (plan §15.5):
     * 'rejected' (a backend served it), 'fast' (only 404/410 everywhere), 'standard' (never asked).
     */
    public static function evidence(string $host, string $kind, string $path): string
    {
        $where = $kind === 'exact' ? 'path = ?' : 'path LIKE ?';
        $arg = $kind === 'exact' ? $path : str_replace(['%', '_'], ['\%', '\_'], $path) . '%';
        $sql = "SELECT data FROM attack_paths WHERE $where" . ($host === '*' ? '' : ' AND host = ?') . " AND day > now() - interval '30 days'";
        $asked = false;
        foreach (DB::all($sql, $host === '*' ? [$arg] : [$arg, $host]) as $r) {
            foreach ((json_dec($r['data'])['ust'] ?? []) as $code => $n) {
                $asked = true;
                if (!in_array((int)$code, [404, 410], true)) return 'rejected';
            }
        }
        return $asked ? 'fast' : 'standard';
    }

    public static function add(string $host, string $kind, string $path, string $state, string $by, string $note = ''): ?int
    {
        $p = self::validPath($kind, $path);
        if (!$p) return null;
        $track = self::evidence($host, $kind, $p);
        if ($track === 'rejected') $state = 'rejected';
        $id = DB::val("INSERT INTO traps (host, kind, path, state, track, note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT (host, kind, path) DO UPDATE SET updated_at = now() RETURNING id",
            [$host, $kind, $p, $state, $track === 'rejected' ? 'standard' : $track, $note, $by]);
        return (int)$id;
    }

    public static function setState(int $id, string $state): void
    {
        if ($state === 'active') {
            $t = DB::one('SELECT * FROM traps WHERE id = ?', [$id]);
            if (!$t || $t['state'] === 'rejected') throw new InvalidArgumentException('A rejected trap cannot be activated: a backend serves this path.');
            if ((int)DB::val("SELECT count(*) FROM traps WHERE state = 'active'") >= self::MAX_ACTIVE) throw new InvalidArgumentException('At most ' . self::MAX_ACTIVE . ' active traps.');
        }
        DB::q('UPDATE traps SET state = ?, shadow_since = CASE WHEN ? = \'shadow\' THEN now() ELSE shadow_since END, updated_at = now() WHERE id = ?', [$state, $state, $id]);
        Audit::log('trap.' . $state, "trap:$id");
        State::publish('traps');
    }

    /** Lifecycle, safety and mining; run by the full scan round. */
    public static function maintain(bool $runNow = false): array
    {
        $st = ['activated' => 0, 'disabled' => 0, 'retired' => 0, 'mined' => 0];
        if (!self::enabled()) return $st + ['enabled' => false];
        // breaker: too many trap blocks in an hour puts every trap back into shadow
        $hour = (int)DB::val("SELECT count(*) FROM block_history WHERE source = 'trap' AND created_at > now() - interval '1 hour'");
        if ($hour >= self::BREAKER_PER_HOUR) {
            DB::q("UPDATE traps SET state = 'shadow', shadow_since = now() WHERE state = 'active' AND NOT pinned");
            Notify::event('health', 'Honeypot breaker: all traps back in shadow', "$hour trap blocks within an hour. Every trap is now only observed. Check the traps on the Security page.", 'trap-breaker');
            Audit::log('trap.breaker', null, ['blocks_last_hour' => $hour]);
        }
        foreach (DB::all("SELECT * FROM traps WHERE state IN ('proposed', 'shadow', 'active')") as $t) {
            $ev = self::evidence($t['host'], $t['kind'], $t['path']);
            if ($ev === 'rejected') {   // a backend serves this path: never a trap
                DB::q("UPDATE traps SET state = CASE WHEN state = 'active' THEN 'disabled' ELSE 'rejected' END, updated_at = now() WHERE id = ?", [$t['id']]);
                $st['disabled']++;
                continue;
            }
            $tr = self::TRACKS[$ev];
            $attackers = self::attackers($t['host'], $t['kind'], $t['path']);
            DB::q('UPDATE traps SET track = ?, attackers = ? WHERE id = ?', [$ev, $attackers, $t['id']]);
            if ($t['state'] === 'proposed' && (int)$t['votes'] >= $tr['votes'] && $attackers >= $tr['attackers']) {
                DB::q("UPDATE traps SET state = 'shadow', shadow_since = now(), updated_at = now() WHERE id = ?", [$t['id']]);
            } elseif ($t['state'] === 'shadow' && $t['shadow_since'] && time() - strtotime($t['shadow_since']) >= $tr['shadow_secs']
                && (int)DB::val("SELECT count(*) FROM traps WHERE state = 'active'") < self::MAX_ACTIVE && $hour < self::BREAKER_PER_HOUR) {
                DB::q("UPDATE traps SET state = 'active', updated_at = now() WHERE id = ?", [$t['id']]);
                $st['activated']++;
            } elseif ($t['state'] === 'active' && !$t['pinned'] && strtotime($t['last_hit_at'] ?? $t['updated_at']) < time() - 90 * 86400) {
                DB::q("UPDATE traps SET state = 'retired', updated_at = now() WHERE id = ?", [$t['id']]);
                $st['retired']++;
            }
        }
        // scope: a pattern seen on at least 3 hosts applies to every host
        foreach (DB::all("SELECT kind, path, count(DISTINCT host) AS n FROM traps WHERE host <> '*' AND state IN ('shadow', 'active') GROUP BY kind, path HAVING count(DISTINCT host) >= 3") as $r) {
            self::add('*', $r['kind'], $r['path'], 'shadow', 'system', 'seen on ' . $r['n'] . ' hosts');
        }
        $last = SecScan::state('last_mining');
        $refused = (int)DB::val("SELECT count(*) FROM attack_paths WHERE day >= current_date - 1");
        if (($runNow || !$last || time() - strtotime($last['at']) >= 3 * 3600) && $refused > 0 && AI::available()) {
            $st['mined'] = self::mine();
            SecScan::setState('last_mining', ['at' => gmdate('c')]);
        }
        return $st;
    }

    private static function attackers(string $host, string $kind, string $path): int
    {
        $where = $kind === 'exact' ? 'path = ?' : 'path LIKE ?';
        $arg = $kind === 'exact' ? $path : str_replace(['%', '_'], ['\%', '\_'], $path) . '%';
        $ips = [];
        foreach (DB::all("SELECT data FROM attack_paths WHERE $where" . ($host === '*' ? '' : ' AND host = ?') . " AND day > now() - interval '30 days'",
            $host === '*' ? [$arg] : [$arg, $host]) as $r) {
            foreach (array_keys(json_dec($r['data'])['ips'] ?? []) as $ip) $ips[$ip] = true;
        }
        return count($ips);
    }

    /** Ask the AI for trap patterns in the refused paths of the last 24 h; one vote per pattern and 3-hour window. */
    private static function mine(): int
    {
        $rows = DB::all("SELECT host, path, data FROM attack_paths WHERE day >= current_date - 1 ORDER BY (data->>'refused')::int DESC NULLS LAST LIMIT 300");
        if (!$rows) return 0;
        $ps = AI::pseudonymiser();
        $items = [];
        foreach ($rows as $r) {
            $d = json_dec($r['data']);
            $items[] = ['host' => $ps->of('host', $r['host']), 'path' => AI::scrubPath($r['path']), 'requests' => $d['total'] ?? 0,
                'refused' => $d['refused'] ?? 0, 'backend_answers' => $d['ust'] ?? new stdClass(), 'clients' => count($d['ips'] ?? [])];
        }
        $sys = 'You design honeypot rules for a reverse proxy. From refused request paths, propose patterns that only attackers request '
            . '(e.g. /.env, /.git/config, /wp-login.php on sites without WordPress). Never propose paths a real application may serve, '
            . 'or anything a backend answered with something other than 404/410. Answer only JSON: {"patterns":[{"host":"host-1 or *",'
            . '"kind":"exact|prefix","path":"/...","reason":"short"}]}';
        try { [$ans, $callId] = AI::call('main', 'honeypots', $sys, ['paths' => $items], $ps); }   // logged in the AI log
        catch (Throwable $e) { return 0; }
        $window = gmdate('Y-m-d\TH:00:00\Z', intdiv(time(), 10800) * 10800);
        $n = 0;
        foreach (array_slice((array)($ans['patterns'] ?? []), 0, 50) as $p) {
            $host = ($p['host'] ?? '*') === '*' ? '*' : $ps->reverse((string)($p['host'] ?? ''));
            $kind = in_array($p['kind'] ?? '', ['exact', 'prefix'], true) ? $p['kind'] : 'exact';
            if (!$host || !self::validPath($kind, (string)($p['path'] ?? ''))) continue;
            $id = self::add($host, $kind, (string)$p['path'], 'proposed', 'ai', mb_substr((string)($p['reason'] ?? ''), 0, 200));
            if (!$id) continue;
            if (DB::q('INSERT INTO trap_votes (trap_id, window_start) VALUES (?, ?) ON CONFLICT DO NOTHING', [$id, $window])->rowCount()) {
                DB::q('UPDATE traps SET votes = votes + 1 WHERE id = ?', [$id]);
                $n++;
            }
        }
        DB::q("INSERT INTO ai_verdicts (kind, subject, verdict, answer, model, outcome, call_id) VALUES ('mining', 'traps', 'patterns', ?::jsonb, ?, ?, ?)",
            [json_enc($ans), AI::settings()['model'], "$n votes", $callId]);
        return $n;
    }
}
