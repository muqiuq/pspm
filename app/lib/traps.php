<?php
declare(strict_types=1);

/**
 * Honeypots (plan §15.5): request paths only attackers ask for. The first request to an
 * active trap from an untrusted address blocks it at once (block.lua); the fast pass makes
 * the block permanent-ish and puts it into the firewall.
 */
final class Traps
{
    public const MAX_ACTIVE = 300;         // only the 300 best are active (docs/security-ai-improvements.md §1)
    public const SWAP_MARGIN = 1.2;        // a waiting trap replaces an active one only with a 20 % higher score
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

    /**
     * An admin's decision. Activating makes the trap eligible (the daily ranking can still let a
     * better one take its place unless it is pinned); moving it to shadow makes it earn its
     * shadow period again, so the ranking does not bring it straight back.
     */
    public static function setState(int $id, string $state): void
    {
        if ($state === 'active') {
            $t = DB::one('SELECT * FROM traps WHERE id = ?', [$id]);
            if (!$t || $t['state'] === 'rejected') throw new InvalidArgumentException('A rejected trap cannot be activated: a backend serves this path.');
            if ((int)DB::val("SELECT count(*) FROM traps WHERE state = 'active'") >= self::MAX_ACTIVE) {
                throw new InvalidArgumentException(self::MAX_ACTIVE . ' traps are active already (the best by score). Disable one first, or wait for the daily ranking.');
            }
        }
        DB::q("UPDATE traps SET state = ?, shadow_since = CASE WHEN ? = 'shadow' THEN now() ELSE shadow_since END,
                 eligible_at = CASE WHEN ? = 'active' THEN coalesce(eligible_at, now()) WHEN ? = 'shadow' THEN NULL ELSE eligible_at END,
                 updated_at = now() WHERE id = ?", [$state, $state, $state, $state, $id]);
        Audit::log('trap.' . $state, "trap:$id");
        self::rank(false);
        State::publish('traps');
    }

    /** Pin or unpin: pinned traps are always active and count towards the 300. */
    public static function pin(int $id): bool
    {
        $pinned = (bool)DB::val('SELECT pinned FROM traps WHERE id = ?', [$id]);
        if (!$pinned && (int)DB::val('SELECT count(*) FROM traps WHERE pinned') >= self::MAX_ACTIVE) {
            throw new InvalidArgumentException('At most ' . self::MAX_ACTIVE . ' pinned traps.');
        }
        DB::q("UPDATE traps SET pinned = NOT pinned, eligible_at = coalesce(eligible_at, now()), updated_at = now() WHERE id = ? AND state NOT IN ('rejected', 'disabled', 'retired')", [$id]);
        Audit::log($pinned ? 'trap.unpin' : 'trap.pin', "trap:$id");
        self::rank(false);
        State::publish('traps');
        return !$pinned;
    }

    /** Score over 30 days: distinct attackers × 1.5 on the fast track × 1.2 for scope "*" × recency. */
    public static function score(string $track, string $host, int $attackers, int $lastSeen): float
    {
        $age = time() - $lastSeen;
        $recency = $lastSeen <= 0 ? 0.2 : ($age <= 7 * 86400 ? 1.0 : ($age <= 30 * 86400 ? 0.5 : 0.2));
        return round($attackers * ($track === 'fast' ? 1.5 : 1.0) * ($host === '*' ? 1.2 : 1.0) * $recency, 3);
    }

    /**
     * Only the 300 best are active. Pinned traps always are and count towards the 300. Free
     * places are filled every round with the best eligible traps; with $swap (once a day and
     * after mining) a waiting trap takes the place of the worst active one when its score is
     * at least 20 % higher, so traps do not flap. Writes each trap's rank.
     * @return array{activated: int, deactivated: int}
     */
    public static function rank(bool $swap, bool $activate = true): array
    {
        $r = ['activated' => 0, 'deactivated' => 0];
        $pinned = $active = $waiting = [];
        foreach (DB::all("SELECT id, state, pinned, score, eligible_at FROM traps WHERE state IN ('active', 'shadow')") as $t) {
            $t['score'] = (float)$t['score'];
            if ($t['pinned']) $pinned[] = $t;
            elseif ($t['state'] === 'active') $active[] = $t;
            elseif ($t['eligible_at'] !== null) $waiting[] = $t;
        }
        $desc = fn($a, $b) => [$b['score'], $a['id']] <=> [$a['score'], $b['id']];
        usort($active, $desc);
        usort($waiting, $desc);
        $set = function (array $t, string $state) use (&$r) {
            DB::q('UPDATE traps SET state = ?, updated_at = now() WHERE id = ?', [$state, $t['id']]);
            $r[$state === 'active' ? 'activated' : 'deactivated']++;
        };
        foreach ($pinned as $t) if ($t['state'] !== 'active') $set($t, 'active');   // pinned: always active
        $slots = max(0, self::MAX_ACTIVE - count($pinned));
        while (count($active) > $slots) { $t = array_pop($active); $set($t, 'shadow'); $waiting[] = $t; }   // fewer places than active traps
        usort($waiting, $desc);
        if ($activate) {
            while (count($active) < $slots && $waiting) { $t = array_shift($waiting); $set($t, 'active'); $active[] = $t; }
            while ($swap && $active && $waiting) {
                $worst = $active[count($active) - 1];
                $best = $waiting[0];
                if (!($best['score'] > $worst['score'] && $best['score'] >= self::SWAP_MARGIN * $worst['score'])) break;
                array_pop($active); array_shift($waiting);
                $set($worst, 'shadow'); $set($best, 'active');
                $active[] = $best; $waiting[] = $worst;
                usort($active, $desc); usort($waiting, $desc);
            }
        }
        // ranks: pinned first, then every active and waiting trap by score
        usort($pinned, $desc);
        $all = array_merge($pinned, (function () use ($active, $waiting, $desc) { $x = array_merge($active, $waiting); usort($x, $desc); return $x; })());
        $ids = array_map(fn($t) => (int)$t['id'], $all);
        DB::q('UPDATE traps SET rank = NULL WHERE rank IS NOT NULL AND NOT (id = ANY (CAST(? AS bigint[])))', ['{' . implode(',', $ids) . '}']);
        if ($ids) DB::q('UPDATE traps t SET rank = v.r FROM unnest(CAST(? AS bigint[]), CAST(? AS int[])) AS v(id, r) WHERE t.id = v.id AND t.rank IS DISTINCT FROM v.r',
            ['{' . implode(',', $ids) . '}', '{' . implode(',', range(1, count($ids))) . '}']);
        return $r;
    }

    /** Lifecycle, safety and mining; run by the full scan round. */
    public static function maintain(bool $runNow = false): array
    {
        $st = ['activated' => 0, 'deactivated' => 0, 'disabled' => 0, 'retired' => 0, 'mined' => 0];
        if (!self::enabled()) return $st + ['enabled' => false];
        // breaker: too many trap blocks in an hour puts every trap back into shadow (they earn their place again)
        $hour = (int)DB::val("SELECT count(*) FROM block_history WHERE source = 'trap' AND created_at > now() - interval '1 hour'");
        if ($hour >= self::BREAKER_PER_HOUR) {
            DB::q("UPDATE traps SET state = 'shadow', shadow_since = now(), eligible_at = NULL WHERE state = 'active' AND NOT pinned");
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
            [$attackers, $lastDay] = self::attackers($t['host'], $t['kind'], $t['path']);
            $lastSeen = max((int)strtotime((string)($t['last_hit_at'] ?? '')), $lastDay ? (int)strtotime("$lastDay 23:59:59 UTC") : 0);
            DB::q('UPDATE traps SET track = ?, attackers = ?, score = ? WHERE id = ?', [$ev, $attackers, self::score($ev, $t['host'], $attackers, $lastSeen), $t['id']]);
            if ($t['state'] === 'proposed' && (int)$t['votes'] >= $tr['votes'] && $attackers >= $tr['attackers']) {
                DB::q("UPDATE traps SET state = 'shadow', shadow_since = now(), updated_at = now() WHERE id = ?", [$t['id']]);
            } elseif ($t['state'] === 'shadow' && $t['eligible_at'] === null && $t['shadow_since'] && time() - strtotime($t['shadow_since']) >= $tr['shadow_secs']
                && $hour < self::BREAKER_PER_HOUR) {
                DB::q('UPDATE traps SET eligible_at = now() WHERE id = ?', [$t['id']]);   // the ranking decides whether it is active
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
        $mined = false;
        if (($runNow || !$last || time() - strtotime($last['at']) >= 3 * 3600) && $refused > 0 && AI::available()) {
            $st['mined'] = self::mine();
            SecScan::setState('last_mining', ['at' => gmdate('c')]);
            $mined = true;
        }
        // the 300 best: free places every round; swaps once a day and after mining
        $lastRank = SecScan::state('last_trap_ranking');
        $daily = $runNow || $mined || !$lastRank || time() - strtotime($lastRank['at']) >= 86400;
        $r = self::rank($daily, $hour < self::BREAKER_PER_HOUR);
        if ($daily) SecScan::setState('last_trap_ranking', ['at' => gmdate('c')]);
        $st['activated'] += $r['activated'];
        $st['deactivated'] += $r['deactivated'];
        return $st;
    }

    /** Distinct attacking addresses over 30 days (trap hits included), and the last day one was seen. */
    private static function attackers(string $host, string $kind, string $path): array
    {
        $where = $kind === 'exact' ? 'path = ?' : 'path LIKE ?';
        $arg = $kind === 'exact' ? $path : str_replace(['%', '_'], ['\%', '\_'], $path) . '%';
        $ips = [];
        $last = null;
        foreach (DB::all("SELECT day::text AS day, data FROM attack_paths WHERE $where" . ($host === '*' ? '' : ' AND host = ?') . " AND day > now() - interval '30 days'",
            $host === '*' ? [$arg] : [$arg, $host]) as $r) {
            foreach (array_keys(json_dec($r['data'])['ips'] ?? []) as $ip) $ips[$ip] = true;
            if ($last === null || $r['day'] > $last) $last = $r['day'];
        }
        return [count($ips), $last];
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
            $items[] = ['host' => $ps->of('host', $r['host']), 'path' => [AI::scrubPath($r['path'])], 'requests' => $d['total'] ?? 0,
                'refused' => $d['refused'] ?? 0, 'backend_answers' => $d['ust'] ?? new stdClass(), 'clients' => count($d['ips'] ?? [])];
        }
        [$items] = AI::shield($items, ['path' => 200]);   // injection check; without one only path-shaped strings
        $items = array_values(array_filter($items, fn($x) => ($x['untrusted']['path'] ?? []) !== [] && $x['untrusted']['path'][0] !== AI::REMOVED));
        if (!$items) return 0;
        $sys = 'You design honeypot rules for a reverse proxy. From refused request paths, propose patterns that only attackers request '
            . '(e.g. /.env, /.git/config, /wp-login.php on sites without WordPress). Never propose paths a real application may serve, '
            . 'or anything a backend answered with something other than 404/410. Answer only JSON: {"patterns":[{"host":"host-1 or *",'
            . '"kind":"exact|prefix","path":"/...","reason":"short"}]}' . AI::UNTRUSTED_NOTE;
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
