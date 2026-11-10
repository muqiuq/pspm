<?php
declare(strict_types=1);

/**
 * Behaviour analysis (plan §15.7): deterministic features and detectors per actor (address,
 * certificate, signed-in user, access-link grant); the AI only assesses. Authorised actors
 * are reported, never blocked automatically; risky untrusted addresses are blocked when
 * nobody reacts within the reaction time.
 */
final class Behaviour
{
    public const PATTERNS = [
        'brute_force' => 'Brute force or credential stuffing at a backend',
        'enumeration' => 'Enumeration',
        'scraping' => 'Scraping or bulk download',
        'shared_credential' => 'Shared or stolen credential',
        'leaked_link' => 'Leaked access link',
        'probing' => 'Probing beyond its scope',
        'changed' => 'Changed behaviour',
        'distributed' => 'Distributed attack on one site',
        'ai_disputed' => 'AI models disagree on a block',
    ];

    /** Sum the hourly feature rows of the last $hours for every actor. */
    private static function window(int $hours): array
    {
        $out = [];
        foreach (DB::all('SELECT actor_type, actor, hour, data FROM behaviour_hours WHERE hour > now() - make_interval(hours => ?)', [$hours]) as $r) {
            $k = $r['actor_type'] . '|' . $r['actor'];
            $d = json_dec($r['data']);
            $o = &$out[$k];
            $o ??= ['type' => $r['actor_type'], 'actor' => $r['actor'], 'req' => 0, 'bytes' => 0, 'denied' => 0, 's404' => 0, 'ust401' => 0, 'posts' => 0,
                'paths' => [], 'p404' => [], 'sites' => [], 'dsites' => [], 'ips' => [], 'uas' => [], 'login401' => [], 'hours' => [], 'max_hour_req' => 0, 'regular' => 0];
            foreach (['req', 'bytes', 'denied', 's404', 'ust401', 'posts'] as $f) $o[$f] += (int)($d[$f] ?? 0);
            foreach (['paths', 'sites', 'dsites', 'login401'] as $f) foreach ((array)($d[$f] ?? []) as $x => $n) $o[$f][$x] = ($o[$f][$x] ?? 0) + (int)$n;
            foreach (['p404', 'ips', 'uas'] as $f) foreach (array_keys((array)($d[$f] ?? [])) as $x) $o[$f][$x] = true;
            $o['hours'][(int)gmdate('G', strtotime($r['hour']))] = true;
            $o['max_hour_req'] = max($o['max_hour_req'], (int)($d['req'] ?? 0));
            $mins = array_values((array)($d['mins'] ?? []));
            if (array_sum($mins) >= 120) {   // machine-regular: busy in (almost) every minute with little variance
                $mean = array_sum($mins) / 60;
                $var = array_sum(array_map(fn($x) => ($x - $mean) ** 2, $mins)) / 60;
                if ($mean > 0 && sqrt($var) / $mean < 0.25) $o['regular']++;
            }
            unset($o);
        }
        return $out;
    }

    private static function baseline(string $type, string $actor): ?array
    {
        $v = DB::val('SELECT data FROM behaviour_baselines WHERE actor_type = ? AND actor = ?', [$type, $actor]);
        return $v ? json_dec($v) : null;
    }

    /** Rolling 30-day baselines for authorised actors (once a day). */
    private static function updateBaselines(): void
    {
        $last = SecScan::state('baselines');
        if ($last && time() - strtotime($last['at']) < 86400) return;
        $rows = DB::all("SELECT actor_type, actor, hour, data FROM behaviour_hours WHERE actor_type <> 'ip' AND hour > now() - interval '30 days' AND hour < now() - interval '24 hours'");
        $b = [];
        foreach ($rows as $r) {
            $k = $r['actor_type'] . '|' . $r['actor'];
            $d = json_dec($r['data']);
            $b[$k]['type'] = $r['actor_type']; $b[$k]['actor'] = $r['actor'];
            $b[$k]['req'][] = (int)($d['req'] ?? 0);
            $b[$k]['hours'][(int)gmdate('G', strtotime($r['hour']))] = true;
            foreach (array_keys((array)($d['paths'] ?? [])) as $p) $b[$k]['paths'][$p] = true;
            foreach (array_keys((array)($d['uas'] ?? [])) as $p) $b[$k]['uas'][$p] = true;
            $b[$k]['ips_per_hour'][] = count((array)($d['ips'] ?? []));
        }
        foreach ($b as $x) {
            $n = count($x['req']);
            $mean = array_sum($x['req']) / max(1, $n);
            $sd = sqrt(array_sum(array_map(fn($v) => ($v - $mean) ** 2, $x['req'])) / max(1, $n));
            DB::q('INSERT INTO behaviour_baselines (actor_type, actor, data, updated_at) VALUES (?, ?, ?::jsonb, now())
                   ON CONFLICT (actor_type, actor) DO UPDATE SET data = excluded.data, updated_at = now()',
                [$x['type'], $x['actor'], json_enc(['hours_seen' => $n, 'req_mean' => $mean, 'req_sd' => $sd, 'hours' => array_keys($x['hours']),
                    'paths' => array_slice(array_keys($x['paths'] ?? []), 0, 300), 'uas' => array_slice(array_keys($x['uas'] ?? []), 0, 20),
                    'max_ips_per_hour' => max($x['ips_per_hour'] ?? [0])])]);
        }
        SecScan::setState('baselines', ['at' => gmdate('c')]);
    }

    /** Is this actor authorised (certificate, user, link) or a trusted/authorised address? */
    private static function authorised(string $type, string $actor): bool
    {
        if ($type !== 'ip') return true;
        return Blocks::trusted(explode('/', $actor)[0]);
    }

    /** @return list<array{pattern:string, risk:int, class:string, evidence:array}> */
    private static function detect(array $a, ?array $base): array
    {
        $f = [];
        $loginFails = $a['login401'] ? max($a['login401']) : 0;
        if ($loginFails >= 20) $f[] = ['brute_force', min(95, 40 + $loginFails), $loginFails >= 100 ? 'attack' : 'risky', ['login_failures' => $loginFails, 'paths' => array_slice(array_keys($a['login401']), 0, 5)]];
        if (count($a['p404']) >= 50) $f[] = ['enumeration', min(90, 30 + count($a['p404']) / 5), count($a['p404']) >= 300 ? 'attack' : 'risky', ['distinct_404' => count($a['p404'])]];
        $threshold = max(2000, ($base['req_mean'] ?? 0) * 10);
        if ($a['max_hour_req'] >= $threshold || $a['bytes'] >= 5 * (1 << 30) || $a['regular'] >= 3) {
            $f[] = ['scraping', 50, 'risky', ['max_requests_per_hour' => $a['max_hour_req'], 'bytes' => $a['bytes'], 'regular_hours' => $a['regular']]];
        }
        if ($a['type'] !== 'ip') {
            $ips = count($a['ips']);
            $usual = (int)($base['max_ips_per_hour'] ?? 1);
            if ($ips >= max(3, $usual + 2)) $f[] = ['shared_credential', 70, 'risky', ['networks' => $ips, 'usual' => $usual]];
            if ($a['type'] === 'link' && $ips >= 5) $f[] = ['leaked_link', 75, 'risky', ['networks' => $ips]];
            if (array_sum($a['dsites']) >= 10) $f[] = ['probing', 60, 'risky', ['denials_on_other_sites' => array_sum($a['dsites'])]];
            if ($base && ($base['hours_seen'] ?? 0) >= 24) {
                $newHours = array_diff(array_keys($a['hours']), $base['hours'] ?? []);
                $newPaths = array_diff(array_keys($a['paths']), $base['paths'] ?? []);
                $spike = ($base['req_sd'] ?? 0) > 0 && $a['max_hour_req'] > ($base['req_mean'] + 3 * $base['req_sd']) && $a['max_hour_req'] > 100;
                if (($newHours && $spike) || count($newPaths) >= 20) $f[] = ['changed', 45, 'risky', ['new_hours' => array_values($newHours), 'new_paths' => count($newPaths), 'spike' => $spike]];
            }
        }
        return array_map(fn($x) => ['pattern' => $x[0], 'risk' => (int)$x[1], 'class' => $x[2], 'evidence' => $x[3]], $f);
    }

    public const DEFAULT_INTERVAL_HOURS = 12;

    /** Hours between two searches for findings (Settings → Blocking and trust; default 12). */
    public static function intervalHours(): int
    {
        return max(1, min(168, (int)(Settings::get('behaviour', [])['interval_hours'] ?? self::DEFAULT_INTERVAL_HOURS)));
    }

    /** When the search for findings ran last and is due next (Unix times; null: never ran). */
    public static function lastSearch(): ?int
    {
        $last = SecScan::state('behaviour_search');
        return $last ? (strtotime((string)$last['at']) ?: null) : null;
    }

    public static function nextSearch(): ?int
    {
        $last = self::lastSearch();
        return $last === null ? null : $last + 3600 * self::intervalHours();
    }

    /**
     * The behaviour part of a scan round (plan §15.7): the search for findings runs every
     * intervalHours() (12 by default) or when forced ("Run now"); reaction deadlines and
     * reminders are checked every round, so a block after the reaction time is not late.
     */
    public static function analyse(int &$runBlocks, bool $force = false): array
    {
        $st = ['findings' => 0, 'assessed' => 0, 'blocked' => 0, 'reminders' => 0];
        $next = self::nextSearch();
        if ($force || $next === null || time() >= $next) {
            self::search($runBlocks, $st);
            SecScan::setState('behaviour_search', ['at' => gmdate('c')]);
        } else {
            $st['next_search'] = gmdate('c', $next);
        }
        self::deadlines($runBlocks, $st);
        return $st;
    }

    /** Detectors over the last 24 h, the AI assessment, findings and their notifications. */
    private static function search(int &$runBlocks, array &$st): void
    {
        self::updateBaselines();
        $ai = AI::settings();
        $cands = [];
        foreach (self::window(24) as $a) {
            $base = $a['type'] === 'ip' ? null : self::baseline($a['type'], $a['actor']);
            foreach (self::detect($a, $base) as $f) $cands[] = $f + ['type' => $a['type'], 'actor' => $a['actor'], 'features' => $a];
        }
        // site-level: many new addresses failing at the same site within an hour
        $siteFail = [];
        foreach (DB::all("SELECT data FROM behaviour_hours WHERE actor_type = 'ip' AND hour > now() - interval '1 hour'") as $r) {
            foreach ((array)(json_dec($r['data'])['dsites'] ?? []) as $site => $n) $siteFail[$site] = ($siteFail[$site] ?? 0) + 1;
        }
        foreach ($siteFail ?? [] as $site => $ips) {
            if ($ips >= 20) $cands[] = ['pattern' => 'distributed', 'risk' => min(90, 40 + $ips), 'class' => 'risky', 'evidence' => ['addresses' => $ips],
                'type' => 'site', 'actor' => (string)$site, 'features' => ['type' => 'site', 'req' => 0]];
        }
        // what still needs a finding: not expected, not reported in the last 24 h
        $todo = [];
        foreach ($cands as $c) {
            if (DB::val('SELECT 1 FROM expected_patterns WHERE actor_type = ? AND actor = ? AND pattern = ? AND until > now()', [$c['type'], $c['actor'], $c['pattern']])) continue;
            if (DB::val("SELECT 1 FROM risk_findings WHERE actor_type = ? AND actor = ? AND pattern = ? AND (status = 'open' OR created_at > now() - interval '24 hours')",
                [$c['type'], $c['actor'], $c['pattern']])) continue;
            $c['auth'] = self::authorised($c['type'], $c['actor']);
            if ($c['auth'] && !$ai['analyse_authorised'] && $c['type'] !== 'ip') continue;
            $todo[] = $c;
        }
        // the AI assesses them in batches of 20 (one call each, logged in the AI log)
        $assessments = $shielded = $rowIds = [];
        $ps = AI::pseudonymiser();   // one for every batch, so the verifier sees the same pseudonyms
        $sys = '';
        foreach (array_chunk($todo, 20, true) as $batch) {
            if (!AI::available()) break;
            $items = [];
            foreach ($batch as $i => $c) {
                $feat = $c['features'];
                $items[] = ['finding' => "f-$i", 'actor' => $ps->of($c['type'] === 'ip' ? 'ip' : $c['type'], $c['actor']), 'kind' => $c['type'], 'authorised' => $c['auth'],
                    'pattern' => $c['pattern'], 'deterministic_risk' => $c['risk'], 'evidence' => $c['evidence'],
                    'requests_24h' => $feat['req'] ?? 0, 'denied' => $feat['denied'] ?? 0, 'not_found' => $feat['s404'] ?? 0,
                    'backend_401_403' => $feat['ust401'] ?? 0, 'networks' => count($feat['ips'] ?? []), 'sites' => count($feat['sites'] ?? []),
                    'paths' => array_map([AI::class, 'scrubPath'], array_slice(array_keys($feat['paths'] ?? []), 0, 25)),
                    'user_agents' => array_slice(array_keys($feat['uas'] ?? []), 0, 3)];
            }
            [$items] = AI::shield($items, ['paths' => 200, 'user_agents' => 120]);   // injection check
            $sys = 'You assess behaviour seen by a reverse proxy over 24 hours. For each finding classify it: "attack" (clearly malicious), "risky" '
                . '(should be looked at by an admin), or "normal". Answer only JSON: {"assessments":[{"finding":"f-1","class":"attack|risky|normal","category":"'
                . implode('|', array_keys(self::PATTERNS)) . '|other","risk":0-100,"confidence":0.0-1.0,"reason":"short","suggested_action":"short"}]}' . AI::UNTRUSTED_NOTE;
            try {
                [$ans, $callId] = AI::call('main', 'behaviour', $sys, ['findings' => $items], $ps, 'assessments');
            } catch (Throwable $e) {
                break;   // the AI log has the error; the deterministic classes stand
            }
            foreach ((array)($ans['assessments'] ?? []) as $a) {
                if (!is_array($a) || !preg_match('/^f-(\d+)$/', (string)($a['finding'] ?? ''), $m) || !isset($batch[(int)$m[1]]) || isset($assessments[(int)$m[1]])) continue;
                $i = (int)$m[1];
                $c = $batch[$i];
                $assessments[$i] = $a;
                $st['assessed']++;
                $ev = array_values(array_filter($items, fn($x) => $x['finding'] === "f-$i"))[0] ?? [];
                $shielded[$i] = $ev;
                $rowIds[$i] = (int)DB::val("INSERT INTO ai_verdicts (kind, subject, verdict, confidence, reason, evidence, answer, model, call_id) VALUES ('behaviour', ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?) RETURNING id",
                    [$c['type'] . ':' . $c['actor'], (string)($a['class'] ?? ''), (float)($a['confidence'] ?? 0), mb_substr((string)($a['reason'] ?? ''), 0, 500),
                     json_enc($ev), json_enc($a), $ai['model'], $callId]);
            }
        }
        // the verifier confirms every immediate block (docs/security-ai-improvements.md §3)
        $verified = [];
        $verifyFailed = false;
        $toVerify = [];
        if (AI::configured('verify')) {
            foreach ($todo as $i => $c) {
                $a = $assessments[$i] ?? null;
                if (!$a || ($a['class'] ?? '') !== 'attack' || $c['type'] !== 'ip' || $c['auth'] || !isset($shielded[$i])) continue;
                if (Blocks::guard(explode('/', $c['actor'])[0], 'block', (float)($a['confidence'] ?? 0)) === null) $toVerify[$i] = $shielded[$i];
            }
        }
        if ($toVerify) {
            $verifyCall = null;
            try {
                if (!AI::available('verify')) throw new RuntimeException('verification model not available');
                [$vans, $verifyCall] = AI::call('verify', 'verify', $sys . AI::VERIFY_NOTE, ['findings' => array_values($toVerify)], $ps, 'assessments');
                foreach ((array)($vans['assessments'] ?? []) as $x) {
                    if (!is_array($x) || !preg_match('/^f-(\d+)$/', (string)($x['finding'] ?? ''), $m) || !isset($toVerify[(int)$m[1]]) || isset($verified[(int)$m[1]])) continue;
                    $verified[(int)$m[1]] = ['class' => (string)($x['class'] ?? ''), 'confidence' => max(0.0, min(1.0, (float)($x['confidence'] ?? 0))), 'reason' => (string)($x['reason'] ?? '')];
                }
            } catch (Throwable) {
                $verifyFailed = true;   // the AI log has the error; no immediate block
            }
            foreach ($toVerify as $i => $_) {
                $vv = $verified[$i] ?? null;
                DB::q('UPDATE ai_verdicts SET verify_verdict = ?, verify_confidence = ?, verify_reason = ?, verify_model = ?, verify_call_id = ? WHERE id = ?',
                    [$vv['class'] ?? 'error', $vv['confidence'] ?? null, isset($vv['reason']) ? mb_substr($vv['reason'], 0, 500) : null, AI::model('verify')['model'], $verifyCall, $rowIds[$i]]);
            }
        }
        foreach ($todo as $i => $c) {
            $auth = $c['auth'];
            $assessment = $assessments[$i] ?? null;
            $class = $c['class'];
            $risk = $c['risk'];
            $conf = null;
            if ($assessment) {
                $class = in_array($assessment['class'] ?? '', ['attack', 'risky', 'normal'], true) ? $assessment['class'] : $class;
                $risk = max(0, min(100, (int)($assessment['risk'] ?? $risk)));
                $conf = (float)($assessment['confidence'] ?? 0);
            }
            if ($class === 'normal') continue;
            $status = 'open';
            $deadline = null;
            if ($c['type'] === 'ip' && !$auth) {
                $ip = explode('/', $c['actor'])[0];
                if ($class === 'attack') {
                    $why = Blocks::guard($ip, 'block', $conf ?? 0.0);
                    $vv = $verified[$i] ?? null;
                    $ok = !isset($toVerify[$i]) || ($vv && $vv['class'] === 'attack' && $vv['confidence'] >= (float)$ai['confidence']);   // the verifier agrees
                    if (isset($toVerify[$i])) $assessment['verifier'] = $vv ?? ['error' => $verifyFailed ? 'no answer from the verification model' : 'not in the answer'];
                    if ($why === null && $ok && Blocks::auto($ip, 'behaviour', self::PATTERNS[$c['pattern']] . ' (attack' . ($vv ? ', verified' : '') . ')', $runBlocks) === 'blocked') { $status = 'blocked'; $st['blocked']++; }
                    elseif ($why !== null || $conf === null || !$ok) $deadline = gmdate('c', time() + 3600 * (int)$ai['reaction_hours']);
                } else {
                    $deadline = gmdate('c', time() + 3600 * (int)$ai['reaction_hours']);
                }
            }
            $id = (int)DB::val('INSERT INTO risk_findings (actor_type, actor, pattern, class, risk, confidence, authorised, status, deadline, evidence, ai)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb) RETURNING id',
                [$c['type'], $c['actor'], $c['pattern'], $class, $risk, $conf, $auth, $status, $deadline, json_enc($c['evidence']), $assessment ? json_enc($assessment) : null]);
            $st['findings']++;
            $label = self::PATTERNS[$c['pattern']];
            $who = self::describe($c['type'], $c['actor']);
            Notify::event('findings', ($auth ? 'Authorised actor: ' : '') . "$label — $who",
                "Finding #$id: $label\nActor: $who" . ($auth ? ' (authorised: never blocked automatically)' : '') . "\nClass: $class, risk $risk"
                . ($assessment['reason'] ?? '' ? "\nAssessment: " . $assessment['reason'] : '') . "\nEvidence: " . json_enc($c['evidence'])
                . ($deadline ? "\n\nNobody reacted: the address is blocked at " . fmt_time($deadline, 'Y-m-d H:i') . ". React on Security → Behaviour." : ''),
                "finding:$id");
        }
    }

    /** Reminders 2 h before the deadline, blocks when it has passed (plan §15.7). */
    private static function deadlines(int &$runBlocks, array &$st): void
    {
        foreach (DB::all("SELECT * FROM risk_findings WHERE status = 'open' AND deadline IS NOT NULL") as $f) {
            $left = strtotime($f['deadline']) - time();
            $n = json_dec($f['notified']) ?? [];
            if ($left > 0 && $left <= 7200 && empty($n['reminder'])) {
                Notify::event('findings', 'Reminder: blocks in ' . human_secs($left) . ' — ' . self::describe($f['actor_type'], $f['actor']),
                    "Finding #{$f['id']} (" . self::PATTERNS[$f['pattern']] . ") has no reaction yet. The address is blocked at " . fmt_time($f['deadline'], 'Y-m-d H:i') . '.', "finding:{$f['id']}:reminder");
                DB::q("UPDATE risk_findings SET notified = notified || '{\"reminder\": true}'::jsonb WHERE id = ?", [$f['id']]);
                $st['reminders']++;
            }
            if ($left <= 0) {
                $ip = explode('/', $f['actor'])[0];
                $why = Blocks::guard($ip, 'block', 1.0, false);   // the missing reaction is the decision
                $out = $why ?? Blocks::auto($ip, 'behaviour', 'risky behaviour, no reaction: ' . self::PATTERNS[$f['pattern']], $runBlocks);
                DB::q("UPDATE risk_findings SET status = ?, note = ?, updated_at = now() WHERE id = ?", [$out === 'blocked' ? 'blocked' : 'closed', "deadline: $out", $f['id']]);
                if ($out === 'blocked') {
                    $st['blocked']++;
                    Notify::event('findings', 'Blocked (no reaction): ' . self::describe($f['actor_type'], $f['actor']), "Finding #{$f['id']}: nobody reacted, so the address is now blocked.", "finding:{$f['id']}:blocked");
                }
            }
        }
    }

    public static function describe(string $type, string $actor): string
    {
        return match ($type) {
            'ip' => "address $actor",
            'cert' => 'certificate ' . (DB::val('SELECT subject_cn FROM client_certs WHERE fingerprint_sha1 = ?', [$actor]) ?? substr($actor, 0, 12) . '…'),
            'user' => "user $actor",
            'link' => 'access link ' . (DB::val('SELECT label FROM access_links WHERE id = ?', [$actor]) ?? $actor),
            'site' => 'site ' . (DB::val('SELECT name FROM sites WHERE id = ?', [$actor]) ?? $actor),
            default => "$type $actor",
        };
    }

    /** Admin reactions (plan §15.7). */
    public static function act(int $id, string $action, string $note = ''): string
    {
        $f = DB::one('SELECT * FROM risk_findings WHERE id = ?', [$id]);
        if (!$f) throw new InvalidArgumentException('No such finding.');
        $msg = '';
        switch ($action) {
            case 'expected':
                DB::q("INSERT INTO expected_patterns (actor_type, actor, pattern, until) VALUES (?, ?, ?, now() + interval '30 days')
                       ON CONFLICT (actor_type, actor, pattern) DO UPDATE SET until = excluded.until", [$f['actor_type'], $f['actor'], $f['pattern']]);
                $status = 'expected'; $msg = 'Marked as expected for 30 days.';
                break;
            case 'block':
                if ($f['actor_type'] !== 'ip') throw new InvalidArgumentException('Only addresses can be blocked.');
                Blocks::add($f['actor'], 'behaviour', 'finding #' . $id . ': ' . self::PATTERNS[$f['pattern']], 7 * 86400, true, Audit::actor());
                State::publish('blocked');
                $status = 'acted'; $msg = 'Blocked for 7 days.';
                break;
            case 'revoke_cert':
                $cid = DB::val('SELECT id FROM client_certs WHERE fingerprint_sha1 = ?', [$f['actor']]);
                if (!$cid) throw new InvalidArgumentException('Not a certificate finding.');
                PKI::revoke($cid, "finding #$id");
                $status = 'acted'; $msg = 'Certificate revoked.';
                break;
            case 'revoke_link':
                if ($f['actor_type'] !== 'link') throw new InvalidArgumentException('Not an access-link finding.');
                Access::revokeLink($f['actor']);
                $status = 'acted'; $msg = 'Link revoked; its clearances ended.';
                break;
            case 'end_clearance':
                DB::q('DELETE FROM cleared_ips WHERE ip >>= ?::inet', [explode('/', $f['actor'])[0]]);
                State::publish('cleared');
                $status = 'acted'; $msg = 'Clearances of this address ended.';
                break;
            case 'close':
                $status = 'closed'; $msg = 'Closed.';
                break;
            default:
                throw new InvalidArgumentException('Unknown action.');
        }
        DB::q('UPDATE risk_findings SET status = ?, acted_by = ?, acted_at = now(), note = ?, updated_at = now() WHERE id = ?', [$status, Audit::actor(), $note ?: $action, $id]);
        Audit::log('finding.' . $action, "finding:$id");
        return $msg;
    }
}
