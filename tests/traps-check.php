<?php
// Honeypots: only the 300 best are active (docs/security-ai-improvements.md §1). Run by
// tests/smoke.sh against the throwaway smoke database; it replaces the traps it finds.
declare(strict_types=1);
require '/src/app/lib/bootstrap.php';
putenv('PSPM_ACTOR=traps-check');
function check(bool $c, string $what): void { echo ($c ? 'ok   ' : 'FAIL ') . $what . "\n"; if (!$c) exit(1); }
$val = fn(string $sql, array $a = []) => DB::val($sql, $a);

// the score
$now = time();
check(Traps::score('fast', '*', 10, $now) === 18.0, 'score: 10 attackers × 1.5 (fast) × 1.2 (all hosts) × 1.0 (seen this week) = 18');
check(Traps::score('standard', 'app.example.ch', 10, $now - 10 * 86400) === 5.0, 'score: seen 10 days ago counts half');
check(Traps::score('standard', 'app.example.ch', 10, 0) === 2.0, 'score: never seen counts 0.2');

// 310 eligible traps with scores 1…310, and 2 pinned ones with a low score
DB::q('DELETE FROM traps');
for ($i = 1; $i <= 310; $i++) {
    DB::q("INSERT INTO traps (host, kind, path, state, score, eligible_at, shadow_since, created_by) VALUES ('*', 'exact', ?, 'shadow', ?, now(), now(), 'test')", ["/t$i", $i]);
}
DB::q("INSERT INTO traps (host, kind, path, state, score, pinned, eligible_at, created_by) VALUES ('*', 'exact', '/pin-1', 'shadow', 0.5, true, now(), 'test'), ('*', 'exact', '/pin-2', 'shadow', 0.5, true, now(), 'test')");
$r = Traps::rank(false);
check((int)$val("SELECT count(*) FROM traps WHERE state = 'active'") === 300, 'exactly 300 traps are active');
check((int)$val("SELECT count(*) FROM traps WHERE pinned AND state = 'active'") === 2, 'pinned traps are always active, even with a low score');
check((float)$val("SELECT min(score) FROM traps WHERE state = 'active' AND NOT pinned") === 13.0, 'the 298 best by score fill the other places');
check($val("SELECT rank FROM traps WHERE path = '/t310'") == 3 && $val("SELECT rank FROM traps WHERE path = '/t1'") == 312, 'ranks: pinned first, then by score');

// the 20 % margin, and swaps only in the daily ranking
DB::q("UPDATE traps SET score = 15 WHERE path = '/t12'");   // worst active is 13; 15 < 13 × 1.2
Traps::rank(true);
check($val("SELECT state FROM traps WHERE path = '/t12'") === 'shadow', 'a waiting trap only a little better does not take a place (20 % margin)');
DB::q("UPDATE traps SET score = 1000 WHERE path = '/t11'");
Traps::rank(false);
check($val("SELECT state FROM traps WHERE path = '/t11'") === 'shadow', 'between daily rankings, nothing is swapped (only free places are filled)');
Traps::rank(true);
check($val("SELECT state FROM traps WHERE path = '/t11'") === 'active' && $val("SELECT state FROM traps WHERE path = '/t13'") === 'shadow'
    && (int)$val("SELECT count(*) FROM traps WHERE state = 'active'") === 300, 'the daily ranking swaps a much better trap in for the worst active one');

// an admin cannot go beyond 300; moving a trap to shadow makes it earn its place again
try { Traps::setState((int)$val("SELECT id FROM traps WHERE path = '/t13'"), 'active'); check(false, 'over 300'); }
catch (InvalidArgumentException $e) { check(str_contains($e->getMessage(), '300 traps are active'), 'activating by hand is refused at 300'); }
Traps::setState((int)$val("SELECT id FROM traps WHERE path = '/t310'"), 'shadow');
check($val("SELECT state FROM traps WHERE path = '/t310'") === 'shadow' && $val("SELECT eligible_at FROM traps WHERE path = '/t310'") === null
    && (int)$val("SELECT count(*) FROM traps WHERE state = 'active'") === 300, 'moved to shadow by hand: it earns its place again; the best waiting one takes the free place');

// the scan round: a trap that passed its shadow period becomes eligible and waits for a place
DB::q("INSERT INTO traps (host, kind, path, state, shadow_since, created_by) VALUES ('*', 'exact', '/late', 'shadow', now() - interval '13 hours', 'test')");
Traps::maintain(false);
check($val("SELECT eligible_at FROM traps WHERE path = '/late'") !== null && $val("SELECT state FROM traps WHERE path = '/late'") === 'shadow'
    && $val("SELECT rank FROM traps WHERE path = '/late'") !== null, 'after its shadow period a trap is eligible and ranked; with no free place it waits');

// the breaker: too many trap blocks in an hour puts every unpinned trap back into shadow
DB::q("INSERT INTO block_history (ip, source, reason, duration_secs, created_by) SELECT ('203.0.113.' || g)::cidr, 'trap', 'test', 86400, 'system' FROM generate_series(1, 200) g");
Traps::maintain(false);
check((int)$val("SELECT count(*) FROM traps WHERE state = 'active'") === 2, 'breaker: only the pinned traps stay active');
DB::q("DELETE FROM block_history WHERE source = 'trap' AND reason = 'test'");
DB::q('DELETE FROM traps');
echo "traps checks passed\n";
