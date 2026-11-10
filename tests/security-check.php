<?php
// Security checks against the smoke-test database (run by tests/smoke.sh).
declare(strict_types=1);
$log = '/tmp/pspm-security.log';
putenv("PSPM_SECLOG=$log");
require '/src/app/lib/bootstrap.php';
putenv('PSPM_ACTOR=security-check');
function check(bool $c, string $what): void { echo ($c ? 'ok   ' : 'FAIL ') . $what . "\n"; if (!$c) exit(1); }
$now = time();
$lines = [];
$l = fn(array $x) => json_enc($x + ['t' => gmdate('c', $now), 'host' => 'app.example.ch', 'site' => '', 'port' => '443', 'm' => 'GET', 'st' => '404', 'ust' => '', 'ua' => 'curl/8', 'bs' => '200', 'out' => 'denied']);
// a scanner: trap hit (nginx already blocked it) and exploit paths
$lines[] = $l(['ip' => '198.51.200.10', 'uri' => '/.env', 'nuri' => '/.env', 'out' => 'trap:1']);
for ($i = 0; $i < 30; $i++) $lines[] = $l(['ip' => '198.51.200.11', 'uri' => "/wp-login.php?x=$i", 'nuri' => '/wp-login.php']);
// unknown host names
$lines[] = $l(['ip' => '198.51.200.12', 'host' => 'nope.test', 'uri' => '/', 'nuri' => '/', 'out' => 'unknown-block', 'st' => '444']);
// a certificate holder used from 4 networks: shared credential (authorised: never blocked)
foreach (['100.1.0.5', '100.2.0.5', '100.3.0.5', '100.4.0.5'] as $ip) for ($i = 0; $i < 3; $i++) $lines[] = $l(['ip' => $ip, 'uri' => '/', 'nuri' => '/', 'st' => '200', 'out' => 'cert', 'fp' => str_repeat('ab', 20)]);
// brute force at a backend login
for ($i = 0; $i < 40; $i++) $lines[] = $l(['ip' => '198.51.200.13', 'm' => 'POST', 'uri' => '/login', 'nuri' => '/login', 'st' => '401', 'ust' => '401', 'out' => 'public']);
// a private address must never be blocked
$lines[] = $l(['ip' => '192.168.5.5', 'uri' => '/.env', 'nuri' => '/.env', 'out' => 'trap:1']);
file_put_contents($log, implode("\n", $lines) . "\n");
DB::q("INSERT INTO traps (id, host, kind, path, state, created_by) VALUES (1, '*', 'exact', '/.env', 'active', 'test') ON CONFLICT DO NOTHING");
DB::val("SELECT setval('traps_id_seq', greatest((SELECT max(id) FROM traps), 1))");   // the fixed id above must not collide with new traps
$r = SecScan::run(true);
check($r['lines'] === count($lines), 'every log line was read (' . $r['lines'] . ')');
check(Blocks::isBlocked('198.51.200.10/32'), 'trap hit is a lasting block');
check(DB::val("SELECT source FROM blocks WHERE ip = '198.51.200.12/32'") === 'unknown-host', 'unknown-host block recorded');
check(!Blocks::isBlocked('192.168.5.5/32'), 'a private address is never blocked');
check((int)DB::val('SELECT hits FROM traps WHERE id = 1') >= 1, 'trap hits counted');
check(DB::val("SELECT kind FROM trusted_ips WHERE ip = '100.1.0.5/32'") === 'authorised', 'certificate holder is authorised in the trust registry');
check((int)DB::val("SELECT count(*) FROM ip_activity") >= 5, 'activity aggregated');
$f = DB::one("SELECT * FROM risk_findings WHERE pattern = 'brute_force'");
check($f && $f['actor'] === '198.51.200.13/32' && $f['deadline'] !== null && !$f['authorised'], 'brute force finding with a reaction deadline');
$g = DB::one("SELECT * FROM risk_findings WHERE pattern = 'shared_credential'");
check($g && $g['authorised'] && $g['deadline'] === null, 'shared certificate: an authorised finding without a deadline');
$r2 = SecScan::run(true);
check($r2['lines'] === 0, 'the cursor does not read lines twice');
check((int)DB::val("SELECT count(*) FROM risk_findings WHERE pattern = 'brute_force'") === 1, 'no duplicate finding');
// schedule: the search for findings every 12 hours by default, deadlines every round
check(Behaviour::intervalHours() === 12, 'behaviour: search for findings every 12 hours by default');
$n = 0; $b = Behaviour::analyse($n, false);
check(isset($b['next_search']) && abs(strtotime($b['next_search']) - (time() + 12 * 3600)) < 120, 'behaviour: right after a search the next one is 12 hours away');
// no reaction: the deadline passes and the address is blocked (but never an authorised one) — also between searches
DB::q("UPDATE risk_findings SET deadline = now() - interval '1 minute' WHERE id = ?", [$f['id']]);
$n = 0; $b = Behaviour::analyse($n, false);
check(isset($b['next_search']), 'behaviour: no search in this round');
check(Blocks::isBlocked('198.51.200.13/32'), 'no reaction within the reaction time: blocked (deadlines are checked every round)');
check(DB::val('SELECT status FROM risk_findings WHERE id = ?', [$f['id']]) === 'blocked', 'the finding says blocked');
check(!Blocks::isBlocked('100.1.0.5/32'), 'the authorised actor is not blocked');
SecScan::setState('behaviour_search', ['at' => gmdate('c', time() - 13 * 3600)]);
$n = 0; $b = Behaviour::analyse($n, false);
check(!isset($b['next_search']), 'behaviour: 13 hours after the last search, the round searches again');
Settings::set('behaviour', ['interval_hours' => 3]);
check(Behaviour::nextSearch() - (int)Behaviour::lastSearch() === 3 * 3600, 'behaviour: the interval follows the setting');
Settings::set('behaviour', ['interval_hours' => Behaviour::DEFAULT_INTERVAL_HOURS]);
// an admin removal is respected for 30 days
Blocks::remove('198.51.200.13/32', 'test', false);
check(Blocks::guard('198.51.200.13', 'block', 1.0) !== null, 'after an admin removed a block, the guard refuses for 30 days');
// escalation
Blocks::add('198.51.200.20', 'ai', 'x', null, true, 'system'); $d1 = (int)DB::val("SELECT duration_secs FROM block_history WHERE ip = '198.51.200.20/32' ORDER BY id DESC LIMIT 1");
Blocks::add('198.51.200.20', 'ai', 'x', null, true, 'system'); $d2 = (int)DB::val("SELECT duration_secs FROM block_history WHERE ip = '198.51.200.20/32' ORDER BY id DESC LIMIT 1");
check($d1 === 86400 && $d2 === 7 * 86400, 'blocks escalate 1 day → 7 days');
// snapshots for Lua
[$tl] = State::build('traps');
check(str_contains(implode('', $tl), "exact|*|/.env\t0\tactive:1"), 'traps snapshot for Lua');
[$ml] = State::build('meta');
check(str_contains(implode('', $ml), "unknown_threshold\t0\t5"), 'meta snapshot carries the unknown-host threshold');
// blocklists: parsing refuses private, reserved and too wide networks
[$e, $ref] = Blocklists::parse("# comment\n1.2.3.0/24 ; x\n10.0.0.0/8\n0.0.0.0/0\n203.0.113.5\n5.6.7.8\n2a00:1::/32\n2a00::/8\nbad\n", 'plain', '');
check(array_keys($e) === ['1.2.3.0/24', '5.6.7.8/32', '2a00:1::/32'] && $ref === 5, 'blocklist parser keeps 3 entries, refuses 5');
[$e2] = Blocklists::parse("{\"cidr\":\"9.9.9.0/24\"}\n{\"other\":1}\n", 'jsonl', 'cidr');
check(array_keys($e2) === ['9.9.9.0/24'], 'JSON-lines blocklist');
// notifications through Mailpit
$mp = trim((string)gethostbyname('pspm-mailpit-test'));
Settings::set('smtp', ['host' => $mp, 'port' => 1025, 'security' => 'none', 'user' => '', 'pass_enc' => '', 'from' => 'pspm@test.test', 'extra' => ['team@test.test']]);
DB::q("UPDATE users SET email = 'admin@test.test', notify = '[]'::jsonb");
Notify::event('findings', 'Test finding', 'Body text');
[$sent, $failed] = Notify::send();
check($sent >= 1 && $failed === 0, "mail sent through the relay ($sent sent)");
$api = json_decode((string)@file_get_contents("http://$mp:8025/api/v1/messages"), true);
check(($api['total'] ?? 0) >= 1 && str_contains(json_encode($api), '[PSPM]'), 'Mailpit received a [PSPM] mail');
check(!preg_match('#https?://[^ ]*(token|access)#', json_encode($api)), 'no action links or tokens in the mail');
echo "security checks passed\n";
