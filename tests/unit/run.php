<?php
// Minimal unit tests (no framework): php tests/unit/run.php
declare(strict_types=1);
putenv('PSPM_ETC=/nonexistent');
require __DIR__ . '/../../app/lib/bootstrap.php';

$n = 0; $fails = 0;
function ok(bool $c, string $what): void { global $n, $fails; $n++; if (!$c) { $fails++; echo "FAIL $what\n"; } }
function eq(mixed $a, mixed $b, string $what): void { ok($a === $b, $what . ($a === $b ? '' : ': got ' . var_export($a, true) . ', want ' . var_export($b, true))); }

// TOTP: RFC 6238 appendix B (SHA-1, 8 digits) and RFC 4226 HOTP vectors
$key = '12345678901234567890';
foreach ([59 => '94287082', 1111111109 => '07081804', 1111111111 => '14050471', 1234567890 => '89005924', 2000000000 => '69279037'] as $t => $code) {
    eq(Totp::hotp($key, intdiv($t, 30), 8), $code, "TOTP vector t=$t");
}
eq(Totp::hotp($key, 0, 6), '755224', 'HOTP vector 0');
$sec = Totp::base32Encode($key);
eq(Totp::base32Decode($sec), $key, 'base32 round trip');
$now = 1700000000;
$c = Totp::code($sec, intdiv($now, 30));
eq(Totp::verify($sec, $c, 0, $now), intdiv($now, 30), 'verify current step');
eq(Totp::verify($sec, $c, intdiv($now, 30), $now), null, 'replay refused');
eq(Totp::verify($sec, Totp::code($sec, intdiv($now, 30) - 1), 0, $now), intdiv($now, 30) - 1, 'previous step accepted');
eq(Totp::verify($sec, Totp::code($sec, intdiv($now, 30) - 2), 0, $now), null, 'two steps back refused');

// Addresses
eq(IP::clientKey('2001:db8:0:1:aaaa::5'), '2001:db8:0:1::/64', 'IPv6 client key');
eq(IP::clientKey('203.0.113.9'), '203.0.113.9', 'IPv4 client key');
eq(IP::normCidr('203.0.113.77/24'), '203.0.113.0/24', 'normalise cidr');
ok(IP::neverBlocked('10.1.2.3'), 'private is never blocked');
ok(IP::neverBlocked('0.0.0.0/0'), 'a supernet of private is never blocked');
ok(!IP::neverBlocked('203.0.113.7'), 'public can be blocked');
ok(IP::neverBlocked('fd00::1'), 'ULA never blocked');
eq(State::cidrKey('2001:db8:abcd:12ff::/56')[0], '2001:db8:abcd:1200::/56', 'v6 cidr key masks');
eq(State::cidrKey('203.0.113.7/32')[0], '203.0.113.7/32', 'v4 cidr key');

// Never-blocked ranges agree between PHP, nginx and SQL
$http = (string)file_get_contents(__DIR__ . '/../../nginx/static/http.conf');
foreach (IP::NEVER_BLOCKED as $r) ok(str_contains($http, $r), "http.conf geo has $r");
$sql = (string)file_get_contents(__DIR__ . '/../../db/migrations/0001_init.sql');
foreach (IP::NEVER_BLOCKED as $r) ok(str_contains($sql, "'$r'") || str_contains($sql, "'" . explode('/', $r)[0] . "/128'"), "SQL has $r");

// Validation
eq(Validate::host('App.Example.CH'), 'app.example.ch', 'host lower-cased');
eq(Validate::host('bücher.example'), 'xn--bcher-kva.example', 'IDN host');
eq(Validate::host('10.0.0.1'), null, 'IP is not a host name');
eq(Validate::host('a..b'), null, 'empty label');
eq(Validate::path('/api/'), '/api/', 'path ok');
eq(Validate::path('/a b'), null, 'space refused');
eq(Validate::path('/$x'), null, 'dollar refused');
eq(Validate::path('/.pspm/x'), null, 'reserved prefix refused');
eq(Validate::headerValue('a$b'), null, 'dollar in header value refused');
eq(Validate::headerValue('a"b'), null, 'quote in header value refused');
eq(Validate::size('10m'), '10m', 'size');
eq(Validate::size('101g'), null, 'size too big');
eq(Validate::serverAddr('[2001:db8::5]:443'), '[2001:db8::5]:443', 'v6 server');
eq(Validate::serverAddr('backend.lan:8080'), 'backend.lan:8080', 'host server');
eq(Validate::serverAddr('10.0.0.5'), null, 'port required');

// The fixture document passes and renders
$doc = json_dec((string)file_get_contents(__DIR__ . '/../fixtures/document.json'));
eq(Model::checkDocument($doc), [], 'fixture document is valid');
$facts = json_dec((string)file_get_contents(__DIR__ . '/../fixtures/facts.json'));
$r = (new Renderer(['id' => 1, 'document' => $doc], $facts))->render();
eq($r['errors'], [], 'fixture renders');
$all = implode("\n", $r['files']);
ok(!str_contains($all, '$$'), 'no doubled dollars');
foreach ($r['files'] as $p => $content) {
    if (!str_starts_with($p, 'sites/')) continue;
    foreach (array_slice(explode("\nserver {\n", "\n$content"), 1) as $i => $srv) {
        eq(substr_count($srv, "\n    set \$pspm_signin "), 1, "$p server " . ($i + 1) . ': $pspm_signin set once at server level');
    }
    // every proxying location sets every identity header (plan §12.4)
    preg_match_all('/location [^{]+\{(.*?)\n    \}/s', $content, $m);
    // every proxying location sets every identity header: to the signed-in identity or to empty (plan §12.4)
    foreach ($m[1] as $body) if (str_contains($body, 'proxy_pass') && !str_contains($body, 'internal;')) foreach (Renderer::IDENTITY_HEADERS as $hn) {
        ok((bool)preg_match('/proxy_set_header ' . preg_quote($hn, '/') . ' ("";|\$pspm_[a-z]+;)/', $body), "$p: $hn always set");
    }
}
$r2 = (new Renderer(['id' => 1, 'document' => $doc], $facts))->render();
eq($r2['files'], $r['files'], 'deterministic output');
ok(isset($r['summary']['pending_certs']['0']) || $r['summary']['pending_certs'] !== null, 'summary has pending certs');

// Sign-in: providers render, the token header is blanked unless the site forwards it
ok(isset($r['files']['oauth2-proxy/peeeeeeee.cfg']) && isset($r['files']['oauth2-proxy/compose.yml']), 'oauth2-proxy config and compose rendered');
$cfg = $r['files']['oauth2-proxy/peeeeeeee.cfg'];
ok(str_contains($cfg, 'whitelist_domains = ["app.example.ch", "auth.example.ch", "www.app.example.ch"]'), 'redirect whitelist lists the exact host names');
ok(str_contains($cfg, 'code_challenge_method = "S256"') && str_contains($cfg, 'session_store_type = "redis"'), 'PKCE and Redis sessions');
ok(!preg_match('/secret/i', preg_replace('/^#.*$/m', '', $cfg)), 'no secret in the rendered config');
ok(str_contains($r['files']['sites/app.example.ch.conf'], 'proxy_set_header X-Forwarded-Access-Token "";'), 'access token not forwarded by default');
ok(str_contains($r['files']['sites/app.example.ch.conf'], 'proxy_set_header X-Forwarded-Email $pspm_email;'), 'selected identity header carries the identity');
ok(str_contains($r['files']['sites/new.example.ch.conf'], 'proxy_set_header X-Forwarded-Email "";'), 'sites without sign-in blank the identity headers');
$bad2 = $doc; $bad2['sites'][0]['hosts'][] = 'app.other.test';
ok((bool)array_filter(Model::checkDocument($bad2), fn($e) => str_contains($e, 'cookie domain')), 'a host outside the cookie domain is refused');

// Diff
ok(str_contains(Diff::unified("a\nb\nc\n", "a\nB\nc\n"), "-b\n+B"), 'diff shows change');
eq(Diff::unified("x\n", "x\n"), '', 'equal texts no diff');

// A broken document is refused by the renderer
$bad = $doc; $bad['sites'][0]['routes'][0]['paths'] = ['/a;b'];
ok((new Renderer(['id' => 2, 'document' => $bad], $facts))->render()['errors'] !== [], 'invalid path refused by the renderer');

// Agent (separate process: its function names clash with the app's): ipset timeouts are
// capped at the kernel limit, capped sets are flagged for a reload, errors name the entry
$agentCode = 'define("PSPM_AGENT_LIBRARY", true); require ' . var_export(realpath(__DIR__ . '/../../agent/pspm-agent.php'), true) . ';
    $now = 1700000000; $d30 = $now + 30 * 86400;
    [$s1, $c1] = set_script("pspm-allowweb4", ["203.0.113.7/32" => $d30, "198.51.100.0/24" => $now + 3600], $now);
    echo json_encode(["t30" => ipset_timeout($d30, $now), "t1h" => ipset_timeout($now + 3600, $now), "perm" => ipset_timeout(0, $now),
        "past" => ipset_timeout($now - 5, $now), "script" => $s1, "capped" => $c1,
        "short" => set_script("pspm-block4", ["192.0.2.1/32" => $now + 3600], $now)[1],
        "allow" => set_script("pspm-allow4", ["192.0.2.1/32" => 0], $now),
        "culprit" => restore_culprit("ipset v7.22: Error in line 3: Syntax error: x", $s1),
        "nolines" => restore_culprit("ipset v7.22: Kernel error", $s1)]);';
$p = proc_open([PHP_BINARY, '-r', $agentCode], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
$agentOut = stream_get_contents($pipes[1]); $agentErr = stream_get_contents($pipes[2]); proc_close($p);
$ag = json_decode((string)$agentOut, true);
ok(is_array($ag), 'agent loads as a library' . ($ag ? '' : ": $agentErr$agentOut"));
if (is_array($ag)) {
    eq($ag['t30'], 2147483, '30-day timeout capped at the ipset limit');
    eq($ag['t1h'], 3600, 'short timeout unchanged');
    eq($ag['perm'], 0, 'permanent entry stays 0');
    eq($ag['past'], 1, 'expired entry gets the minimum timeout');
    ok(str_contains($ag['script'], "add pspm-allowweb4-tmp 203.0.113.7/32 timeout 2147483\n"), 'capped entry in the restore script');
    preg_match_all('/timeout (\d+)/', $ag['script'], $tm);
    ok(max(array_map('intval', $tm[1])) <= 2147483, 'no timeout above the limit in the script');
    ok($ag['capped'] === true && $ag['short'] === false, 'only sets with capped entries are flagged for a reload');
    ok(!str_contains($ag['allow'][0], 'timeout') && $ag['allow'][1] === false, 'sets without timeout support get no timeout');
    eq($ag['culprit'], ' [entry: 203.0.113.7/32 timeout 2147483]', 'restore error names the entry of its line');
    eq($ag['nolines'], '', 'errors without a line name no entry');
}

// Review (install.sh): sign-in is part of what a site is reachable by
$review = function (?array $old, array $new): string {
    $dir = sys_get_temp_dir();
    $fo = $old === null ? '/dev/null' : tempnam($dir, 'rv'); $fn = tempnam($dir, 'rv');
    if ($old !== null) file_put_contents($fo, json_enc(['document' => $old]));
    file_put_contents($fn, json_enc(['document' => $new]));
    $p = proc_open([PHP_BINARY, __DIR__ . '/../../app/bin/review.php', $fo, $fn], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]); proc_close($p);
    if ($old !== null) unlink($fo);
    unlink($fn);
    return (string)$out;
};
$rv = $review(null, $doc);
ok(str_contains($rv, 'OPENS: new site app.example.ch, reachable by: lan, cleared, cert, or Microsoft sign-in (Example staff: groups aaaa1111-2222-3333-4444-555566667777)'), 'new site: sign-in alternative in its OPENS line' . (str_contains($rv, 'OPENS') ? '' : ": $rv"));
ok(!str_contains($rv, '/device/'), 'a route without sign-in on an "alternative" site does not open anything');
$noSi = $doc; $noSi['sites'][0]['access']['signin']['mode'] = 'none';
ok(str_contains($review($noSi, $doc), 'OPENS: site app.example.ch: Microsoft sign-in added as an alternative (Example staff: groups aaaa1111-2222-3333-4444-555566667777)'), 'sign-in added as an alternative opens');
$req = $doc; $req['sites'][0]['access']['signin']['mode'] = 'required';
ok(str_contains($review($req, $doc), 'sign-in is now an alternative instead of required'), 'required → alternative opens');
ok(!str_contains($review($doc, $req), 'OPENS'), 'alternative → required opens nothing');
ok(str_contains($review($req, $req), 'No configuration changes'), 'no change, no lines');
$any = $doc; $any['sites'][0]['access']['signin']['groups'] = [];
ok(str_contains($review($doc, $any), 'more users may sign in (groups: no limit)'), 'dropping the group limit opens');
ok(str_contains($review(null, $any), 'or Microsoft sign-in (Example staff: any account from example.ch)'), 'without limits: every account the provider accepts');

// Firewall problem summary (dashboard, health mail)
eq(Status::firewallProblem(['sets' => ['pspm-block4' => 3], 'errors' => [], 'rules' => ['chain4' => 'ok']]), null, 'no firewall problem');
ok(str_starts_with((string)Status::firewallProblem(['sets' => ['pspm-allowweb4' => -1, 'pspm-block4' => 1], 'errors' => ['ipset restore pspm-allowweb4: x'], 'rules' => ['chain4' => 'ok']]),
    'The firewall works, but set pspm-allowweb4 could not be loaded'), 'failed set named');
ok(str_starts_with((string)Status::firewallProblem(['sets' => [], 'errors' => ['iptables-restore: y'], 'rules' => ['chain4' => 'error']]),
    'The firewall chain could not be set up (chain4)'), 'broken chain named');

echo "$n checks, $fails failed\n";
exit($fails ? 1 : 0);
