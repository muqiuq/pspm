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

echo "$n checks, $fails failed\n";
exit($fails ? 1 : 0);
