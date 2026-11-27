<?php
// Render tests/fixtures into a release directory: php tests/render-fixture.php <out dir> [shared]
// "shared": the admin host name is the provider's sign-in host (one server for both).
// "own": app.example.ch is public with sign-in required, and its application's own sign-in
// callbacks pass without it (a route that overrides only the sign-in).
// "strip": printer.example.ch passes /site1/, /site2/ and /site3/ to an application at / (without the prefix);
// the site is protected (LAN only), /site1/ /site2/ and /other/ are public, /site3/ keeps the site's access.
declare(strict_types=1);
putenv('PSPM_ETC=/nonexistent');
require __DIR__ . '/../app/lib/bootstrap.php';
$out = rtrim($argv[1] ?? '', '/');
$doc = json_dec((string)file_get_contents(__DIR__ . '/fixtures/document.json'));
$facts = json_dec((string)file_get_contents(__DIR__ . '/fixtures/facts.json'));
if (($argv[2] ?? '') === 'shared') $doc['global']['admin_host'] = $doc['providers'][0]['signin_host'];
if (($argv[2] ?? '') === 'own') {
    $doc['sites'][0]['access']['conditions'] = ['public'];
    $doc['sites'][0]['access']['signin']['mode'] = 'required';
    $doc['sites'][0]['routes'][] = ['id' => 'rcb', 'match' => 'exact', 'paths' => ['/signin-oidc', '/signout-callback-oidc'], 'listeners' => ['all'],
        'action' => 'proxy', 'status' => 404, 'redirect_url' => '', 'redirect_code' => 302, 'overrides' => ['access' => ['signin' => 'none']]];
}
if (($argv[2] ?? '') === 'strip') {
    // applications that run at / under one host name: printer.example.ch (plain HTTP, LAN only, so the
    // test's 127.0.0.1 is refused) sends /site1/ /site2/ /site3/ without the prefix, everything else with it,
    // to tests/echo-backend.php. Public: /site1/ (sign-in none too), /site2/ and /other/; the rest the site's.
    $echo = '33333333-3333-4333-8333-333333333333';
    $doc['backends'][] = ['id' => $echo, 'name' => 'echo', 'protocol' => 'http', 'tls_verify' => 'off', 'tls_name' => '', 'custom_ca' => '', 'keepalive' => 4,
        'servers' => [['addr' => '127.0.0.1:8097', 'weight' => 1, 'backup' => false, 'max_fails' => 1, 'fail_timeout' => 10]]];
    foreach ($doc['sites'] as &$s) {
        if ($s['hosts'][0] !== 'printer.example.ch') continue;
        $s['access']['conditions'] = ['lan'];
        $s['access']['denied'] = '403';
        $s['proxy']['backend'] = $echo;
        $route = fn(string $id, string $path, array $access, bool $strip) => ['id' => $id, 'match' => 'prefix', 'paths' => [$path], 'listeners' => ['all'],
            'action' => 'proxy', 'status' => 404, 'redirect_url' => '', 'redirect_code' => 302, 'overrides' => $access ? ['access' => $access] : []]
            + ($strip ? ['strip_prefix' => true] : []);
        $s['routes'][] = $route('rsite1', '/site1/', ['conditions' => ['public'], 'signin' => 'none'], true);
        $s['routes'][] = $route('rsite2', '/site2/', ['conditions' => ['public']], true);
        $s['routes'][] = $route('rsite3', '/site3/', [], true);
        $s['routes'][] = $route('rother', '/other/', ['conditions' => ['public']], false);
    }
    unset($s);
}
$r = (new Renderer(['id' => 1, 'document' => $doc], $facts))->render();
if ($r['errors']) { fwrite(STDERR, implode("\n", $r['errors']) . "\n"); exit(2); }
foreach ($r['files'] as $p => $c) { @mkdir(dirname("$out/$p"), 0755, true); file_put_contents("$out/$p", $c); }
file_put_contents("$out/summary.json", json_enc($r['summary'], true));
foreach ($r['warnings'] as $w) echo "warning: $w\n";
echo json_enc($r['summary']) . "\n";
