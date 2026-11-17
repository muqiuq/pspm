<?php
// Render tests/fixtures into a release directory: php tests/render-fixture.php <out dir> [shared]
// "shared": the admin host name is the provider's sign-in host (one server for both).
// "own": app.example.ch is public with sign-in required, and its application's own sign-in
// callbacks pass without it (a route that overrides only the sign-in).
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
$r = (new Renderer(['id' => 1, 'document' => $doc], $facts))->render();
if ($r['errors']) { fwrite(STDERR, implode("\n", $r['errors']) . "\n"); exit(2); }
foreach ($r['files'] as $p => $c) { @mkdir(dirname("$out/$p"), 0755, true); file_put_contents("$out/$p", $c); }
file_put_contents("$out/summary.json", json_enc($r['summary'], true));
foreach ($r['warnings'] as $w) echo "warning: $w\n";
echo json_enc($r['summary']) . "\n";
