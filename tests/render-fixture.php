<?php
// Render tests/fixtures into a release directory: php tests/render-fixture.php <out dir>
declare(strict_types=1);
putenv('PSPM_ETC=/nonexistent');
require __DIR__ . '/../app/lib/bootstrap.php';
$out = rtrim($argv[1] ?? '', '/');
$doc = json_dec((string)file_get_contents(__DIR__ . '/fixtures/document.json'));
$facts = json_dec((string)file_get_contents(__DIR__ . '/fixtures/facts.json'));
$r = (new Renderer(['id' => 1, 'document' => $doc], $facts))->render();
if ($r['errors']) { fwrite(STDERR, implode("\n", $r['errors']) . "\n"); exit(2); }
foreach ($r['files'] as $p => $c) { @mkdir(dirname("$out/$p"), 0755, true); file_put_contents("$out/$p", $c); }
file_put_contents("$out/summary.json", json_enc($r['summary'], true));
foreach ($r['warnings'] as $w) echo "warning: $w\n";
echo json_enc($r['summary']) . "\n";
