<?php
// Export/import round trip (run by tests/smoke.sh): export from pspm, tamper checks,
// import into a fresh database pspm2, export again and compare.
declare(strict_types=1);
require '/src/app/lib/bootstrap.php';
putenv('PSPM_ACTOR=export-check');
function check(bool $c, string $what): void { echo ($c ? 'ok   ' : 'FAIL ') . $what . "\n"; if (!$c) exit(1); }
$pass = 'a long export passphrase';
$mode = $argv[1] ?? 'export';
if ($mode === 'export') {
    $json = Export::encode(Export::build($pass, true, ['letsencrypt' => base64_encode('fake-tar'), 'never_block' => "203.0.113.9\n"]));
    file_put_contents('/tmp/export1.json', $json);
    $d = json_decode($json, true);
    check($d['format'] === 'pspm-export' && isset($d['secrets']['ciphertext']), 'export has the format header and an encrypted part');
    check(!str_contains($json, '$argon2id$') && !str_contains($json, 'BEGIN PRIVATE KEY') && !str_contains($json, '"v1:'), 'no password hash, key or sealed value in the plain part');
    try { Export::open($json, 'wrong passphrase here'); check(false, 'wrong passphrase'); } catch (InvalidArgumentException) { check(true, 'a wrong passphrase is refused'); }
    $t = json_decode($json, true); $t['sites']['sites'][0]['name'] = 'tampered.example';
    try { Export::open(json_encode($t), $pass); check(false, 'tamper'); } catch (InvalidArgumentException) { check(true, 'a changed file is refused (tamper-evident)'); }
    [$doc, $sec] = Export::open($json, $pass);
    check(isset($sec['tls']) && count(array_filter(array_keys($sec), fn($k) => str_starts_with($k, 'users|'))) >= 1, 'secrets decrypt: users and TLS material');
    DB::pdo()->exec('DROP DATABASE IF EXISTS pspm2');
    DB::pdo()->exec('CREATE DATABASE pspm2');
    echo "export written\n";
} elseif ($mode === 'import') {
    [$doc, $sec] = Export::open((string)file_get_contents('/tmp/export1.json'), $pass);
    $stats = Export::apply($doc, $sec, '');
    check(($stats['sites.sites'] ?? 0) >= 1 && ($stats['pki.cas'] ?? 0) >= 1, 'import into an empty database: ' . array_sum($stats) . ' records');
    $u = DB::one("SELECT * FROM users WHERE username = 'tester' OR username = 'admin' LIMIT 1");
    check($u && str_starts_with($u['password_hash'], '$argon2id$'), 'password hashes restored');
    check(!$u['totp_secret_enc'] || strlen(Crypto::open($u['totp_secret_enc'])) === 32, 'TOTP secret re-sealed with this box key');
    check(DB::val("SELECT scope FROM cleared_ips WHERE ip = '203.0.113.51/32'") === 'admin' && DB::val("SELECT target FROM access_links WHERE label = 'export round trip'") === 'admin',
        'an admin link and its clearance survive the round trip (scope is recomputed by the database)');
    check(PKI::unwrap(DB::val('SELECT key_wrapped FROM cas LIMIT 1'), 'correct horse battery staple', DB::val('SELECT id FROM cas LIMIT 1'), DB::val('SELECT fingerprint_sha256 FROM cas LIMIT 1')) !== null,
        'the CA key still unwraps with its passphrase');
    file_put_contents('/tmp/export2.json', Export::encode(Export::build($pass, true, ['letsencrypt' => base64_encode('fake-tar'), 'never_block' => "203.0.113.9\n"])));
    $a = json_decode((string)file_get_contents('/tmp/export1.json'), true); $b = json_decode((string)file_get_contents('/tmp/export2.json'), true);
    foreach ([&$a, &$b] as &$x) { unset($x['exported_at'], $x['secrets'], $x['history']['audit']); }
    unset($x);
    $diff = [];
    foreach (array_keys($a) as $k) if (json_canonical($a[$k], false) !== json_canonical($b[$k] ?? null, false)) $diff[] = $k;
    check(!$diff, 'round trip: the second export equals the first' . ($diff ? ' (differs in: ' . implode(', ', $diff) . ')' : ''));
    [, $s1] = Export::open((string)file_get_contents('/tmp/export1.json'), $pass);
    [, $s2] = Export::open((string)file_get_contents('/tmp/export2.json'), $pass);
    check(json_canonical($s1, false) === json_canonical($s2, false), 'round trip: the secrets are identical');
    echo "export checks passed\n";
}
