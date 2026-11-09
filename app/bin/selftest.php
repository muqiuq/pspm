<?php
// Checks an app release before it goes live (install.sh phase 8). Run as pspm.
// Exit 0 when every check passes; prints one line per check.
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';

$fail = 0;
$check = function (string $name, callable $fn) use (&$fail) {
    try { $r = $fn(); $ok = $r === true || is_string($r); $msg = is_string($r) ? $r : ''; }
    catch (Throwable $e) { $ok = false; $msg = $e->getMessage(); }
    printf("%-34s %s%s\n", $name, $ok ? 'ok' : 'FAIL', $msg !== '' ? "  $msg" : '');
    if (!$ok) $fail++;
};
$check('PHP version >= 8.2', fn() => version_compare(PHP_VERSION, '8.2', '>=') ?: false);
foreach (['pdo_pgsql', 'sodium', 'intl', 'mbstring', 'curl', 'openssl'] as $ext) $check("extension $ext", fn() => extension_loaded($ext) ?: false);
$check('Argon2id password hashing', fn() => defined('PASSWORD_ARGON2ID') && password_verify('x', password_hash('x', PASSWORD_ARGON2ID)) ?: false);
$check('app.key readable and valid', fn() => Crypto::open(Crypto::seal('t')) === 't' ?: false);
$check('database connection', fn() => DB::available() ?: false);
$check('schema version', function () {
    $v = DB::schemaVersion();
    return $v >= PSPM_SCHEMA ? "$v" : throw new RuntimeException("schema $v, this code needs " . PSPM_SCHEMA);
});
$check('TOTP RFC 6238 vector', fn() => Totp::hotp('12345678901234567890', intdiv(59, 30), 8) === '94287082' ?: false);
$check('renderer (empty document)', function () {
    $r = (new Renderer(['id' => 0, 'document' => ['format' => 1, 'global' => Settings::GLOBAL_DEFAULTS, 'sites' => [], 'backends' => []]],
        ['release' => 'selftest']))->render();
    return !$r['errors'] && isset($r['files']['nginx.conf']) ?: throw new RuntimeException(implode('; ', $r['errors']));
});
$check('state directory writable', fn() => is_writable(PSPM_STATE) ?: throw new RuntimeException(PSPM_STATE . ' is not writable'));
exit($fail ? 1 : 0);
