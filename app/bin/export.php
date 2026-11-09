<?php
// Export the whole configuration as one JSON file on stdout (run as pspm).
//   export.php [--no-history] [--tls-stdin]      passphrase in $PSPM_EXPORT_PASSPHRASE
//   export.php --backup                          passphrase from Settings → Backups (nightly backups)
// With --tls-stdin, root passes {"letsencrypt": base64 tar.gz, "never_block": text} on stdin.
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=' . (getenv('PSPM_ACTOR') ?: 'root (export)'));
try {
    if (in_array('--backup', $argv, true)) {
        $enc = Settings::get('backup', [])['passphrase_enc'] ?? '';
        if ($enc === '') { fwrite(STDERR, "no backup passphrase set (Settings → Backups); the JSON export is skipped\n"); exit(5); }
        $pass = Crypto::open($enc);
    } else {
        $pass = (string)getenv('PSPM_EXPORT_PASSPHRASE');
    }
    $tls = in_array('--tls-stdin', $argv, true) ? json_decode((string)stream_get_contents(STDIN), true) : null;
    echo Export::encode(Export::build($pass, !in_array('--no-history', $argv, true), $tls));
} catch (Throwable $e) {
    fwrite(STDERR, 'export: ' . $e->getMessage() . "\n");
    exit(1);
}
