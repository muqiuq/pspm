<?php
// Import an export file (run as pspm). Passphrase in $PSPM_IMPORT_PASSPHRASE.
//   import.php preview <file>    what would change (JSON)
//   import.php apply <file>      replace everything (one transaction)
//   import.php tls <file>        the Let's Encrypt material (JSON) for root to restore
// $PSPM_IMPORTER names the admin whose account is kept as it is.
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=' . (getenv('PSPM_ACTOR') ?: 'root (import)'));
try {
    [$cmd, $file] = [$argv[1] ?? '', $argv[2] ?? ''];
    if (!in_array($cmd, ['preview', 'apply', 'tls'], true) || !is_readable($file)) { fwrite(STDERR, "usage: import.php preview|apply|tls <file>\n"); exit(64); }
    [$doc, $secrets] = Export::open((string)file_get_contents($file), (string)getenv('PSPM_IMPORT_PASSPHRASE'));
    $importer = (string)(getenv('PSPM_IMPORTER') ?: '');
    if ($cmd === 'preview') echo json_enc(Export::preview($doc, $secrets, $importer), true) . "\n";
    elseif ($cmd === 'tls') echo json_enc($secrets['tls'] ?? null) . "\n";
    else echo json_enc(Export::apply($doc, $secrets, $importer), true) . "\n";
} catch (InvalidArgumentException $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(2);
} catch (Throwable $e) {
    fwrite(STDERR, 'import: ' . $e->getMessage() . "\n");
    exit(1);
}
