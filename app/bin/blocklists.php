<?php
// External blocklists (pspm-blocklists.timer, every 15 minutes, as pspm). [--id <uuid>] fetches one now.
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=system');
try {
    $only = ($i = array_search('--id', $argv, true)) !== false ? ($argv[$i + 1] ?? null) : null;
    $r = Blocklists::run($only);
    echo json_enc($r) . "\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'blocklists: ' . $e->getMessage() . "\n");
    exit(1);
}
