<?php
// The security scan (pspm-secscan.timer, every minute, as pspm). --full forces the analysis.
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=system');
try {
    $r = SecScan::run(in_array('--full', $argv, true));
    echo json_enc($r) . "\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'secscan: ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine() . "\n");
    exit(1);
}
