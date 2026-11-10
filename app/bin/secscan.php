<?php
// The security scan, as pspm:
//   secscan.php            read the security log (pspm-secscan.timer, every minute)
//   secscan.php --analyse  the analysis when due (pspm-analyse.timer, every minute; works every 5 min or on Run now)
//   secscan.php --full     both, the analysis at once
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=system');
try {
    $full = in_array('--full', $argv, true);
    $r = SecScan::run($full, $full ? 'all' : (in_array('--analyse', $argv, true) ? 'analyse' : 'ingest'));
    echo json_enc($r) . "\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'secscan: ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine() . "\n");
    exit(1);
}
