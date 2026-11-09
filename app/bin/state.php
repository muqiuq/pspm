<?php
// Publish the snapshot files for nginx and the agent (run as pspm).
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
try {
    $r = State::publish();
    echo 'snapshots written; nginx sync: ' . ($r['ok'] ? 'ok' : 'not reachable (' . ($r['error'] ?? '') . ')') . "\n";
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(3);
}
