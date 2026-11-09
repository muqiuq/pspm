<?php
// For install.sh (run as pspm): the environment (secrets) of a sign-in container.
//   signin.php env <provider id>
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
try {
    if (($argv[1] ?? '') !== 'env' || !Validate::uuid($argv[2] ?? '')) { fwrite(STDERR, "usage: signin.php env <provider id>\n"); exit(64); }
    echo Signin::env($argv[2]);
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(3);
}
