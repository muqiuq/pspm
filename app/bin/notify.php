<?php
// Health checks and the mail outbox (pspm-notify.timer, every minute, as pspm).
//   notify.php            run
//   notify.php test <to>  send a test mail now
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=system');
try {
    if (($argv[1] ?? '') === 'test') {
        $ok = Notify::mail([$argv[2] ?? ''], '[PSPM] Test e-mail', "This is a test from PSPM.\n", $err);
        echo $ok ? "sent\n" : "failed: $err\n";
        exit($ok ? 0 : 1);
    }
    Notify::health();
    [$sent, $failed] = Notify::send();
    echo "sent $sent, failed $failed\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'notify: ' . $e->getMessage() . "\n");
    exit(1);
}
