<?php
// Backend for tests/box-e2e.sh (php -S 127.0.0.1:8099 tests/box-backend.php): answers with
// one response header of ?n bytes, to test the response header buffer of a backend.
declare(strict_types=1);
header('X-Big: ' . str_repeat('a', max(1, min(200000, (int)($_GET['n'] ?? 100)))));
echo "ok\n";
