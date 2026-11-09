<?php
// Apply pending SQL migrations, each in its own transaction (plan §10.3).
// Run by install.sh as user pspm:  php bin/migrate.php /opt/pspm/db/migrations [--status]
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';

$dir = $argv[1] ?? '';
$statusOnly = in_array('--status', $argv, true);
if (!is_dir($dir)) { fwrite(STDERR, "usage: migrate.php <migrations dir> [--status]\n"); exit(64); }

try {
    $pdo = DB::pdo();
} catch (Throwable $e) {
    fwrite(STDERR, 'cannot connect to PostgreSQL: ' . $e->getMessage() . "\n");
    exit(3);
}
$pdo->exec('CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
$done = array_map('intval', array_column(DB::all('SELECT version FROM schema_migrations'), 'version'));
$files = glob(rtrim($dir, '/') . '/[0-9][0-9][0-9][0-9]_*.sql') ?: [];
sort($files);
$pending = [];
foreach ($files as $f) {
    $v = (int)substr(basename($f), 0, 4);
    if (!in_array($v, $done, true)) $pending[$v] = $f;
}
echo 'schema version ' . ($done ? max($done) : 0) . ', ' . count($pending) . " pending\n";
if ($statusOnly || !$pending) exit(0);

foreach ($pending as $v => $f) {
    $sql = (string)file_get_contents($f);
    $t = microtime(true);
    try {
        $pdo->beginTransaction();
        $pdo->exec($sql);
        DB::q('INSERT INTO schema_migrations (version, name) VALUES (?, ?)', [$v, basename($f)]);
        $pdo->commit();
        printf("applied %s (%.2f s)\n", basename($f), microtime(true) - $t);
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        fwrite(STDERR, 'FAILED ' . basename($f) . ': ' . $e->getMessage() . "\nThe database is unchanged by this migration (it ran in a transaction).\n");
        exit(4);
    }
}
exit(0);
