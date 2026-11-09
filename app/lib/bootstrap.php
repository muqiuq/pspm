<?php
// PSPM bootstrap: constants, configuration, libraries. Every entry point requires this file.
declare(strict_types=1);

const PSPM_APP = __DIR__ . '/..';
const PSPM_SCHEMA = 2;   // the newest migration this code needs (db/migrations/NNNN_*.sql)

// Paths can be moved for tests with environment variables; production uses the defaults.
define('PSPM_ETC',   rtrim(getenv('PSPM_ETC') ?: '/etc/pspm', '/'));
define('PSPM_VAR',   rtrim(getenv('PSPM_VAR') ?: '/var/lib/pspm', '/'));
define('PSPM_LOG',   rtrim(getenv('PSPM_LOGDIR') ?: '/var/log/pspm', '/'));
define('PSPM_STATE', PSPM_VAR . '/state');
define('PSPM_STATUS', PSPM_VAR . '/status');
define('PSPM_NGINX', PSPM_ETC . '/nginx');

foreach (['util', 'db', 'crypto', 'ip', 'audit', 'settings', 'totp', 'auth', 'validate',
          'model', 'revisions', 'render', 'diff', 'live', 'status', 'state', 'access',
          'layout', 'markdown', 'pki', 'signin', 'ai', 'notify', 'blocks', 'secscan', 'traps', 'behaviour',
          'blocklists', 'export'] as $lib) {
    require_once __DIR__ . "/$lib.php";
}

/** Install-time facts written by install.sh (KEY=value lines). */
function pspm_conf(string $key, ?string $default = null): ?string
{
    static $conf = null;
    if ($conf === null) {
        $conf = [];
        $f = PSPM_ETC . '/pspm.conf';
        if (is_readable($f)) {
            foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if ($line[0] === '#' || !str_contains($line, '=')) continue;
                [$k, $v] = explode('=', $line, 2);
                $conf[trim($k)] = trim($v, " \t\"'");
            }
        }
    }
    return $conf[$key] ?? $default;
}

function pspm_version(): string
{
    $f = PSPM_APP . '/VERSION';
    return is_readable($f) ? trim((string)file_get_contents($f)) : 'dev';
}
