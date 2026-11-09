<?php
// The single entry point of the web UI. nginx sends every UI request here; page files
// under app/pages/ are never reachable directly.
declare(strict_types=1);

require __DIR__ . '/../lib/bootstrap.php';

$listener = $_SERVER['PSPM_LISTENER'] ?? 'dev';
$path = rawurldecode((string)(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/'));
if ($path !== '/') $path = rtrim($path, '/');

set_exception_handler(function (Throwable $e) {
    error_log('PSPM: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
    if (!headers_sent()) http_response_code(500);
    echo '<!doctype html><title>PSPM error</title><p>Something went wrong. The details are in the PHP error log '
        . '(<code>journalctl -u php8.4-fpm</code>).</p>';
});

// Site host names only ever reach the access-link handler (plan §11.1).
if ($listener === 'site') {
    if (preg_match('#^/\.pspm/access/([A-Za-z0-9_-]{20,64})$#', $path, $m)) {
        $token = $m[1];
        require PSPM_APP . '/pages/access_link.php';
    } else {
        http_response_code(404);
    }
    exit;
}

if ($path === '/healthz') {
    header('Content-Type: application/json');
    $db = DB::available();
    $schema = $db ? DB::schemaVersion() : 0;
    $ok = $db && $schema >= PSPM_SCHEMA;
    http_response_code($ok ? 200 : 503);
    echo json_enc(['ok' => $ok, 'db' => $db, 'schema' => $schema, 'needs' => PSPM_SCHEMA, 'version' => pspm_version()]);
    exit;
}

if (!DB::available() || DB::schemaVersion() < PSPM_SCHEMA) {
    http_response_code(503);
    header('Retry-After: 30');
    echo '<!doctype html><html><head><title>PSPM maintenance</title><link rel="stylesheet" href="/assets/vendor/bootstrap.min.css"></head>'
        . '<body class="p-5"><h1 class="h4">PSPM is not available right now</h1><p>The database is not reachable, or its schema is older '
        . 'than this version needs. On the server run <code>sudo /opt/pspm/install.sh</code>. Sites keep working.</p></body></html>';
    exit;
}

$routes = [
    '/'               => 'dashboard',
    '/login'          => 'login',
    '/login/password' => 'login_password',
    '/login/enrol'    => 'login_enrol',
    '/login/otp'      => 'login_otp',
    '/logout'         => 'logout',
    '/reauth'         => 'reauth',
    '/account'        => 'account',
    '/about'          => 'about',
    '/sites'          => 'sites',
    '/sites/edit'     => 'site_edit',
    '/backends'       => 'backends',
    '/backends/edit'  => 'backend_edit',
    '/access'         => 'access',
    '/changes'        => 'changes',
    '/changes/file'   => 'changes_file',
    '/changes/apply'  => 'changes_apply',
    '/settings'       => 'settings',
    '/users'          => 'users',
    '/activity'       => 'activity',
    '/help'           => 'help',
];

$page = $routes[$path] ?? null;
if ($page === null && preg_match('#^/help/([a-z0-9-]+)$#', $path, $m)) { $page = 'help'; $_GET['page'] = $m[1]; }
if ($page === null) page_error(404, 'There is no such page.');
require PSPM_APP . "/pages/$page.php";
