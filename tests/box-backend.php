<?php
// Backend for tests/box-e2e.sh (php -S 127.0.0.1:8099 tests/box-backend.php): answers with
// one response header of ?n bytes, to test the response header buffer of a backend; on the
// sign-in callbacks of an application with its own sign-in, the request as the backend got it.
declare(strict_types=1);
if (in_array(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), ['/signin-oidc', '/signout-callback-oidc'], true)) {
    header('Content-Type: application/json');
    echo json_encode(['method' => $_SERVER['REQUEST_METHOD'], 'host' => $_SERVER['HTTP_HOST'] ?? '', 'proto' => $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '',
        'xff' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '', 'cookie' => $_SERVER['HTTP_COOKIE'] ?? '', 'body' => file_get_contents('php://input'),
        'user' => $_SERVER['HTTP_X_FORWARDED_USER'] ?? ''], JSON_UNESCAPED_SLASHES), "\n";
    exit;
}
header('X-Big: ' . str_repeat('a', max(1, min(200000, (int)($_GET['n'] ?? 100)))));
echo "ok\n";
