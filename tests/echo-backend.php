<?php
// An application that runs at /, for the "without the prefix" check in tests/nginx-check.sh
// (php -S 127.0.0.1:8097 tests/echo-backend.php). It answers with the request as it arrived;
// a few paths answer with a redirect or set cookies, to see what nginx does with them.
declare(strict_types=1);
$path = (string)parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$host = $_SERVER['HTTP_HOST'] ?? '';
match ($path) {
    '/go' => header('Location: /login', true, 302),                                       // relative
    '/abs' => header("Location: http://$host/login", true, 302),                           // to the host name it got
    '/in' => header('Location: /site1/done', true, 302),                                    // already under the prefix
    '/ext' => header('Location: https://login.microsoftonline.com/tenant/authorize', true, 302),   // another host
    '/cookies' => (function () {
        header('Set-Cookie: a=1; Path=/', false);
        header('Set-Cookie: b=2; Path=/site1', false);
        header('Set-Cookie: c=3; Path=/api; HttpOnly', false);
    })(),
    default => null,
};
header('Content-Type: application/json');
echo json_encode(['uri' => $_SERVER['REQUEST_URI'], 'prefix' => $_SERVER['HTTP_X_FORWARDED_PREFIX'] ?? '', 'host' => $host], JSON_UNESCAPED_SLASHES), "\n";
