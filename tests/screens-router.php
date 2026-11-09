<?php
// Router for the PHP built-in server in tests/screenshots.sh: /assets/ from app/assets (nginx
// does this in production, conf/ui.conf), everything else to the UI.
declare(strict_types=1);
$path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (str_starts_with($path, '/assets/')) {
    $f = realpath('/src/app/assets/' . substr($path, 8));
    if ($f !== false && str_starts_with($f, '/src/app/assets/') && is_file($f)) {
        $types = ['css' => 'text/css', 'js' => 'text/javascript', 'svg' => 'image/svg+xml', 'png' => 'image/png'];
        header('Content-Type: ' . ($types[pathinfo($f, PATHINFO_EXTENSION)] ?? 'application/octet-stream'));
        readfile($f);
        return true;
    }
    http_response_code(404);
    return true;
}
require '/src/app/public/index.php';
