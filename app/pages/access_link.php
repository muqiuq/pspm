<?php
// https://<site host>/.pspm/access/<token> — public, rate-limited by nginx (plan §11.1).
declare(strict_types=1);

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
$host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
$host = preg_replace('/:\d+$/', '', $host) ?? '';
if (!DB::available()) { http_response_code(503); echo 'Temporarily unavailable. Please try again in a few minutes.'; exit; }
[$ok, $msg, $after] = Access::useLink($host, $token, IP::remote());
if ($ok && $after) {
    header('Location: https://' . $host . $after, true, 303);
    exit;
}
http_response_code($ok ? 200 : 403);
header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Access</title></head>'
   . '<body><main><h1>' . ($ok ? 'Access granted' : 'Access not granted') . '</h1><p>' . h($msg) . '</p></main></body></html>';
