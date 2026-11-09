<?php
// Drives the UI like a browser: sign-in, password change, TOTP enrolment, then a site.
declare(strict_types=1);
$serverEtc = getenv('PSPM_ETC') ?: '/tmp/etc';   // the server's, for the one step that changes settings directly
putenv('PSPM_ETC=/nonexistent');
require '/src/app/lib/totp.php';
require '/src/app/lib/util.php';

$base = getenv('BASE') ?: 'http://127.0.0.1:8080';
$user = getenv('ADMIN_USER') ?: 'admin';
$cookies = [];
function req(string $method, string $path, array $form = []): array
{
    global $base, $cookies;
    usleep(300000);   // stay below the UI rate limits when run through nginx
    $ch = curl_init($base . $path);
    $hdr = [];
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_HTTPHEADER => ['Cookie: ' . implode('; ', array_map(fn($k, $v) => "$k=$v", array_keys($cookies), $cookies))]]);
    if ($method === 'POST') { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form)); }
    $res = (string)curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    $head = substr($res, 0, $hs); $body = substr($res, $hs);
    preg_match_all('/^Set-Cookie: ([^=]+)=([^;]*)/mi', $head, $m, PREG_SET_ORDER);
    foreach ($m as [, $k, $v]) { if ($v === '' || $v === 'deleted') unset($cookies[$k]); else $cookies[$k] = $v; }
    preg_match('/^Location: (.*)$/mi', $head, $loc);
    return [$code, $body, trim($loc[1] ?? '')];
}
function csrf(string $html): string { preg_match('/name="_csrf" value="([^"]+)"/', $html, $m); return $m[1] ?? ''; }
function check(bool $c, string $what): void { echo ($c ? 'ok   ' : 'FAIL ') . $what . "\n"; if (!$c) exit(1); }

[$c, $b] = req('GET', '/');
check($c === 303, 'dashboard redirects to sign-in when signed out');
[$c] = req('POST', '/login', ['username' => $user, 'password' => 'wrong']);
check($c === 200, 'wrong password stays on the sign-in page');
[$c, , $loc] = req('POST', '/login', ['username' => $user, 'password' => getenv('ADMIN_PW')]);
check($c === 303 && $loc === '/login/password', 'right password leads to the password change');
[$c, $b] = req('GET', '/login/password');
$new = 'a-much-better-password-42';
[$c, $b2, $loc] = req('POST', '/login/password', ['_csrf' => csrf($b), 'current' => getenv('ADMIN_PW'), 'password' => $new, 'password2' => $new]);
check($c === 303 && $loc === '/login/enrol', 'password changed, enrolment is next');
[$c, $b] = req('GET', '/');
check($c === 303, 'the dashboard stays closed before OTP enrolment');
[$c, $b] = req('GET', '/login/enrol');
preg_match('#<code class="fs-6 text-break">([A-Z2-7 ]+)</code>#', $b, $m);
$secret = str_replace(' ', '', $m[1] ?? '');
check(strlen($secret) === 32, 'enrolment shows a 160-bit secret');
check(str_contains($b, 'data-otpauth="otpauth://totp/PSPM'), 'enrolment has the otpauth URI for the QR code');
[$c, , $loc] = req('POST', '/login/enrol', ['_csrf' => csrf($b), 'code' => '000000']);
check($c === 200, 'a wrong code is refused');
[$c, , $loc] = req('POST', '/login/enrol', ['_csrf' => csrf($b), 'code' => Totp::code($secret, intdiv(time(), 30))]);
check($c === 303 && $loc === '/', 'the right code completes the sign-in');
[$c, $b] = req('GET', '/');
check($c === 200 && str_contains($b, 'Proxy') && str_contains($b, 'Changes'), 'dashboard renders');
check(!str_contains($b, 'Philipp'), 'the dashboard does not show the full name');
foreach (['/sites', '/backends', '/access', '/certificates', '/signin', '/security', '/security?tab=behaviour', '/security?tab=traps', '/security?tab=blocklists', '/security?tab=trusted', '/security?tab=verdicts', '/backup', '/changes', '/settings', '/activity', '/help', '/account', '/about', '/sites/edit', '/backends/edit'] as $p) {
    [$c, $b] = req('GET', $p);
    check($c === 200, "GET $p");
}
[$c, $b] = req('GET', '/backends/edit');
[$c, , $loc] = req('POST', '/backends/edit', ['_csrf' => csrf($b), 'name' => 'app', 'protocol' => 'http', 'keepalive' => '16', 'tls_verify' => 'off',
    'servers' => [['addr' => '10.0.0.5:8080', 'weight' => '1', 'max_fails' => '1', 'fail_timeout' => '10']]]);
check($c === 303, 'backend saved');
[$c, $b] = req('GET', '/backends');
preg_match('#/backends/edit\?id=([0-9a-f-]{36})#', $b, $m);
$bid = $m[1] ?? '';
check($bid !== '', 'backend listed');
[$c, $b] = req('GET', '/sites/edit');
$form = ['_csrf' => csrf($b), 'hosts' => "app.example.ch\nwww.app.example.ch", 'description' => 'Smoke', 'enabled' => '1',
    'conditions' => ['lan', 'cleared'], 'denied' => '403', 'denied_url' => '', 'client_certs' => 'optional',
    'tls_mode' => 'letsencrypt', 'tls_profile' => 'default', 'http2' => '1', 'hsts_mode' => 'default', 'hsts_max_age' => '31536000', 'hsts_sub' => '1',
    'port80' => 'redirect', 'backend' => $bid, 'max_body' => '50m', 'host_header' => 'client', 'host_fixed' => '',
    'connect_timeout' => '10', 'read_timeout' => '60', 'send_timeout' => '60', 'rate' => 'standard', 'limit_conn' => '0', 'websocket' => '1',
    'request_buffering' => '1', 'response_buffering' => '1', 'security' => 'default', 'hide_headers' => '',
    'routes' => [['id' => 'r1', 'match' => 'prefix', 'paths' => '/', 'action' => 'proxy', 'listeners' => ['all'], 'status' => '404', 'redirect_code' => '302'],
                 ['id' => 'r2', 'match' => 'prefix', 'paths' => '/bad path', 'action' => 'proxy', 'listeners' => ['all'], 'status' => '404', 'redirect_code' => '302']]];
[$c, $b] = req('POST', '/sites/edit', $form);
check($c === 200 && str_contains($b, 'Not an allowed path'), 'an invalid path is refused with a message');
$form['routes'][1]['paths'] = '/api/';
$form['routes'][1]['ov_conditions'] = ['public'];
[$c, , $loc] = req('POST', '/sites/edit', $form);
check($c === 303, 'site saved');
[$c, $b] = req('GET', '/changes');
check($c === 200 && str_contains($b, 'Ready to apply'), 'changes offers Ready to apply');
check(str_contains($b, 'sites/app.example.ch.conf'), 'the preview diff lists the new site file');
[$c, , $loc] = req('POST', '/changes', ['_csrf' => csrf($b), 'action' => 'ready', 'message' => 'smoke test']);
check($c === 303, 'revision committed');
[$c, $b] = req('GET', '/');
check(str_contains($b, 'is ready'), 'the dashboard says the revision is ready');
[$c, $b] = req('GET', '/certificates');
check($c === 200 && str_contains($b, 'Server certificates') && str_contains($b, 'pspm-smoke-pspm-test') && str_contains($b, 'renewal is overdue'),
    'certificates: overview with a Let\'s Encrypt certificate whose renewal is overdue');
check(str_contains($b, 'IP certificate (self-signed)') && str_contains($b, 'SSH tunnel (127.0.0.1:9443)'), 'certificates: the IP certificate and what uses it');
[$c, $b] = req('GET', '/access');
check($c === 200 && str_contains($b, 'Create link'), 'access offers links for the site');
[$c, $b] = req('POST', '/access', ['_csrf' => csrf($b), 'action' => 'block', 'ip' => '10.0.0.0/8', 'days' => '1', 'reason' => 'x']);
[$c, $b] = req('GET', '/access');
check(!str_contains($b, '10.0.0.0/8'), 'private ranges cannot be blocked');
// links to the admin UI (the logic: tests/access-check.php; here the page)
check(str_contains($b, 'Links to the admin UI: set an admin host name'), 'access explains how to enable links to the admin UI');
exec('PSPM_ETC=' . escapeshellarg($serverEtc) . ' php -r ' . escapeshellarg('require "/src/app/lib/bootstrap.php"; $g = Settings::global(); $g["admin_host"] = "proxy.pspm.test"; $g["admin_access"] = ["lan", "cleared", "cert"]; Settings::saveGlobal($g);'), $out, $rc);
check($rc === 0, 'admin host name and "access links" set for the admin UI');
[$c, $b] = req('GET', '/access');
check(str_contains($b, '<option value="admin">PSPM admin UI (proxy.pspm.test)</option>'), 'access offers links to the admin UI');
[$c, $b] = req('POST', '/access', ['_csrf' => csrf($b), 'action' => 'create_link', 'site' => 'admin', 'label' => 'smoke admin', 'grant' => '3600', 'after' => '/']);
check($c === 200 && preg_match('#value="https://proxy\.pspm\.test/\.pspm/access/[A-Za-z0-9_-]{20,}"#', $b) === 1 && str_contains($b, 'opens the admin UI'),
    'a link to the admin UI is created and shown once');
check(str_contains($b, '<td>PSPM admin UI</td><td>smoke admin</td>'), 'the link list names the admin UI');
[$c, , $loc] = req('POST', '/logout', ['_csrf' => csrf($b)]);
check($c === 303, 'sign-out');
[$c] = req('GET', '/');
check($c === 303, 'signed out for real');
echo "smoke test passed\n";
