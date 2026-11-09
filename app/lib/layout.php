<?php
declare(strict_types=1);

/** HTML frame and form helpers. Strict CSP: no inline scripts or styles anywhere. */

const NAV = [
    ['/', 'Dashboard', 'viewer'],
    ['/sites', 'Sites', 'viewer'],
    ['/backends', 'Backends', 'viewer'],
    ['/access', 'Access', 'viewer'],
    ['/changes', 'Changes', 'viewer'],
    ['/settings', 'Settings', 'admin'],
    ['/users', 'Users', 'admin'],
    ['/activity', 'Activity', 'viewer'],
    ['/help', 'Help', 'viewer'],
];

function page_start(string $title, string $active = ''): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    $u = Auth::user();
    $full = Auth::full();
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . h($title) . ' · PSPM</title>';
    echo '<link rel="stylesheet" href="/assets/vendor/bootstrap.min.css"><link rel="stylesheet" href="/assets/pspm.css">';
    echo '<link rel="icon" href="/assets/pspm.svg" type="image/svg+xml"></head><body>';
    echo '<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-3"><div class="container-fluid">';
    echo '<a class="navbar-brand d-flex align-items-center" href="/"><img src="/assets/pspm.svg" alt="" width="26" height="26" class="me-2">PSPM</a>';
    if ($u && $full) {
        echo '<button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav"><span class="navbar-toggler-icon"></span></button>';
        echo '<div class="collapse navbar-collapse" id="nav"><ul class="navbar-nav me-auto">';
        foreach (NAV as [$href, $label, $role]) {
            if (!Auth::can($role)) continue;
            $badge = '';
            if ($href === '/changes' && ($n = changes_badge())) $badge = ' <span class="badge text-bg-warning">' . h($n) . '</span>';
            $cls = $active === $href ? ' active' : '';
            echo '<li class="nav-item"><a class="nav-link' . $cls . '" href="' . h($href) . '">' . h($label) . $badge . '</a></li>';
        }
        echo '</ul><ul class="navbar-nav"><li class="nav-item dropdown"><a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">'
            . h($u['username']) . ' <span class="badge text-bg-secondary">' . h($u['role']) . '</span></a>'
            . '<ul class="dropdown-menu dropdown-menu-end"><li><a class="dropdown-item" href="/account">Account</a></li>'
            . '<li><a class="dropdown-item" href="/about">About</a></li><li><hr class="dropdown-divider"></li>'
            . '<li><form method="post" action="/logout" class="px-3">' . csrf_field() . '<button class="btn btn-link p-0">Sign out</button></form></li></ul></li></ul></div>';
    } elseif ($u) {
        echo '<form method="post" action="/logout" class="ms-auto">' . csrf_field() . '<button class="btn btn-sm btn-outline-light">Sign out</button></form>';
    }
    echo '</div></nav><main class="container-fluid pb-5">';
    flash_render();
}

/** Extra script files for this page (loaded before pspm.js). */
function page_js(string $src): void
{
    $GLOBALS['pspm_js'][] = $src;
}

function page_end(): void
{
    echo '</main><script src="/assets/vendor/bootstrap.bundle.min.js"></script>';
    foreach ($GLOBALS['pspm_js'] ?? [] as $src) echo '<script src="' . h($src) . '"></script>';
    echo '<script src="/assets/pspm.js"></script></body></html>';
    exit;
}

function page_error(int $code, string $message): never
{
    http_response_code($code);
    page_start("Error $code");
    echo '<div class="alert alert-danger">' . h($message) . '</div><p><a href="/">Back to the dashboard</a></p>';
    page_end();
}

/** Changes not applied yet: newest revision not live, or working copy changed. */
function changes_badge(): string
{
    static $v = null;
    if ($v !== null) return $v;
    try {
        $live = Live::revision();
        $latest = Revisions::latest();
        $n = 0;
        if ($latest && (int)($live['id'] ?? 0) !== (int)$latest['id']) $n++;
        if (Revisions::workingChanged()) $n++;
        return $v = $n ? (string)$n : '';
    } catch (Throwable) { return $v = ''; }
}

// ---- one-line result after an action (the only thing ever shown on top of a page)

function flash(string $msg, string $type = 'success'): void
{
    setcookie('__Host-pspm-flash', base64_encode(json_enc([$type, $msg])), ['path' => '/', 'secure' => true,
        'httponly' => true, 'samesite' => 'Strict']);
}

function flash_render(): void
{
    $c = $_COOKIE['__Host-pspm-flash'] ?? '';
    if ($c === '') return;
    setcookie('__Host-pspm-flash', '', ['expires' => 1, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
    try { [$type, $msg] = json_dec((string)base64_decode($c)); } catch (Throwable) { return; }
    $type = in_array($type, ['success', 'danger', 'warning', 'info'], true) ? $type : 'info';
    echo '<div class="alert alert-' . $type . ' alert-dismissible py-2" role="status">' . h($msg)
        . '<button type="button" class="btn-close py-2" data-bs-dismiss="alert"></button></div>';
}

// ---- forms

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . h(Auth::csrf()) . '">';
}

function nonce_field(string $purpose): string
{
    $n = Crypto::token(18);
    DB::q("INSERT INTO nonces (nonce, user_id, purpose, expires_at) VALUES (?, ?, ?, now() + interval '30 minutes')",
        [$n, Auth::user()['id'], $purpose]);
    return '<input type="hidden" name="_nonce" value="' . h($n) . '">';
}

function nonce_consume(string $purpose): bool
{
    $n = (string)($_POST['_nonce'] ?? '');
    DB::q('DELETE FROM nonces WHERE expires_at < now()');
    return DB::q('DELETE FROM nonces WHERE nonce = ? AND user_id = ? AND purpose = ?', [$n, Auth::user()['id'], $purpose])->rowCount() === 1;
}

function field_err(array $errors, string $key): string
{
    return isset($errors[$key]) ? '<div class="invalid-feedback d-block">' . h($errors[$key]) . '</div>' : '';
}

function f_text(string $name, string $label, mixed $value, array $errors = [], string $help = '', string $type = 'text', string $key = '', array $attr = []): string
{
    $key = $key ?: $name;
    $id = 'f_' . preg_replace('/\W+/', '_', $name);
    $inv = isset($errors[$key]) ? ' is-invalid' : '';
    $extra = '';
    foreach ($attr as $k => $v) $extra .= ' ' . h($k) . '="' . h($v) . '"';
    return '<div class="mb-3"><label class="form-label" for="' . $id . '">' . h($label) . '</label>'
        . '<input class="form-control' . $inv . '" type="' . h($type) . '" id="' . $id . '" name="' . h($name) . '" value="' . h($value) . '"' . $extra . '>'
        . ($help ? '<div class="form-text">' . h($help) . '</div>' : '') . field_err($errors, $key) . '</div>';
}

function f_area(string $name, string $label, string $value, array $errors = [], string $help = '', int $rows = 4, string $key = ''): string
{
    $key = $key ?: $name;
    $id = 'f_' . preg_replace('/\W+/', '_', $name);
    $inv = isset($errors[$key]) ? ' is-invalid' : '';
    return '<div class="mb-3"><label class="form-label" for="' . $id . '">' . h($label) . '</label>'
        . '<textarea class="form-control font-monospace' . $inv . '" id="' . $id . '" name="' . h($name) . '" rows="' . $rows . '">' . h($value) . '</textarea>'
        . ($help ? '<div class="form-text">' . h($help) . '</div>' : '') . field_err($errors, $key) . '</div>';
}

function f_select(string $name, string $label, mixed $value, array $options, array $errors = [], string $help = '', string $key = ''): string
{
    $key = $key ?: $name;
    $id = 'f_' . preg_replace('/\W+/', '_', $name);
    $o = '<div class="mb-3"><label class="form-label" for="' . $id . '">' . h($label) . '</label><select class="form-select'
        . (isset($errors[$key]) ? ' is-invalid' : '') . '" id="' . $id . '" name="' . h($name) . '">';
    foreach ($options as $v => $l) $o .= '<option value="' . h($v) . '"' . ((string)$v === (string)$value ? ' selected' : '') . '>' . h($l) . '</option>';
    return $o . '</select>' . ($help ? '<div class="form-text">' . h($help) . '</div>' : '') . field_err($errors, $key) . '</div>';
}

function f_check(string $name, string $label, bool $checked, string $help = '', string $value = '1'): string
{
    $id = 'f_' . preg_replace('/\W+/', '_', $name . '_' . $value);
    return '<div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="' . $id . '" name="' . h($name) . '" value="' . h($value) . '"'
        . ($checked ? ' checked' : '') . '><label class="form-check-label" for="' . $id . '">' . h($label) . '</label>'
        . ($help ? '<div class="form-text mt-0">' . h($help) . '</div>' : '') . '</div>';
}

function badge(string $level, string $text, string $title = ''): string
{
    $cls = ['green' => 'success', 'amber' => 'warning', 'red' => 'danger', 'grey' => 'secondary', 'info' => 'info'][$level] ?? 'secondary';
    return '<span class="badge text-bg-' . $cls . '"' . ($title ? ' title="' . h($title) . '" data-bs-toggle="tooltip"' : '') . '>' . h($text) . '</span>';
}

function errors_box(array $errors): string
{
    if (!$errors) return '';
    $o = '<div class="alert alert-danger py-2"><ul class="mb-0">';
    foreach ($errors as $k => $e) $o .= '<li>' . h(is_int($k) ? $e : "$k: $e") . '</li>';
    return $o . '</ul></div>';
}

/** Post-only action button with CSRF and optional confirmation (data-confirm, handled by pspm.js). */
function post_button(string $action, string $label, array $fields = [], string $cls = 'btn-outline-secondary btn-sm', string $confirm = ''): string
{
    $o = '<form method="post" action="' . h($action) . '" class="d-inline"' . ($confirm ? ' data-confirm="' . h($confirm) . '"' : '') . '>' . csrf_field();
    foreach ($fields as $k => $v) $o .= '<input type="hidden" name="' . h($k) . '" value="' . h($v) . '">';
    return $o . '<button class="btn ' . h($cls) . '">' . h($label) . '</button></form>';
}

function is_post(): bool { return ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST'; }
function post(string $k, mixed $d = ''): mixed { return $_POST[$k] ?? $d; }
function get(string $k, mixed $d = ''): mixed { return $_GET[$k] ?? $d; }
