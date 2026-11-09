<?php
// Step 3: TOTP enrolment, mandatory, no skip (plan §9.2, §9.3).
declare(strict_types=1);

$u = Auth::user() ?? redirect('/login');
if (Auth::full() || $u['must_change_password'] || $u['totp_confirmed']) redirect(Auth::nextStep());
if (!$u['totp_secret_enc']) {
    $secret = Totp::newSecret();
    DB::q('UPDATE users SET totp_secret_enc = ?, totp_last_step = 0 WHERE id = ?', [Crypto::seal($secret), $u['id']]);
} else {
    $secret = Crypto::open($u['totp_secret_enc']);
}
$error = '';
if (is_post()) {
    Auth::checkCsrf();
    $step = Totp::verify($secret, (string)post('code'), 0);
    if ($step !== null) {
        DB::q('UPDATE users SET totp_confirmed = true, totp_last_step = ?, updated_at = now() WHERE id = ?', [$step, $u['id']]);
        Audit::log('user.otp_enrol', 'user:' . $u['username']);
        Auth::completeLogin();
        $next = $_COOKIE['__Host-pspm-next'] ?? '/';
        redirect(preg_match('#^/[A-Za-z0-9/_?=&.-]*$#', $next) && !str_starts_with($next, '//') ? $next : '/');
    }
    $error = 'That code is not valid. Check the time on your phone and try the current code.';
}
$host = pspm_conf('BOX_FQDN', gethostname() ?: 'pspm');
$uri = Totp::uri($secret, $u['username'] . '@' . $host, 'PSPM');
page_js('/assets/vendor/qrcode.js');
page_start('Set up two-factor sign-in');
?>
<div class="row justify-content-center"><div class="col-md-8 col-lg-6">
  <h1 class="h4 mb-3">Set up your authenticator</h1>
  <p>PSPM requires a one-time code at every sign-in. Scan the code with an authenticator app
     (for example Microsoft Authenticator, Google Authenticator, 1Password, Aegis), then enter the six digits it shows.</p>
  <div class="row align-items-center">
    <div class="col-sm-6 text-center mb-3"><div id="qr" class="d-inline-block p-2 bg-white border" data-otpauth="<?= h($uri) ?>"></div></div>
    <div class="col-sm-6 mb-3">
      <div class="small text-muted">Or enter this key by hand:</div>
      <code class="fs-6 text-break"><?= h(trim(chunk_split($secret, 4, ' '))) ?></code>
      <div class="small text-muted mt-2">Type: time-based, 6 digits, 30 seconds, SHA-1.</div>
    </div>
  </div>
  <?php if ($error): ?><div class="alert alert-danger py-2"><?= h($error) ?></div><?php endif; ?>
  <form method="post" class="row g-2"><?= csrf_field() ?>
    <div class="col-auto"><input class="form-control" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" placeholder="123456" required autofocus></div>
    <div class="col-auto"><button class="btn btn-primary">Confirm</button></div>
  </form>
  <p class="small text-muted mt-3">Lost the authenticator later? An admin resets it on the server with <code>sudo /opt/pspm/scripts/reset-otp.sh <?= h($u['username']) ?></code>.</p>
</div></div>
<?php page_end();
