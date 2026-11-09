<?php
// Re-authentication for sensitive actions: password and a fresh TOTP code.
declare(strict_types=1);

$u = Auth::require('viewer');
$next = (string)get('next', '/');
if (!preg_match('#^/[A-Za-z0-9/_?=&.%-]*$#', $next) || str_starts_with($next, '//')) $next = '/';
$error = '';
if (is_post()) {
    if (password_verify((string)post('password'), $u['password_hash']) && Auth::verifyOtp((string)post('code'))) {
        Auth::markReauth();
        Audit::log('reauth', 'user:' . $u['username']);
        redirect($next);
    }
    $error = 'Password or code is wrong.';
}
page_start('Confirm it is you');
?>
<div class="row justify-content-center"><div class="col-sm-8 col-md-5 col-lg-4">
  <h1 class="h4 mb-3">Confirm it is you</h1>
  <p class="text-muted">This action needs your password and a current code again.</p>
  <?php if ($error): ?><div class="alert alert-danger py-2"><?= h($error) ?></div><?php endif; ?>
  <form method="post"><?= csrf_field() ?>
    <?= f_text('password', 'Password', '', [], '', 'password', '', ['autocomplete' => 'current-password', 'autofocus' => 'autofocus']) ?>
    <?= f_text('code', 'One-time code', '', [], '', 'text', '', ['inputmode' => 'numeric', 'autocomplete' => 'one-time-code']) ?>
    <button class="btn btn-primary w-100">Confirm</button>
  </form>
</div></div>
<?php page_end();
