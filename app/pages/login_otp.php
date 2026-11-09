<?php
// Step 4: the TOTP code on every sign-in.
declare(strict_types=1);

$u = Auth::user() ?? redirect('/login');
if (Auth::full() || $u['must_change_password'] || !$u['totp_confirmed']) redirect(Auth::nextStep());
$error = '';
if (is_post()) {
    Auth::checkCsrf();
    if (Auth::verifyOtp((string)post('code'))) {
        Auth::completeLogin();
        $next = $_COOKIE['__Host-pspm-next'] ?? '/';
        redirect(preg_match('#^/[A-Za-z0-9/_?=&.-]*$#', $next) && !str_starts_with($next, '//') ? $next : '/');
    }
    $error = 'That code is not valid (or was already used). Wait for the next one.';
}
page_start('One-time code');
?>
<div class="row justify-content-center"><div class="col-sm-8 col-md-5 col-lg-4">
  <h1 class="h4 mb-3">One-time code</h1>
  <?php if ($error): ?><div class="alert alert-danger py-2"><?= h($error) ?></div><?php endif; ?>
  <form method="post"><?= csrf_field() ?>
    <?= f_text('code', 'Code from your authenticator', '', [], '', 'text', '', ['inputmode' => 'numeric', 'autocomplete' => 'one-time-code', 'autofocus' => 'autofocus', 'required' => 'required']) ?>
    <button class="btn btn-primary w-100">Sign in</button>
  </form>
</div></div>
<?php page_end();
