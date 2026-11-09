<?php
// Step 1: user name and password (plan §9.2).
declare(strict_types=1);

if (Auth::full()) redirect('/');
$error = '';
if (is_post()) {
    [$ok, $error] = Auth::attemptPassword((string)post('username'), (string)post('password'));
    if ($ok) {
        $next = (string)get('next', '/');
        if (!preg_match('#^/[A-Za-z0-9/_?=&.-]*$#', $next) || str_starts_with($next, '//')) $next = '/';
        setcookie('__Host-pspm-next', $next, ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
        redirect(Auth::nextStep());
    }
}
page_start('Sign in');
?>
<div class="row justify-content-center"><div class="col-sm-8 col-md-5 col-lg-4">
  <h1 class="h4 mb-3">Sign in to PSPM</h1>
  <?php if ($error): ?><div class="alert alert-danger py-2"><?= h($error) ?></div><?php endif; ?>
  <form method="post" autocomplete="on">
    <?= f_text('username', 'User name', post('username'), [], '', 'text', '', ['autocomplete' => 'username', 'autofocus' => 'autofocus', 'required' => 'required']) ?>
    <?= f_text('password', 'Password', '', [], '', 'password', '', ['autocomplete' => 'current-password', 'required' => 'required']) ?>
    <button class="btn btn-primary w-100">Continue</button>
  </form>
  <p class="text-muted small mt-4 text-center">PSPM · Philipp's Secure Proxy Manager · <?= h(pspm_version()) ?></p>
</div></div>
<?php page_end();
