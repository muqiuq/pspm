<?php
// Step 2: a generated or reset password must be replaced.
declare(strict_types=1);

$u = Auth::user() ?? redirect('/login');
if (!$u['must_change_password']) redirect(Auth::nextStep());
$errors = [];
if (is_post()) {
    Auth::checkCsrf();
    $pw = (string)post('password');
    if (!password_verify((string)post('current'), $u['password_hash'])) $errors['current'] = 'Wrong password.';
    elseif ($e = Auth::validPassword($pw, $u['username'])) $errors['password'] = $e;
    elseif ($pw !== post('password2')) $errors['password2'] = 'The two passwords differ.';
    elseif (password_verify($pw, $u['password_hash'])) $errors['password'] = 'Choose a new password.';
    if (!$errors) {
        DB::q('UPDATE users SET password_hash = ?, must_change_password = false, updated_at = now() WHERE id = ?',
            [password_hash($pw, PASSWORD_ARGON2ID), $u['id']]);
        Audit::log('user.password', 'user:' . $u['username']);
        Auth::refresh();
        redirect(Auth::nextStep());
    }
}
page_start('Choose a password');
?>
<div class="row justify-content-center"><div class="col-sm-8 col-md-5 col-lg-4">
  <h1 class="h4 mb-3">Choose your password</h1>
  <p class="text-muted">The current password was generated or reset. Pick your own (at least 12 characters).</p>
  <form method="post"><?= csrf_field() ?>
    <?= f_text('current', 'Current password', '', $errors, '', 'password', '', ['autocomplete' => 'current-password']) ?>
    <?= f_text('password', 'New password', '', $errors, '', 'password', '', ['autocomplete' => 'new-password']) ?>
    <?= f_text('password2', 'Repeat', '', $errors, '', 'password', '', ['autocomplete' => 'new-password']) ?>
    <button class="btn btn-primary w-100">Save and continue</button>
  </form>
</div></div>
<?php page_end();
