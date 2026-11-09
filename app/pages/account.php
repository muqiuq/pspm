<?php
// Your own account: password, sessions.
declare(strict_types=1);

$u = Auth::require('viewer');
$errors = [];
if (is_post()) {
    if (post('action') === 'password') {
        $pw = (string)post('password');
        if (!password_verify((string)post('current'), $u['password_hash'])) $errors['current'] = 'Wrong password.';
        elseif ($e = Auth::validPassword($pw, $u['username'])) $errors['password'] = $e;
        elseif ($pw !== post('password2')) $errors['password2'] = 'The two passwords differ.';
        if (!$errors) {
            DB::q('UPDATE users SET password_hash = ?, updated_at = now() WHERE id = ?', [password_hash($pw, PASSWORD_ARGON2ID), $u['id']]);
            DB::q('DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?', [$u['id'], Auth::session()['id_hash']]);
            Audit::log('user.password', 'user:' . $u['username']);
            flash('Password changed. Your other sessions were ended.');
            redirect('/account');
        }
    } elseif (post('action') === 'end_others') {
        DB::q('DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?', [$u['id'], Auth::session()['id_hash']]);
        flash('Your other sessions were ended.');
        redirect('/account');
    }
}
$sessions = DB::all("SELECT * FROM sessions WHERE user_id = ? AND stage = 'full' ORDER BY last_seen_at DESC", [$u['id']]);
page_start('Account');
?>
<h1 class="h4 mb-3">Account <?= h($u['username']) ?> <span class="badge text-bg-secondary"><?= h($u['role']) ?></span></h1>
<div class="row g-4">
  <div class="col-lg-5">
    <h2 class="h6">Change password</h2>
    <form method="post"><?= csrf_field() ?><input type="hidden" name="action" value="password">
      <?= f_text('current', 'Current password', '', $errors, '', 'password', '', ['autocomplete' => 'current-password']) ?>
      <?= f_text('password', 'New password', '', $errors, 'At least 12 characters.', 'password', '', ['autocomplete' => 'new-password']) ?>
      <?= f_text('password2', 'Repeat', '', $errors, '', 'password', '', ['autocomplete' => 'new-password']) ?>
      <button class="btn btn-primary btn-sm">Change</button></form>
    <p class="small text-muted mt-3">A lost authenticator is reset on the server: <code>sudo /opt/pspm/scripts/reset-otp.sh <?= h($u['username']) ?></code></p>
  </div>
  <div class="col-lg-7">
    <h2 class="h6">Your sessions</h2>
    <table class="table table-sm small"><thead><tr><th>From</th><th>Started</th><th>Last seen</th><th>Browser</th></tr></thead><tbody>
    <?php foreach ($sessions as $s): ?><tr><td><?= h($s['ip']) ?><?= $s['id_hash'] === Auth::session()['id_hash'] ? ' ' . badge('info', 'this one') : '' ?></td>
      <td><?= h(fmt_time($s['created_at'])) ?></td><td><?= h(ago($s['last_seen_at'])) ?></td><td><?= h(substr((string)$s['user_agent'], 0, 70)) ?></td></tr><?php endforeach; ?>
    </tbody></table>
    <?= count($sessions) > 1 ? post_button('/account', 'End my other sessions', ['action' => 'end_others']) : '' ?>
  </div>
</div>
<?php page_end();
