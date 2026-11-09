<?php
// User management (plan §9). Admins only, with re-authentication for changes.
declare(strict_types=1);

$u = Auth::require('admin');
Auth::requireReauth();
$shown = null;
if (is_post()) {
    $action = post('action');
    $target = DB::one('SELECT * FROM users WHERE id = ?', [(int)post('id')]);
    if ($action === 'create') {
        $name = strtolower(trim((string)post('username')));
        $role = Validate::enum(post('role'), ['admin', 'operator', 'viewer']);
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{1,31}$/', $name) || !$role) { flash('User name: 2–32 characters a–z 0–9 . _ -; and a role.', 'danger'); redirect('/users'); }
        if (DB::val('SELECT 1 FROM users WHERE username = ?', [$name])) { flash('That user exists.', 'danger'); redirect('/users'); }
        $pw = Crypto::password();
        DB::q('INSERT INTO users (username, role, password_hash, must_change_password) VALUES (?, ?, ?, true)', [$name, $role, password_hash($pw, PASSWORD_ARGON2ID)]);
        Audit::log('user.create', "user:$name", ['role' => $role]);
        $shown = [$name, $pw];
    } elseif ($target && $target['id'] == $u['id'] && in_array($action, ['role', 'disable', 'delete'], true)) {
        flash('You cannot change your own role or disable yourself.', 'danger');
        redirect('/users');
    } elseif ($target && $action === 'role' && ($role = Validate::enum(post('role'), ['admin', 'operator', 'viewer']))) {
        DB::q('UPDATE users SET role = ?, updated_at = now() WHERE id = ?', [$role, $target['id']]);
        Audit::log('user.role', 'user:' . $target['username'], ['from' => $target['role'], 'to' => $role]);
        flash("{$target['username']} is now $role.");
    } elseif ($target && $action === 'disable') {
        $dis = !$target['disabled'];
        DB::q('UPDATE users SET disabled = ?, updated_at = now() WHERE id = ?', [$dis, $target['id']]);
        if ($dis) Auth::endUserSessions((int)$target['id']);
        Audit::log($dis ? 'user.disable' : 'user.enable', 'user:' . $target['username']);
        flash($target['username'] . ($dis ? ' disabled.' : ' enabled.'));
    } elseif ($target && $action === 'reset_password') {
        $pw = Crypto::password();
        DB::q('UPDATE users SET password_hash = ?, must_change_password = true, failed_logins = 0, updated_at = now() WHERE id = ?', [password_hash($pw, PASSWORD_ARGON2ID), $target['id']]);
        Auth::endUserSessions((int)$target['id']);
        Audit::log('user.reset_password', 'user:' . $target['username']);
        $shown = [$target['username'], $pw];
    } elseif ($target && $action === 'reset_otp') {
        DB::q('UPDATE users SET totp_secret_enc = NULL, totp_confirmed = false, totp_last_step = 0, updated_at = now() WHERE id = ?', [$target['id']]);
        Auth::endUserSessions((int)$target['id']);
        Audit::log('user.reset_otp', 'user:' . $target['username']);
        flash("{$target['username']} enrols a new authenticator at the next sign-in.");
    } elseif ($target && $action === 'delete') {
        DB::q('DELETE FROM users WHERE id = ?', [$target['id']]);
        Audit::log('user.delete', 'user:' . $target['username']);
        flash("{$target['username']} deleted.");
    } elseif ($action === 'end_session') {
        DB::q('DELETE FROM sessions WHERE id_hash = ?', [(string)post('session')]);
        flash('Session ended.');
    }
    if (!$shown) redirect('/users');
}
$users = DB::all('SELECT u.*, (SELECT count(*) FROM sessions s WHERE s.user_id = u.id AND s.stage = \'full\') AS sessions FROM users u ORDER BY username');
$sessions = DB::all("SELECT s.*, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.stage = 'full' ORDER BY s.last_seen_at DESC");
page_start('Users', '/users');
?>
<h1 class="h4 mb-3">Users</h1>
<?php if ($shown): ?>
  <div class="alert alert-warning">Password for <strong><?= h($shown[0]) ?></strong>, shown once: <code class="fs-6"><?= h($shown[1]) ?></code>
    <div class="small">They must choose their own password and enrol an authenticator at the first sign-in.</div></div>
<?php endif; ?>
<table class="table table-sm align-middle">
  <thead><tr><th>User</th><th>Role</th><th>OTP</th><th>Last sign-in</th><th>Sessions</th><th></th></tr></thead><tbody>
  <?php foreach ($users as $x): ?>
    <tr class="<?= $x['disabled'] ? 'text-muted' : '' ?>">
      <td><?= h($x['username']) ?><?= $x['disabled'] ? ' ' . badge('grey', 'disabled') : '' ?><?= $x['must_change_password'] ? ' ' . badge('amber', 'password pending') : '' ?></td>
      <td><form method="post" class="d-inline-flex gap-1"><?= csrf_field() ?><input type="hidden" name="action" value="role"><input type="hidden" name="id" value="<?= h($x['id']) ?>">
        <select class="form-select form-select-sm" name="role"><?php foreach (['admin', 'operator', 'viewer'] as $r): ?><option <?= $r === $x['role'] ? 'selected' : '' ?>><?= $r ?></option><?php endforeach; ?></select>
        <button class="btn btn-sm btn-outline-secondary">Set</button></form></td>
      <td><?= $x['totp_confirmed'] ? badge('green', 'enrolled') : badge('amber', 'not yet') ?></td>
      <td class="small"><?= h(fmt_time($x['last_login_at'])) ?> <?= h($x['last_login_ip']) ?></td>
      <td><?= h($x['sessions']) ?></td>
      <td class="text-end text-nowrap">
        <?= post_button('/users', 'Reset password', ['action' => 'reset_password', 'id' => $x['id']], 'btn-outline-secondary btn-sm', "Reset the password of {$x['username']}? Their sessions end.") ?>
        <?= post_button('/users', 'Reset OTP', ['action' => 'reset_otp', 'id' => $x['id']], 'btn-outline-secondary btn-sm', "Reset the authenticator of {$x['username']}?") ?>
        <?= post_button('/users', $x['disabled'] ? 'Enable' : 'Disable', ['action' => 'disable', 'id' => $x['id']], 'btn-outline-secondary btn-sm') ?>
        <?= post_button('/users', 'Delete', ['action' => 'delete', 'id' => $x['id']], 'btn-outline-danger btn-sm', "Delete {$x['username']}?") ?>
      </td></tr>
  <?php endforeach; ?></tbody>
</table>
<form method="post" class="row g-2 align-items-end mb-4 col-lg-8"><?= csrf_field() ?><input type="hidden" name="action" value="create">
  <div class="col"><label class="form-label small">New user</label><input class="form-control form-control-sm" name="username" placeholder="alice"></div>
  <div class="col-auto"><select class="form-select form-select-sm" name="role"><option>viewer</option><option>operator</option><option>admin</option></select></div>
  <div class="col-auto"><button class="btn btn-primary btn-sm">Create with a generated password</button></div>
</form>
<h2 class="h6">Open sessions</h2>
<table class="table table-sm small"><thead><tr><th>User</th><th>From</th><th>Started</th><th>Last seen</th><th>Browser</th><th></th></tr></thead><tbody>
<?php foreach ($sessions as $s): ?>
  <tr><td><?= h($s['username']) ?></td><td><?= h($s['ip']) ?></td><td><?= h(fmt_time($s['created_at'])) ?></td><td><?= h(ago($s['last_seen_at'])) ?></td>
    <td class="text-truncate"><?= h(substr((string)$s['user_agent'], 0, 60)) ?></td>
    <td><?= $s['id_hash'] === Auth::session()['id_hash'] ? badge('info', 'this one') : post_button('/users', 'End', ['action' => 'end_session', 'session' => $s['id_hash']], 'btn-link btn-sm p-0') ?></td></tr>
<?php endforeach; ?></tbody></table>
<p class="small text-muted">Changes on this page ask for your password and code again (at most every 5 minutes).</p>
<?php page_end();
