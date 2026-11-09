<?php
// Microsoft sign-in providers (plan §12). Admins only, with re-authentication.
declare(strict_types=1);

$u = Auth::require('admin');
$errors = [];
$editId = Validate::uuid(get('id')) ?? null;
$form = $editId ? Signin::provider($editId) : null;
if ($editId && !$form) page_error(404, 'No such provider.');
if (is_post()) {
    Auth::requireReauth();
    $a = post('action');
    if ($a === 'save') {
        $id = Validate::uuid(post('id')) ?? null;
        $in = ['name' => post('name'), 'tenant_id' => post('tenant_id'), 'client_id' => post('client_id'), 'signin_host' => post('signin_host'),
            'cookie_domain' => post('cookie_domain'), 'email_domains' => preg_split('/[\s,]+/', trim((string)post('email_domains')), -1, PREG_SPLIT_NO_EMPTY) ?: [],
            'groups_claim' => post('groups_claim'), 'email_claim' => post('email_claim'), 'session_hours' => post('session_hours'),
            'recheck_minutes' => post('recheck_minutes'), 'start_url' => post('start_url'), 'port' => 0];
        [$p, $errors] = Signin::validate($in);
        $secret = trim((string)post('client_secret'));
        if (!$id && $secret === '') $errors['client_secret'] = 'The client secret from Entra (Certificates & secrets).';
        if ($secret !== '' && (strlen($secret) > 512 || preg_match('/[\s"\\\\]/', $secret))) $errors['client_secret'] = 'That does not look like a client secret.';
        if (!$errors) {
            [$newId, $err] = Signin::save($id, $p, $secret !== '' ? $secret : null);
            if ($err) $errors['name'] = $err;
            else { flash('Provider saved. It takes effect with the next apply.'); redirect('/signin'); }
        }
        $form = $in + ['id' => $id];
    } elseif ($a === 'rotate' && ($id = Validate::uuid(post('id')))) {
        Signin::rotateCookieSecret($id);
        flash('New cookie secret: every session of this provider ends with the next apply.');
        redirect('/signin');
    } elseif ($a === 'delete' && ($id = Validate::uuid(post('id')))) {
        if ($used = Signin::users($id)) flash('Still used by: ' . implode(', ', $used), 'danger');
        else { DB::q('DELETE FROM oauth_providers WHERE id = ?', [$id]); Audit::log('signin.delete', "provider:$id"); flash('Provider deleted.'); }
        redirect('/signin');
    }
}
$providers = Signin::providers();
$fresh = Auth::reauthFresh();
page_start('Sign-in', '/signin');
?>
<h1 class="h4 mb-3">Sign-in with Microsoft</h1>
<p class="text-muted small">Sites can require a Microsoft (Entra ID) sign-in. Each provider is one app registration in Entra and one sign-in host name.
  PSPM's own UI keeps password + code. <a href="/help/signin">How to set up Entra</a>.</p>
<div class="row g-4">
<div class="col-xl-6">
  <?php foreach ($providers as $p): $ready = Signin::ready((int)$p['port']); $users = Signin::users($p['id']); ?>
    <div class="card mb-2"><div class="card-body py-2 small">
      <div class="d-flex justify-content-between"><strong><?= h($p['name']) ?></strong>
        <span><?= $ready === true ? badge('green', 'running') : badge($users ? 'red' : 'grey', 'not running', 'The container answers /ready once applied and the identity provider is reachable') ?></span></div>
      <div>Sign-in host <code><?= h($p['signin_host']) ?></code> · cookie domain <code>.<?= h($p['cookie_domain']) ?></code> · port <?= h($p['port']) ?></div>
      <div>Tenant <code><?= h($p['tenant_id']) ?></code> · client <code><?= h($p['client_id']) ?></code> <?= $p['has_secret'] ? '' : badge('red', 'no secret') ?></div>
      <div>E-mail domains: <?= h(implode(', ', $p['email_domains'])) ?> · session <?= h($p['session_hours']) ?> h, re-check every <?= h($p['recheck_minutes']) ?> min</div>
      <div>Used by: <?= h(implode(', ', $users) ?: 'no site yet') ?></div>
      <div class="mt-1">
        <a class="btn btn-sm btn-outline-secondary" href="/signin?id=<?= h($p['id']) ?>">Edit</a>
        <a class="btn btn-sm btn-outline-secondary" href="https://<?= h($p['signin_host']) ?>/oauth2/start?rd=https%3A%2F%2F<?= h($p['signin_host']) ?>%2F" target="_blank" rel="noopener">Test sign-in</a>
        <?php if ($fresh): ?>
        <?= post_button('/signin', 'End all sessions', ['action' => 'rotate', 'id' => $p['id']], 'btn-outline-secondary btn-sm', 'Rotate the cookie secret? Everyone signs in again after the next apply.') ?>
        <?= post_button('/signin', 'Delete', ['action' => 'delete', 'id' => $p['id']], 'btn-outline-danger btn-sm', "Delete provider {$p['name']}?") ?>
        <?php endif; ?>
      </div>
    </div></div>
  <?php endforeach; ?>
  <?php if (!$providers): ?><p class="text-muted">No provider yet.</p><?php endif; ?>
</div>
<div class="col-xl-6">
  <?php if (!$fresh): ?>
    <a class="btn btn-outline-primary" href="/reauth?next=<?= h(rawurlencode('/signin' . ($editId ? "?id=$editId" : ''))) ?>">Confirm it is you to add or change providers</a>
  <?php else: $f = $form ?? ['name' => '', 'tenant_id' => '', 'client_id' => '', 'signin_host' => '', 'cookie_domain' => '', 'email_domains' => [],
      'groups_claim' => 'groups', 'email_claim' => 'email', 'session_hours' => 24, 'recheck_minutes' => 60, 'start_url' => '']; ?>
    <h2 class="h6"><?= !empty($f['id']) ? 'Edit ' . h($f['name']) : 'Add a provider' ?></h2>
    <form method="post" class="card card-body" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="save"><input type="hidden" name="id" value="<?= h($f['id'] ?? '') ?>">
      <?= f_text('name', 'Name', $f['name'], $errors, 'e.g. Example staff') ?>
      <div class="row"><div class="col-md-6"><?= f_text('tenant_id', 'Directory (tenant) ID', $f['tenant_id'], $errors) ?></div>
        <div class="col-md-6"><?= f_text('client_id', 'Application (client) ID', $f['client_id'], $errors) ?></div></div>
      <?= f_text('client_secret', 'Client secret' . (!empty($f['id']) ? ' (empty: keep the current one)' : ''), '', $errors, 'Stored encrypted; never shown again.', 'password', '', ['autocomplete' => 'new-password']) ?>
      <div class="row"><div class="col-md-6"><?= f_text('signin_host', 'Sign-in host name', $f['signin_host'], $errors, 'e.g. auth.example.ch; its DNS must point here') ?></div>
        <div class="col-md-6"><?= f_text('cookie_domain', 'Cookie domain', $f['cookie_domain'], $errors, 'Empty: the parent of the sign-in host. Every site using this provider must be inside it.') ?></div></div>
      <?= f_text('email_domains', 'Accepted e-mail domains', implode(' ', (array)$f['email_domains']), $errors, 'Space separated, e.g. example.ch; * accepts every account of the tenant.') ?>
      <div class="row">
        <div class="col-md-6"><?= f_select('groups_claim', 'Groups claim', $f['groups_claim'], ['groups' => 'groups (group object IDs)', 'roles' => 'roles (app roles)']) ?></div>
        <div class="col-md-6"><?= f_select('email_claim', 'E-mail claim', $f['email_claim'], ['email' => 'email', 'preferred_username' => 'preferred_username (UPN)', 'upn' => 'upn']) ?></div>
        <div class="col-md-6"><?= f_text('session_hours', 'Session lifetime (hours)', $f['session_hours'], $errors, '1–168', 'number') ?></div>
        <div class="col-md-6"><?= f_text('recheck_minutes', 'Re-check at Microsoft every (minutes)', $f['recheck_minutes'], $errors, 'A user disabled in Entra loses access within this time', 'number') ?></div>
      </div>
      <?= f_text('start_url', 'Start page of the sign-in host (optional)', $f['start_url'], $errors, 'Where https://<sign-in host>/ redirects; empty answers 404') ?>
      <div><button class="btn btn-primary btn-sm">Save</button> <a class="btn btn-link btn-sm" href="/signin">Cancel</a></div>
    </form>
  <?php endif; ?>
</div>
</div>
<?php page_end();
