<?php
// Client-certificate PKI (plan §13): CAs, issuing with the CA passphrase, revocation, scopes.
declare(strict_types=1);

$u = Auth::require('viewer');
$issued = null;
$errors = [];
$a = (string)post('action');

if (is_post()) {
    try {
        switch ($a) {
            case 'create_ca':
            case 'import_ca':
            case 'trust':
            case 'delete_ca':
            case 'export_key':
                Auth::require('admin');
                Auth::requireReauth();
                break;
            default:
                Auth::require('operator');
        }
        if ($a === 'create_ca') {
            $name = trim((string)post('name'));
            $pass = (string)post('passphrase');
            if (!PKI::validName($name)) throw new InvalidArgumentException('Name: 3–64 letters, digits, space . _ -');
            if (DB::val('SELECT 1 FROM cas WHERE name = ?', [$name])) throw new InvalidArgumentException('A CA with this name exists.');
            if ($e = PKI::passphraseProblem($pass)) throw new InvalidArgumentException($e);
            if ($pass !== post('passphrase2')) throw new InvalidArgumentException('The two passphrases differ.');
            $years = Validate::int(post('years'), 10, 20) ?? 10;
            PKI::createCA($name, $years, $pass);
            flash("CA $name created. nginx trusts it after the next apply (mark it ready on Changes).");
        } elseif ($a === 'import_ca') {
            $name = trim((string)post('name'));
            if (!PKI::validName($name)) throw new InvalidArgumentException('Name: 3–64 letters, digits, space . _ -');
            $key = trim((string)post('key_pem'));
            if ($key !== '') {
                if ($e = PKI::passphraseProblem((string)post('passphrase'))) throw new InvalidArgumentException($e);
                if (post('passphrase') !== post('passphrase2')) throw new InvalidArgumentException('The two passphrases differ.');
            }
            PKI::importCA($name, trim((string)post('cert_pem')), $key ?: null, (string)post('key_password'), (string)post('passphrase'));
            flash("CA $name imported" . ($key ? ' with its key.' : ' (trust only: it cannot issue).') . ' nginx trusts it after the next apply.');
        } elseif ($a === 'trust' && ($id = Validate::uuid(post('id')))) {
            DB::q('UPDATE cas SET trusted = NOT trusted, updated_at = now() WHERE id = ?', [$id]);
            Audit::log('ca.trust', "ca:$id", ['trusted' => (bool)DB::val('SELECT trusted FROM cas WHERE id = ?', [$id])]);
            flash('Changed. It takes effect with the next apply.');
        } elseif ($a === 'delete_ca' && ($id = Validate::uuid(post('id')))) {
            $n = DB::val('SELECT name FROM cas WHERE id = ?', [$id]);
            DB::q('DELETE FROM cas WHERE id = ?', [$id]);
            Audit::log('ca.delete', "ca:$n");
            State::publish('certs');
            flash("CA $n deleted with its certificates. nginx stops trusting it with the next apply.");
        } elseif ($a === 'export_key' && ($id = Validate::uuid(post('id')))) {
            if ($e = PKI::passphraseProblem((string)post('export_pass'))) throw new InvalidArgumentException('Export password: ' . $e);
            $pem = PKI::exportKey($id, (string)post('passphrase'), (string)post('export_pass'), (int)$u['id']);
            header('Content-Type: application/x-pem-file');
            header('Content-Disposition: attachment; filename="pspm-ca-' . slugify((string)DB::val('SELECT name FROM cas WHERE id = ?', [$id])) . '-key.pem"');
            header('Cache-Control: no-store');
            echo $pem;
            exit;
        } elseif ($a === 'change_passphrase' && ($id = Validate::uuid(post('id')))) {
            Auth::require('admin');
            if ($e = PKI::passphraseProblem((string)post('new'))) throw new InvalidArgumentException($e);
            if (post('new') !== post('new2')) throw new InvalidArgumentException('The two passphrases differ.');
            PKI::changePassphrase($id, (string)post('old'), (string)post('new'), (int)$u['id']);
            flash('Passphrase changed.');
        } elseif ($a === 'issue') {
            if (!nonce_consume('issue')) throw new InvalidArgumentException('This form was already used. Open it again.');
            $scope = array_values(array_filter((array)post('scope', []), fn($s) => Validate::uuid($s)));
            $issued = PKI::issue((string)post('ca'), (string)post('passphrase'), trim((string)post('cn')),
                (int)(Validate::int(post('days'), 1, 2190) ?? 365), mb_substr(trim((string)post('label')), 0, 100),
                post('scope_mode') === 'some' ? $scope : [], isset($_POST['compat']), (int)$u['id']);
        } elseif ($a === 'revoke' && ($id = Validate::uuid(post('id')))) {
            PKI::revoke($id, mb_substr(trim((string)post('reason')) ?: 'revoked', 0, 200));
            flash('Revoked. It is refused from the next request on.');
        } elseif ($a === 'scope' && ($id = Validate::uuid(post('id')))) {
            PKI::setScope($id, post('scope_mode') === 'some' ? array_values(array_filter((array)post('scope', []), fn($s) => Validate::uuid($s))) : []);
            flash('Scope changed. It takes effect at once.');
        }
    } catch (InvalidArgumentException $e) {
        $errors[] = $e->getMessage();
    }
    if (!$issued && !$errors) redirect('/certificates');
}

$cas = DB::all('SELECT c.*, (SELECT count(*) FROM client_certs x WHERE x.ca_id = c.id AND x.revoked_at IS NULL AND x.not_after > now()) AS active FROM cas c ORDER BY name');
$certs = DB::all('SELECT x.*, c.name AS ca_name FROM client_certs x JOIN cas c ON c.id = x.ca_id ORDER BY x.issued_at DESC LIMIT 300');
$sites = Model::sites();
$siteName = fn(string $id) => $sites[$id]['hosts'][0] ?? '?';
$live = Live::revision()['document']['cas'] ?? [];
$liveIds = array_column($live, 'id');
$issuers = array_filter($cas, fn($c) => $c['key_wrapped'] && strtotime($c['not_after']) > time());

page_start('Certificates', '/certificates');
if ($issued) {
    $c = $issued['cert'];
    ?>
    <h1 class="h4">Certificate issued</h1>
    <div class="alert alert-success">
      <p class="mb-1"><strong><?= h($c['subject_cn']) ?></strong> <?= $c['label'] ? '(' . h($c['label']) . ')' : '' ?>, valid until <?= h(fmt_time($c['not_after'], 'Y-m-d')) ?>.</p>
      <p class="mb-1">Password of the .p12 file (shown once): <code class="fs-5"><?= h($issued['password']) ?></code></p>
      <p class="mb-0 small">Hand over the file and the password through different channels.</p>
    </div>
    <a class="btn btn-primary" id="p12dl" href="#" data-b64="<?= h(base64_encode($issued['p12'])) ?>"
       data-name="<?= h(slugify($c['label'] ?: $c['subject_cn'], 60)) ?>.p12" data-autostart="1">Download the .p12 again</a>
    <a class="btn btn-link" href="/certificates">Back to certificates</a>
    <?php
    header('Cache-Control: no-store');
    page_end();
}
?>
<h1 class="h4 mb-3">Certificates</h1>
<?= errors_box($errors) ?>
<div class="row g-4">
<div class="col-xl-7">
  <h2 class="h6">Issued client certificates</h2>
  <table class="table table-sm small align-middle"><thead><tr><th>Subject</th><th>CA</th><th>Sites</th><th>Valid until</th><th>State</th><th></th></tr></thead><tbody>
  <?php foreach ($certs as $c):
      $exp = strtotime($c['not_after']);
      $state = $c['revoked_at'] ? badge('grey', 'revoked', (string)$c['revoke_reason']) : ($exp < time() ? badge('grey', 'expired') : ($exp < time() + 30 * 86400 ? badge('amber', 'expires soon') : badge('green', 'valid')));
      $scope = $c['scope'] === 'all' ? 'all' : implode(', ', array_map($siteName, explode(',', $c['scope']))); ?>
    <tr><td><?= h($c['subject_cn']) ?><div class="text-muted"><?= h($c['label']) ?></div></td><td><?= h($c['ca_name']) ?></td><td><?= h($scope) ?></td>
      <td><?= h(fmt_time($c['not_after'], 'Y-m-d')) ?></td><td><?= $state ?></td>
      <td class="text-nowrap"><?php if (!$c['revoked_at'] && Auth::can('operator')): ?>
        <form method="post" class="d-inline" data-confirm="Revoke the certificate of <?= h($c['subject_cn']) ?>?"><?= csrf_field() ?><input type="hidden" name="action" value="revoke"><input type="hidden" name="id" value="<?= h($c['id']) ?>">
          <input class="form-control form-control-sm d-inline w-auto" name="reason" placeholder="reason"> <button class="btn btn-outline-danger btn-sm">Revoke</button></form>
        <details class="d-inline"><summary class="small d-inline">scope</summary>
          <form method="post" class="mt-1"><?= csrf_field() ?><input type="hidden" name="action" value="scope"><input type="hidden" name="id" value="<?= h($c['id']) ?>">
            <?= f_check('scope_mode', 'only these sites:', $c['scope'] !== 'all', '', 'some') ?>
            <?php foreach ($sites as $sid => $s): ?><?= f_check('scope[]', $s['hosts'][0], in_array($sid, explode(',', $c['scope']), true), '', $sid) ?><?php endforeach; ?>
            <button class="btn btn-sm btn-outline-secondary">Save scope</button></form></details>
      <?php endif; ?></td></tr>
  <?php endforeach; ?>
  <?php if (!$certs): ?><tr><td colspan="6" class="text-muted">None yet.</td></tr><?php endif; ?>
  </tbody></table>

  <?php if (Auth::can('operator')): ?>
  <h2 class="h6 mt-3">Issue a certificate</h2>
  <?php if (!$issuers): ?><p class="text-muted small">Create a CA first (or import one with its key).</p><?php else: ?>
  <form method="post" class="card card-body" autocomplete="off"><?= csrf_field() ?><?= nonce_field('issue') ?><input type="hidden" name="action" value="issue">
    <div class="row g-2">
      <div class="col-md-4"><label class="form-label small">CA</label><select class="form-select form-select-sm" name="ca"><?php foreach ($issuers as $c): ?><option value="<?= h($c['id']) ?>"><?= h($c['name']) ?></option><?php endforeach; ?></select></div>
      <div class="col-md-4"><label class="form-label small">Subject</label><input class="form-control form-control-sm" name="cn" placeholder="anna@example.ch" required></div>
      <div class="col-md-4"><label class="form-label small">Valid for</label><select class="form-select form-select-sm" name="days"><?php foreach (PKI::DURATIONS as $d => $l): ?><option value="<?= $d ?>" <?= $d === '365' ? 'selected' : '' ?>><?= h($l) ?></option><?php endforeach; ?></select></div>
      <div class="col-md-6"><label class="form-label small">Label</label><input class="form-control form-control-sm" name="label" placeholder="Anna, laptop"></div>
      <div class="col-md-6"><label class="form-label small">CA passphrase</label><input class="form-control form-control-sm" type="password" name="passphrase" required autocomplete="off"></div>
      <div class="col-12"><?= f_check('scope_mode', 'Only for these sites (otherwise all):', false, '', 'some') ?>
        <?php foreach ($sites as $sid => $s): ?><span class="me-3 d-inline-block"><?= f_check('scope[]', $s['hosts'][0], false, '', $sid) ?></span><?php endforeach; ?></div>
      <div class="col-12"><?= f_check('compat', 'Compatible .p12 (3DES/SHA-1) for older macOS, iOS, Android and Windows keychains', true) ?></div>
    </div>
    <div><button class="btn btn-primary btn-sm">Issue</button> <span class="small text-muted">The client key is never stored; the .p12 is shown once.</span></div>
  </form>
  <?php endif; endif; ?>
</div>

<div class="col-xl-5">
  <h2 class="h6">Certificate authorities</h2>
  <?php foreach ($cas as $c):
      $years = (strtotime($c['not_after']) - time()) / (365 * 86400);
      $live = in_array($c['id'], $liveIds, true); ?>
    <div class="card mb-2"><div class="card-body py-2 small">
      <div class="d-flex justify-content-between"><strong><?= h($c['name']) ?></strong>
        <span><?= $c['key_wrapped'] ? badge('green', 'can issue') : badge('grey', 'trust only') ?>
        <?= $c['trusted'] ? ($live ? badge('green', 'trusted by nginx') : badge('amber', 'trusted after the next apply')) : ($live ? badge('amber', 'untrusted after the next apply') : badge('grey', 'not trusted')) ?></span></div>
      <div>Valid until <?= h(fmt_time($c['not_after'], 'Y-m-d')) ?> <?= $years < 1 ? badge('red', 'expires within a year') : '' ?> · <?= h($c['active']) ?> active certificates</div>
      <div class="text-muted text-break">SHA-256 <?= h(implode(':', str_split(strtoupper($c['fingerprint_sha256']), 2))) ?></div>
      <?php if (Auth::can('admin')): ?>
      <div class="mt-1">
        <?= post_button('/certificates', $c['trusted'] ? 'Stop trusting' : 'Trust', ['action' => 'trust', 'id' => $c['id']]) ?>
        <?= post_button('/certificates', 'Delete', ['action' => 'delete_ca', 'id' => $c['id']], 'btn-outline-danger btn-sm', "Delete CA {$c['name']} and its certificate records?") ?>
        <?php if ($c['key_wrapped']): ?>
        <details class="mt-1"><summary>Change passphrase / export the key</summary>
          <form method="post" class="row g-1 mt-1" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="change_passphrase"><input type="hidden" name="id" value="<?= h($c['id']) ?>">
            <div class="col-12"><input class="form-control form-control-sm" type="password" name="old" placeholder="current passphrase"></div>
            <div class="col-6"><input class="form-control form-control-sm" type="password" name="new" placeholder="new passphrase"></div>
            <div class="col-6"><input class="form-control form-control-sm" type="password" name="new2" placeholder="repeat"></div>
            <div class="col-12"><button class="btn btn-sm btn-outline-secondary">Change passphrase</button></div></form>
          <form method="post" class="row g-1 mt-2" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="export_key"><input type="hidden" name="id" value="<?= h($c['id']) ?>">
            <div class="col-6"><input class="form-control form-control-sm" type="password" name="passphrase" placeholder="CA passphrase"></div>
            <div class="col-6"><input class="form-control form-control-sm" type="password" name="export_pass" placeholder="password for the file"></div>
            <div class="col-12"><button class="btn btn-sm btn-outline-secondary">Download the encrypted key (PKCS#8)</button></div></form>
        </details>
        <?php endif; ?>
      </div>
      <?php endif; ?>
    </div></div>
  <?php endforeach; ?>
  <?php if (!$cas): ?><p class="text-muted small">No CA yet.</p><?php endif; ?>

  <?php if (Auth::can('admin') && !Auth::reauthFresh()): ?>
  <p class="mt-3"><a class="btn btn-sm btn-outline-primary" href="/reauth?next=/certificates">Confirm it is you to create, import, trust or delete CAs</a></p>
  <?php elseif (Auth::can('admin')): ?>
  <details class="mt-3" <?= $a === 'create_ca' && $errors ? 'open' : '' ?>><summary class="h6 d-inline">Create a CA</summary>
    <form method="post" class="card card-body mt-2" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="create_ca">
      <?= f_text('name', 'Name (also the certificate subject)', post('name'), [], 'Unique, e.g. Example Clients') ?>
      <?= f_select('years', 'Valid for', '10', ['10' => '10 years', '15' => '15 years', '20' => '20 years']) ?>
      <?= f_text('passphrase', 'Passphrase (at least 16 characters)', '', [], 'Suggestion: ' . PKI::generatePassphrase() . ' — it is never stored; keep it in a password manager.', 'password', '', ['autocomplete' => 'new-password']) ?>
      <?= f_text('passphrase2', 'Repeat', '', [], '', 'password', '', ['autocomplete' => 'new-password']) ?>
      <button class="btn btn-primary btn-sm">Create (RSA 4096; takes a few seconds)</button>
    </form></details>
  <details class="mt-2" <?= $a === 'import_ca' && $errors ? 'open' : '' ?>><summary class="h6 d-inline">Import a CA</summary>
    <form method="post" class="card card-body mt-2" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="import_ca">
      <?= f_text('name', 'Name', '', []) ?>
      <?= f_area('cert_pem', 'CA certificate (PEM)', '', [], '', 5) ?>
      <?= f_area('key_pem', 'Its private key (PEM, optional)', '', [], 'Without a key the CA is trust only: nginx accepts its certificates, PSPM cannot issue.', 5) ?>
      <?= f_text('key_password', 'Password of that key file (if any)', '', [], '', 'password') ?>
      <?= f_text('passphrase', 'New PSPM passphrase for the key', '', [], 'At least 16 characters', 'password', '', ['autocomplete' => 'new-password']) ?>
      <?= f_text('passphrase2', 'Repeat', '', [], '', 'password', '', ['autocomplete' => 'new-password']) ?>
      <button class="btn btn-primary btn-sm">Import</button>
    </form></details>
  <?php endif; ?>
</div>
</div>
<?php page_end();
