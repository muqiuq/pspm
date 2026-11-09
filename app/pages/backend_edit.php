<?php
declare(strict_types=1);

$u = Auth::require('viewer');
$id = Validate::uuid(get('id')) ?? null;
$b = $id ? Model::backend($id) : null;
if ($id && !$b) page_error(404, 'No such backend.');
$errors = [];
$form = $b ?? ['name' => '', 'protocol' => 'http', 'tls_verify' => 'off', 'tls_name' => '', 'custom_ca' => '', 'keepalive' => 16,
    'header_buffer' => Validate::HEADER_BUFFER_DEFAULT,
    'servers' => [['addr' => '', 'weight' => 1, 'backup' => false, 'max_fails' => 1, 'fail_timeout' => 10]]];
if (is_post()) {
    Auth::require('admin');
    $servers = [];
    foreach ((array)post('servers', []) as $s) {
        $servers[] = ['addr' => $s['addr'] ?? '', 'weight' => $s['weight'] ?? 1, 'backup' => isset($s['backup']),
            'max_fails' => $s['max_fails'] ?? 1, 'fail_timeout' => $s['fail_timeout'] ?? 10];
    }
    $in = ['name' => post('name'), 'protocol' => post('protocol'), 'tls_verify' => post('tls_verify'), 'tls_name' => post('tls_name'),
        'custom_ca' => post('custom_ca'), 'keepalive' => post('keepalive'), 'header_buffer' => post('header_buffer'), 'servers' => $servers];
    [$norm, $errors] = Validate::backend($in);
    $form = $in;
    if (!$errors) {
        [$newId, $err] = Model::saveBackend($id, $norm, post('updated_at') ?: null);
        if ($err) $errors['save'] = $err;
        else { flash('Backend saved.'); redirect('/backends'); }
    }
}
$ro = !Auth::can('admin');
page_start($b ? 'Backend ' . $b['name'] : 'New backend', '/backends');
?>
<h1 class="h4 mb-3"><?= $b ? 'Backend ' . h($b['name']) : 'New backend' ?></h1>
<?= errors_box(isset($errors['save']) ? [$errors['save']] : []) ?>
<form method="post" class="col-xl-8"><?= csrf_field() ?>
  <input type="hidden" name="updated_at" value="<?= h($b['updated_at'] ?? '') ?>">
  <fieldset <?= $ro ? 'disabled' : '' ?>>
  <div class="row">
    <div class="col-md-6"><?= f_text('name', 'Name', $form['name'], $errors, 'Lower-case, e.g. nextcloud') ?></div>
    <div class="col-md-3"><?= f_select('protocol', 'Protocol', $form['protocol'], ['http' => 'http', 'https' => 'https']) ?></div>
    <div class="col-md-3"><?= f_text('keepalive', 'Idle connections kept', $form['keepalive'], $errors, '0 = none', 'number') ?></div>
  </div>
  <h2 class="h6 mt-2">Servers</h2>
  <div data-rows="servers">
    <?php foreach (array_values($form['servers']) as $i => $s): ?>
      <div class="row g-2 align-items-end mb-2" data-row>
        <div class="col-md-4"><label class="form-label small">host:port</label><input class="form-control" name="servers[<?= $i ?>][addr]" value="<?= h($s['addr']) ?>" placeholder="10.0.0.5:8080"><?= field_err($errors, "servers.$i") ?></div>
        <div class="col-md-2"><label class="form-label small">Weight</label><input class="form-control" type="number" name="servers[<?= $i ?>][weight]" value="<?= h($s['weight']) ?>"></div>
        <div class="col-md-2"><label class="form-label small">Max fails</label><input class="form-control" type="number" name="servers[<?= $i ?>][max_fails]" value="<?= h($s['max_fails']) ?>"></div>
        <div class="col-md-2"><label class="form-label small">Fail timeout (s)</label><input class="form-control" type="number" name="servers[<?= $i ?>][fail_timeout]" value="<?= h($s['fail_timeout']) ?>"></div>
        <div class="col-md-1"><div class="form-check"><input class="form-check-input" type="checkbox" name="servers[<?= $i ?>][backup]" value="1" <?= !empty($s['backup']) ? 'checked' : '' ?>><label class="form-check-label small">Backup</label></div></div>
        <div class="col-md-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div>
      </div>
    <?php endforeach; ?>
  </div>
  <?= field_err($errors, 'servers') ?>
  <template data-template="servers">
      <div class="row g-2 align-items-end mb-2" data-row>
        <div class="col-md-4"><label class="form-label small">host:port</label><input class="form-control" name="servers[__i__][addr]" placeholder="10.0.0.5:8080"></div>
        <div class="col-md-2"><label class="form-label small">Weight</label><input class="form-control" type="number" name="servers[__i__][weight]" value="1"></div>
        <div class="col-md-2"><label class="form-label small">Max fails</label><input class="form-control" type="number" name="servers[__i__][max_fails]" value="1"></div>
        <div class="col-md-2"><label class="form-label small">Fail timeout (s)</label><input class="form-control" type="number" name="servers[__i__][fail_timeout]" value="10"></div>
        <div class="col-md-1"><div class="form-check"><input class="form-check-input" type="checkbox" name="servers[__i__][backup]" value="1"><label class="form-check-label small">Backup</label></div></div>
        <div class="col-md-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div>
      </div>
  </template>
  <button type="button" class="btn btn-outline-secondary btn-sm mb-3" data-add-row="servers">Add server</button>

  <h2 class="h6 mt-2">TLS to the backend (https only)</h2>
  <div class="row">
    <div class="col-md-4"><?= f_select('tls_verify', 'Certificate check', $form['tls_verify'], ['off' => 'off', 'system' => 'system CAs', 'custom' => 'custom CA']) ?></div>
    <div class="col-md-8"><?= f_text('tls_name', 'TLS name (SNI and verify name)', $form['tls_name'], $errors, 'Empty: the server\'s host name, or no SNI for an IP address') ?></div>
  </div>
  <?= f_area('custom_ca', 'Custom CA (PEM)', (string)$form['custom_ca'], $errors, 'Only with "custom CA".', 4) ?>

  <h2 class="h6 mt-2">Responses</h2>
  <div class="row">
    <div class="col-md-4"><?= f_select('header_buffer', 'Response header buffer', (string)($form['header_buffer'] ?? Validate::HEADER_BUFFER_DEFAULT),
        array_combine(array_map('strval', Validate::HEADER_BUFFERS), array_map(fn($k) => $k . ' KB' . ($k === Validate::HEADER_BUFFER_DEFAULT ? ' (default)' : ''), Validate::HEADER_BUFFERS)), $errors) ?></div>
    <div class="col-md-8 small text-body-secondary pt-md-4">Raise it when nginx logs <code>upstream sent too big header</code> for this backend
      (the visitor sees 502): large cookies, long Content-Security-Policy headers or SSO tokens. Applies to every site and route that uses this backend.</div>
  </div>
  </fieldset>
  <?php if (!$ro): ?><button class="btn btn-primary">Save</button><?php endif; ?>
  <a class="btn btn-link" href="/backends">Back</a>
</form>
<?php page_end();
