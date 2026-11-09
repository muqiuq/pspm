<?php
// Site editor (plan §7.2, §7.3, §7.5).
declare(strict_types=1);

$u = Auth::require('viewer');
$id = Validate::uuid(get('id')) ?? null;
$site = $id ? Model::site($id) : null;
if ($id && !$site) page_error(404, 'No such site.');
$backends = Model::backends();
$backendOpts = ['' => '— none —'];
foreach ($backends as $bid => $b) $backendOpts[$bid] = $b['name'];
$errors = [];
$form = $site ?? Validate::defaultSite();

/** Turn the posted form into the model's input shape (checkboxes become real booleans). */
function site_from_post(): array
{
    $lines = fn(string $k) => preg_split('/[\s,]+/', trim((string)post($k)), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    $rows = function (string $k, array $fields): array {
        $out = [];
        foreach ((array)post($k, []) as $r) {
            if (!is_array($r)) continue;
            $row = [];
            foreach ($fields as $f => $type) $row[$f] = $type === 'bool' ? isset($r[$f]) : (string)($r[$f] ?? '');
            $out[] = $row;
        }
        return $out;
    };
    $routes = [];
    foreach ((array)post('routes', []) as $r) {
        if (!is_array($r)) continue;
        $ov = [];
        if (!empty($r['ov_conditions'])) $ov['access'] = ['conditions' => (array)$r['ov_conditions']];
        if (trim((string)($r['ov_max_body'] ?? '')) !== '') $ov['max_body'] = $r['ov_max_body'];
        if (trim((string)($r['ov_read_timeout'] ?? '')) !== '') $ov['read_timeout'] = $r['ov_read_timeout'];
        if (!empty($r['ov_backend'])) $ov['backend'] = $r['ov_backend'];
        $routes[] = ['id' => (string)($r['id'] ?? ''), 'match' => (string)($r['match'] ?? 'prefix'),
            'paths' => preg_split('/[\s,]+/', trim((string)($r['paths'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [],
            'listeners' => (array)($r['listeners'] ?? ['all']), 'action' => (string)($r['action'] ?? 'proxy'),
            'status' => (string)($r['status'] ?? '404'), 'redirect_url' => (string)($r['redirect_url'] ?? ''),
            'redirect_code' => (string)($r['redirect_code'] ?? '302'), 'overrides' => $ov];
    }
    return [
        'enabled' => isset($_POST['enabled']),
        'description' => post('description'),
        'hosts' => $lines('hosts'),
        'tls' => ['mode' => post('tls_mode'), 'profile' => post('tls_profile'), 'http2' => isset($_POST['http2']),
            'hsts' => ['mode' => post('hsts_mode'), 'max_age' => post('hsts_max_age'),
                'include_subdomains' => isset($_POST['hsts_sub']), 'preload' => isset($_POST['hsts_preload'])]],
        'port80' => post('port80'),
        'client_certs' => post('client_certs'),
        'access' => ['conditions' => (array)post('conditions', []), 'denied' => post('denied'), 'denied_url' => post('denied_url')],
        'limits' => ['max_body' => post('max_body'), 'rate' => post('rate'), 'limit_conn' => post('limit_conn')],
        'proxy' => ['backend' => post('backend'), 'host_header' => post('host_header'), 'host_fixed' => post('host_fixed'),
            'connect_timeout' => post('connect_timeout'), 'read_timeout' => post('read_timeout'), 'send_timeout' => post('send_timeout'),
            'websocket' => isset($_POST['websocket']), 'request_buffering' => isset($_POST['request_buffering']),
            'response_buffering' => isset($_POST['response_buffering'])],
        'headers' => ['request' => $rows('req_headers', ['name' => 's', 'type' => 's', 'value' => 's']),
            'response' => $rows('resp_headers', ['name' => 's', 'value' => 's']),
            'hide' => $lines('hide_headers'), 'security' => post('security')],
        'listeners' => $rows('listeners', ['port' => 's', 'tls' => 'bool']),
        'routes' => $routes,
    ];
}

if (is_post()) {
    Auth::require('admin');
    $in = site_from_post();
    [$norm, $errors] = Validate::site($in, array_keys($backends));
    $form = $in + ['id' => $id];
    if (!$errors) {
        [$newId, $err] = Model::saveSite($id, $norm, post('updated_at') ?: null);
        if ($err) $errors['save'] = $err;
        else { flash('Site saved. Mark it ready on Changes, then run install.sh.'); redirect('/sites/edit?id=' . $newId); }
    }
}
$ro = !Auth::can('admin');
$conds = ['lan' => 'LAN', 'cleared' => 'Cleared (access link for this site)', 'cert' => 'Client certificate', 'public' => 'Public (everyone)'];
$listenerOpts = ['all' => 'all', 'https' => 'HTTPS', 'http' => 'HTTP'];
foreach ($form['listeners'] as $li) if (!empty($li['port'])) $listenerOpts['port:' . $li['port']] = 'port ' . $li['port'];

function route_row(string $i, array $r, array $backendOpts, array $listenerOpts, array $conds, array $errors): string
{
    $sel = fn(string $name, array $opts, $val) => '<select class="form-select form-select-sm" name="routes[' . $i . '][' . $name . ']">'
        . implode('', array_map(fn($k, $v) => '<option value="' . h($k) . '"' . ((string)$k === (string)$val ? ' selected' : '') . '>' . h($v) . '</option>', array_keys($opts), $opts)) . '</select>';
    $ov = $r['overrides'] ?? [];
    $o = '<div class="card mb-2" data-row><div class="card-body py-2"><input type="hidden" name="routes[' . $i . '][id]" value="' . h($r['id'] ?? '') . '">';
    $o .= '<div class="row g-2 align-items-end">';
    $o .= '<div class="col-md-2"><label class="form-label small">Match</label>' . $sel('match', ['prefix' => 'prefix', 'exact' => 'exact'], $r['match'] ?? 'prefix') . '</div>';
    $o .= '<div class="col-md-4"><label class="form-label small">Paths (one or more)</label><input class="form-control form-control-sm font-monospace" name="routes[' . $i . '][paths]" value="' . h(implode(' ', $r['paths'] ?? [])) . '" placeholder="/ or /api/ /static/">'
        . field_err($errors, "routes.$i.paths") . '</div>';
    $o .= '<div class="col-md-3"><label class="form-label small">Action</label>' . $sel('action', ['proxy' => 'proxy to backend', 'status' => 'return status', 'redirect' => 'redirect', 'acme_proxy' => 'proxy the ACME challenge to the backend'], $r['action'] ?? 'proxy') . '</div>';
    $o .= '<div class="col-md-3 text-end"><button type="button" class="btn btn-outline-secondary btn-sm" data-move="up">↑</button> <button type="button" class="btn btn-outline-secondary btn-sm" data-move="down">↓</button> <button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>Remove</button></div>';
    $o .= '</div><div class="row g-2 mt-1">';
    $o .= '<div class="col-md-2"><label class="form-label small">Status / code</label><input class="form-control form-control-sm" name="routes[' . $i . '][status]" value="' . h($r['status'] ?? 404) . '"></div>';
    $o .= '<div class="col-md-4"><label class="form-label small">Redirect URL</label><input class="form-control form-control-sm" name="routes[' . $i . '][redirect_url]" value="' . h($r['redirect_url'] ?? '') . '">' . field_err($errors, "routes.$i.redirect_url") . '</div>';
    $o .= '<div class="col-md-2"><label class="form-label small">Redirect code</label>' . $sel('redirect_code', [301 => '301', 302 => '302', 303 => '303', 307 => '307', 308 => '308'], $r['redirect_code'] ?? 302) . '</div>';
    $o .= '<div class="col-md-4"><label class="form-label small d-block">Listeners</label>';
    foreach ($listenerOpts as $k => $v) {
        $o .= '<div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" name="routes[' . $i . '][listeners][]" value="' . h($k) . '"'
            . (in_array($k, $r['listeners'] ?? ['all'], true) ? ' checked' : '') . '><label class="form-check-label small">' . h($v) . '</label></div>';
    }
    $o .= '</div></div><details class="mt-1"><summary class="small">Overrides for this route</summary><div class="row g-2 mt-1">';
    $o .= '<div class="col-md-5"><label class="form-label small d-block">Access (empty: the site\'s)</label>';
    foreach ($conds as $k => $v) {
        $o .= '<div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" name="routes[' . $i . '][ov_conditions][]" value="' . h($k) . '"'
            . (in_array($k, $ov['access']['conditions'] ?? [], true) ? ' checked' : '') . '><label class="form-check-label small">' . h(explode(' (', $v)[0]) . '</label></div>';
    }
    $o .= field_err($errors, "routes.$i.access.conditions") . '</div>';
    $o .= '<div class="col-md-2"><label class="form-label small">Max body</label><input class="form-control form-control-sm" name="routes[' . $i . '][ov_max_body]" value="' . h($ov['max_body'] ?? '') . '" placeholder="site"></div>';
    $o .= '<div class="col-md-2"><label class="form-label small">Read timeout (s)</label><input class="form-control form-control-sm" name="routes[' . $i . '][ov_read_timeout]" value="' . h($ov['read_timeout'] ?? '') . '" placeholder="site"></div>';
    $o .= '<div class="col-md-3"><label class="form-label small">Backend</label>' . $sel('ov_backend', ['' => 'site\'s'] + array_slice($backendOpts, 1, null, true), $ov['backend'] ?? '') . field_err($errors, "routes.$i.backend") . '</div>';
    $o .= '</div></details></div></div>';
    return $o;
}

page_start($site ? 'Site ' . $site['hosts'][0] : 'New site', '/sites');
?>
<h1 class="h4 mb-3"><?= $site ? 'Site ' . h($site['hosts'][0]) : 'New site' ?></h1>
<?= errors_box(isset($errors['save']) ? [$errors['save']] : ($errors ? ['Please correct the marked fields.'] : [])) ?>
<?php if (!$backends): ?><div class="alert alert-info py-2">There is no backend yet. <a href="/backends/edit">Add one</a> first, unless every route only returns a status or redirects.</div><?php endif; ?>
<form method="post" class="col-xxl-10"><?= csrf_field() ?>
<input type="hidden" name="updated_at" value="<?= h($site['updated_at'] ?? '') ?>">
<fieldset <?= $ro ? 'disabled' : '' ?>>
<div class="row">
  <div class="col-lg-6">
    <h2 class="h6">General</h2>
    <?= f_area('hosts', 'Host names', implode("\n", $form['hosts']), $errors, 'One per line. The first is the primary name.', 3) ?>
    <?= f_text('description', 'Description', $form['description'], $errors) ?>
    <?= f_check('enabled', 'Enabled', (bool)$form['enabled']) ?>

    <h2 class="h6 mt-3">Access</h2>
    <div class="mb-2"><label class="form-label">Preset</label>
      <select class="form-select form-select-sm" data-preset-target="conditions">
        <option value="">— choose to fill in the conditions —</option>
        <?php foreach (Validate::PRESETS as $k => [$label, $c]): ?><option value="<?= h(implode(',', $c)) ?>"><?= h($label) ?></option><?php endforeach; ?>
      </select></div>
    <div class="mb-2"><span class="form-label d-block">Let a request in when any of these is true</span>
      <?php foreach ($conds as $k => $v): ?><?= f_check('conditions[]', $v, in_array($k, $form['access']['conditions'], true), '', $k) ?><?php endforeach; ?>
      <?= field_err($errors, 'access.conditions') ?></div>
    <div class="row"><div class="col-md-6"><?= f_select('denied', 'When denied', $form['access']['denied'], ['403' => '403 Forbidden', '404' => '404 (reveal nothing)', 'redirect' => '302 to a URL', 'close' => 'close the connection']) ?></div>
      <div class="col-md-6"><?= f_text('denied_url', 'Redirect URL when denied', $form['access']['denied_url'], $errors, '', 'text', 'access.denied_url') ?></div></div>
    <?= f_select('client_certs', 'Client certificates', $form['client_certs'], ['optional' => 'request (optional)', 'off' => 'do not request'], $errors) ?>
  </div>
  <div class="col-lg-6">
    <h2 class="h6">TLS</h2>
    <div class="row">
      <div class="col-md-6"><?= f_select('tls_mode', 'Certificate', $form['tls']['mode'], ['letsencrypt' => 'Let\'s Encrypt', 'none' => 'none (HTTP only)']) ?></div>
      <div class="col-md-6"><?= f_select('tls_profile', 'TLS profile', $form['tls']['profile'], ['default' => 'global setting', 'intermediate' => 'intermediate (TLS 1.2 + 1.3)', 'modern' => 'modern (TLS 1.3)']) ?></div>
    </div>
    <?= f_check('http2', 'HTTP/2', (bool)$form['tls']['http2']) ?>
    <div class="row">
      <div class="col-md-4"><?= f_select('hsts_mode', 'HSTS', $form['tls']['hsts']['mode'], ['default' => 'global setting', 'on' => 'on', 'off' => 'off']) ?></div>
      <div class="col-md-4"><?= f_text('hsts_max_age', 'max-age (s)', $form['tls']['hsts']['max_age'], $errors, '', 'number') ?></div>
      <div class="col-md-4 pt-4"><?= f_check('hsts_sub', 'includeSubDomains', (bool)$form['tls']['hsts']['include_subdomains']) ?><?= f_check('hsts_preload', 'preload', (bool)$form['tls']['hsts']['preload']) ?></div>
    </div>
    <?= f_select('port80', 'Port 80', $form['port80'], ['redirect' => 'redirect to HTTPS', 'serve' => 'serve the same routes', 'acme_only' => 'ACME only, 404 otherwise']) ?>

    <h2 class="h6 mt-3">Backend and limits</h2>
    <div class="row">
      <div class="col-md-6"><?= f_select('backend', 'Backend', $form['proxy']['backend'], $backendOpts, $errors, '', 'proxy.backend') ?></div>
      <div class="col-md-6"><?= f_text('max_body', 'Max. request body', $form['limits']['max_body'], $errors, '0 = unlimited; e.g. 10m, 2g', 'text', 'limits.max_body') ?></div>
      <div class="col-md-6"><?= f_select('host_header', 'Host header upstream', $form['proxy']['host_header'], ['client' => 'the client\'s host name', 'fixed' => 'a fixed name']) ?></div>
      <div class="col-md-6"><?= f_text('host_fixed', 'Fixed host name', $form['proxy']['host_fixed'], $errors, '', 'text', 'proxy.host_fixed') ?></div>
      <div class="col-md-4"><?= f_text('connect_timeout', 'Connect timeout (s)', $form['proxy']['connect_timeout'], $errors, '', 'number', 'proxy.connect_timeout') ?></div>
      <div class="col-md-4"><?= f_text('read_timeout', 'Read timeout (s)', $form['proxy']['read_timeout'], $errors, '', 'number', 'proxy.read_timeout') ?></div>
      <div class="col-md-4"><?= f_text('send_timeout', 'Send timeout (s)', $form['proxy']['send_timeout'], $errors, '', 'number', 'proxy.send_timeout') ?></div>
      <div class="col-md-6"><?= f_select('rate', 'Rate limit', $form['limits']['rate'], ['standard' => 'standard', 'strict' => 'strict', 'off' => 'off']) ?></div>
      <div class="col-md-6"><?= f_text('limit_conn', 'Max. connections per address', $form['limits']['limit_conn'], $errors, '0 = no limit', 'number') ?></div>
    </div>
    <?= f_check('websocket', 'WebSocket', (bool)$form['proxy']['websocket']) ?>
    <?= f_check('request_buffering', 'Buffer requests (turn off for large uploads)', (bool)$form['proxy']['request_buffering']) ?>
    <?= f_check('response_buffering', 'Buffer responses', (bool)$form['proxy']['response_buffering']) ?>
  </div>
</div>

<h2 class="h6 mt-3">Routes <span class="text-muted small">(in order; nginx picks the longest matching prefix)</span></h2>
<?= field_err($errors, 'routes') ?>
<div data-rows="routes">
  <?php foreach (array_values($form['routes']) as $i => $r) echo route_row((string)$i, $r, $backendOpts, $listenerOpts, $conds, $errors); ?>
</div>
<template data-template="routes"><?= route_row('__i__', ['match' => 'prefix', 'paths' => [], 'listeners' => ['all'], 'action' => 'proxy'], $backendOpts, $listenerOpts, $conds, []) ?></template>
<button type="button" class="btn btn-outline-secondary btn-sm mb-3" data-add-row="routes">Add route</button>

<details class="mb-3" <?= array_filter(array_keys($errors), fn($k) => str_starts_with($k, 'headers') || str_starts_with($k, 'listeners')) ? 'open' : '' ?>>
  <summary class="h6">Headers and extra ports</summary>
  <div class="row mt-2">
    <div class="col-lg-6">
      <h3 class="h6 small">Request headers to the backend</h3>
      <div data-rows="req_headers">
        <?php foreach (array_values($form['headers']['request']) as $i => $hd): ?>
          <div class="row g-2 mb-2" data-row><div class="col-4"><input class="form-control form-control-sm" name="req_headers[<?= $i ?>][name]" value="<?= h($hd['name']) ?>" placeholder="X-Client-IP"></div>
            <div class="col-3"><select class="form-select form-select-sm" name="req_headers[<?= $i ?>][type]"><?php foreach (Validate::HEADER_VALUE_TYPES as $t): ?><option <?= $t === $hd['type'] ? 'selected' : '' ?>><?= h($t) ?></option><?php endforeach; ?></select></div>
            <div class="col-4"><input class="form-control form-control-sm" name="req_headers[<?= $i ?>][value]" value="<?= h($hd['value']) ?>" placeholder="text value"></div>
            <div class="col-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div><?= field_err($errors, "headers.request.$i") ?></div>
        <?php endforeach; ?>
      </div>
      <template data-template="req_headers"><div class="row g-2 mb-2" data-row><div class="col-4"><input class="form-control form-control-sm" name="req_headers[__i__][name]" placeholder="X-Client-IP"></div>
        <div class="col-3"><select class="form-select form-select-sm" name="req_headers[__i__][type]"><?php foreach (Validate::HEADER_VALUE_TYPES as $t): ?><option><?= h($t) ?></option><?php endforeach; ?></select></div>
        <div class="col-4"><input class="form-control form-control-sm" name="req_headers[__i__][value]" placeholder="text value"></div>
        <div class="col-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div></div></template>
      <button type="button" class="btn btn-outline-secondary btn-sm mb-3" data-add-row="req_headers">Add request header</button>

      <h3 class="h6 small">Response headers to add</h3>
      <div data-rows="resp_headers">
        <?php foreach (array_values($form['headers']['response']) as $i => $hd): ?>
          <div class="row g-2 mb-2" data-row><div class="col-5"><input class="form-control form-control-sm" name="resp_headers[<?= $i ?>][name]" value="<?= h($hd['name']) ?>"></div>
            <div class="col-6"><input class="form-control form-control-sm" name="resp_headers[<?= $i ?>][value]" value="<?= h($hd['value']) ?>"></div>
            <div class="col-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div><?= field_err($errors, "headers.response.$i") ?></div>
        <?php endforeach; ?>
      </div>
      <template data-template="resp_headers"><div class="row g-2 mb-2" data-row><div class="col-5"><input class="form-control form-control-sm" name="resp_headers[__i__][name]"></div>
        <div class="col-6"><input class="form-control form-control-sm" name="resp_headers[__i__][value]"></div>
        <div class="col-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div></div></template>
      <button type="button" class="btn btn-outline-secondary btn-sm mb-3" data-add-row="resp_headers">Add response header</button>
    </div>
    <div class="col-lg-6">
      <?= f_text('hide_headers', 'Backend headers to hide', implode(' ', $form['headers']['hide']), $errors, 'Space separated, e.g. Server X-AspNet-Version', 'text', 'headers.hide') ?>
      <?= f_select('security', 'Security headers', $form['headers']['security'], ['default' => 'global setting', 'off' => 'off for this site']) ?>
      <h3 class="h6 small">Extra listeners</h3>
      <div data-rows="listeners">
        <?php foreach (array_values($form['listeners']) as $i => $li): ?>
          <div class="row g-2 mb-2" data-row><div class="col-4"><input class="form-control form-control-sm" type="number" name="listeners[<?= $i ?>][port]" value="<?= h($li['port']) ?>" placeholder="8080"></div>
            <div class="col-4"><div class="form-check"><input class="form-check-input" type="checkbox" name="listeners[<?= $i ?>][tls]" value="1" <?= !empty($li['tls']) ? 'checked' : '' ?>><label class="form-check-label small">TLS</label></div></div>
            <div class="col-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div><?= field_err($errors, "listeners.$i") ?></div>
        <?php endforeach; ?>
      </div>
      <template data-template="listeners"><div class="row g-2 mb-2" data-row><div class="col-4"><input class="form-control form-control-sm" type="number" name="listeners[__i__][port]" placeholder="8080"></div>
        <div class="col-4"><div class="form-check"><input class="form-check-input" type="checkbox" name="listeners[__i__][tls]" value="1"><label class="form-check-label small">TLS</label></div></div>
        <div class="col-1"><button type="button" class="btn btn-outline-danger btn-sm" data-remove-row>×</button></div></div></template>
      <button type="button" class="btn btn-outline-secondary btn-sm mb-1" data-add-row="listeners">Add listener</button>
      <?= field_err($errors, 'listeners') ?>
      <div class="form-text">Save once after adding a port, so routes can be bound to it.</div>
    </div>
  </div>
</details>
</fieldset>
<?php if (!$ro): ?><button class="btn btn-primary">Save</button><?php endif; ?>
<a class="btn btn-link" href="/sites">Back</a>
</form>
<?php page_end();
