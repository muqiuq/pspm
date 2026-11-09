<?php
// Global settings (plan §7.1). Static ones go through revisions; login protection is runtime.
declare(strict_types=1);

$u = Auth::require('admin');
$g = Settings::global();
$login = Settings::get('login');
$errors = [];
if (is_post()) {
    $in = [
        'admin_host' => post('admin_host'), 'admin_access' => (array)post('admin_access', []),
        'acme_email' => post('acme_email'),
        'lan_ranges' => preg_split('/[\s,]+/', trim((string)post('lan_ranges')), -1, PREG_SPLIT_NO_EMPTY) ?: [],
        'tls_profile' => post('tls_profile'), 'security_headers' => isset($_POST['security_headers']), 'error_pages' => isset($_POST['error_pages']),
        'hsts' => ['enabled' => isset($_POST['hsts_enabled']), 'max_age' => post('hsts_max_age'), 'include_subdomains' => isset($_POST['hsts_sub'])],
        'rate_standard' => ['rate' => post('std_rate'), 'burst' => post('std_burst')],
        'rate_strict' => ['rate' => post('strict_rate'), 'burst' => post('strict_burst')],
    ];
    [$norm, $errors] = Validate::global($in);
    if ($norm['admin_host'] !== '' && Model::hostConflicts([$norm['admin_host']], null)) $errors['admin_host'] = 'This host name belongs to a site.';
    $lf = ['max_failures' => Validate::int(post('max_failures'), 3, 1000), 'window_secs' => Validate::int(post('window_mins'), 1, 1440),
        'ban_secs' => Validate::int(post('ban_hours'), 1, 8760)];
    if (in_array(null, $lf, true)) $errors['login'] = 'Login protection: whole numbers within range.';
    if (!$errors) {
        Settings::saveGlobal($norm);
        Settings::set('login', ['max_failures' => $lf['max_failures'], 'window_secs' => $lf['window_secs'] * 60, 'ban_secs' => $lf['ban_secs'] * 3600]);
        Audit::log('settings.update', 'settings:global', ['admin_host' => $norm['admin_host']]);
        flash('Settings saved. The global part takes effect with the next apply.');
        redirect('/settings');
    }
    $g = array_replace($g, $in);
}
page_start('Settings', '/settings');
?>
<h1 class="h4 mb-3">Settings</h1>
<?= errors_box($errors ? ['Please correct the marked fields.'] : []) ?>
<form method="post" class="col-xl-9"><?= csrf_field() ?>
<div class="row">
  <div class="col-lg-6">
    <h2 class="h6">Admin UI</h2>
    <?= f_text('admin_host', 'Admin host name', $g['admin_host'], $errors, 'Empty: the UI answers by IP, to private addresses only. Once set and its certificate exists, the UI answers only there (and through the SSH tunnel).') ?>
    <div class="mb-3"><span class="form-label d-block">Who may open the UI on the host name (then password + code)</span>
      <?= f_check('admin_access[]', 'LAN', in_array('lan', $g['admin_access'], true), '', 'lan') ?>
      <?= f_check('admin_access[]', 'Client certificate', in_array('cert', $g['admin_access'], true), '', 'cert') ?>
      <?= f_check('admin_access[]', 'Everyone (password and code only)', in_array('public', $g['admin_access'], true), '', 'public') ?>
      <?= field_err($errors, 'admin_access') ?></div>
    <?= f_text('acme_email', 'Let\'s Encrypt e-mail (optional)', $g['acme_email'], $errors, 'Expiry warnings from Let\'s Encrypt. PSPM watches expiry anyway.') ?>
    <?= f_area('lan_ranges', 'LAN ranges', implode("\n", $g['lan_ranges']), $errors, 'Used by the LAN condition. One network per line.', 4) ?>
  </div>
  <div class="col-lg-6">
    <h2 class="h6">Defaults for sites</h2>
    <?= f_select('tls_profile', 'TLS profile', $g['tls_profile'], ['intermediate' => 'intermediate (TLS 1.2 + 1.3)', 'modern' => 'modern (TLS 1.3 only)']) ?>
    <?= f_check('security_headers', 'Security headers (nosniff, Referrer-Policy, hide X-Powered-By)', (bool)$g['security_headers']) ?>
    <?= f_check('error_pages', 'PSPM error pages (403, 404, 429, 502, 503, 504)', (bool)$g['error_pages']) ?>
    <?= f_check('hsts_enabled', 'HSTS', (bool)$g['hsts']['enabled']) ?>
    <div class="row"><div class="col-md-6"><?= f_text('hsts_max_age', 'HSTS max-age (s)', $g['hsts']['max_age'], $errors, '', 'number') ?></div>
      <div class="col-md-6 pt-4"><?= f_check('hsts_sub', 'includeSubDomains', (bool)$g['hsts']['include_subdomains']) ?></div></div>
    <div class="row">
      <div class="col-6"><?= f_text('std_rate', 'Standard: requests/s', $g['rate_standard']['rate'], $errors, '', 'number') ?></div>
      <div class="col-6"><?= f_text('std_burst', 'Standard: burst', $g['rate_standard']['burst'], $errors, '', 'number') ?></div>
      <div class="col-6"><?= f_text('strict_rate', 'Strict: requests/s', $g['rate_strict']['rate'], $errors, '', 'number') ?></div>
      <div class="col-6"><?= f_text('strict_burst', 'Strict: burst', $g['rate_strict']['burst'], $errors, '', 'number') ?></div>
    </div>
    <h2 class="h6 mt-2">Sign-in protection <span class="text-muted small">(takes effect at once)</span></h2>
    <div class="row">
      <div class="col-4"><?= f_text('max_failures', 'Failures', $login['max_failures'], $errors, '', 'number', 'login') ?></div>
      <div class="col-4"><?= f_text('window_mins', 'within (min)', intdiv((int)$login['window_secs'], 60), [], '', 'number') ?></div>
      <div class="col-4"><?= f_text('ban_hours', 'ban for (h)', intdiv((int)$login['ban_secs'], 3600), [], '', 'number') ?></div>
    </div>
  </div>
</div>
<button class="btn btn-primary">Save</button>
</form>
<?php page_end();
