<?php
// Global settings (plan §7.1). Static ones go through revisions; login protection is runtime.
declare(strict_types=1);

$u = Auth::require('admin');
$g = Settings::global();
$login = Settings::get('login');
$errors = [];
$rt = [];
if (is_post() && in_array(post('action'), ['runtime', 'test_mail'], true)) {
    if (post('action') === 'test_mail') {
        $to = Validate::email((string)post('test_to'));
        $ok = $to && Notify::mail([$to], '[PSPM] Test e-mail', "This is a test from PSPM.\n", $err);
        flash($ok ? "Test mail sent to $to." : 'The test mail failed: ' . ($to ? $err : 'not an e-mail address'), $ok ? 'success' : 'danger');
        redirect('/settings#runtime');
    }
    $ai = AI::settings();
    $ai['base_url'] = Validate::url((string)post('ai_base_url')) ?? $ai['base_url'];
    $ai['model'] = preg_match('#^[A-Za-z0-9._:/@-]{0,100}$#', trim((string)post('ai_model'))) ? trim((string)post('ai_model')) : $ai['model'];
    if (trim((string)post('ai_key')) !== '') $ai['key_enc'] = Crypto::seal(trim((string)post('ai_key')));
    if (isset($_POST['ai_key_clear'])) $ai['key_enc'] = '';
    $ai['daily_cap'] = Validate::int(post('ai_daily_cap'), 1, 10000) ?? $ai['daily_cap'];
    $ai['confidence'] = max(0.5, min(0.99, (float)post('ai_confidence', $ai['confidence'])));
    $ai['analyse_authorised'] = isset($_POST['ai_authorised']);
    $ai['reaction_hours'] = Validate::int(post('reaction_hours'), 1, 720) ?? $ai['reaction_hours'];
    Settings::set('ai', $ai);
    Settings::set('unknown_hosts', ['threshold' => Validate::int(post('unknown_threshold'), 0, 1000) ?? 5, 'window' => 60 * (Validate::int(post('unknown_window'), 1, 1440) ?? 60)]);
    Settings::set('traps', ['enabled' => isset($_POST['traps_enabled'])]);
    Settings::set('trust', ['authorised_days' => Validate::int(post('authorised_days'), 1, 365) ?? 30]);
    Settings::set('pki', ['strict' => isset($_POST['pki_strict'])]);
    Settings::set('firewall_enforcement', isset($_POST['firewall_enforcement']));
    $smtp = Notify::smtp();
    $smtp['host'] = preg_match('/^[A-Za-z0-9.-]{0,253}$/', trim((string)post('smtp_host'))) ? trim((string)post('smtp_host')) : $smtp['host'];
    $smtp['port'] = Validate::int(post('smtp_port'), 1, 65535) ?? 587;
    $smtp['security'] = Validate::enum(post('smtp_security'), ['starttls', 'tls', 'none']) ?? 'starttls';
    if ($smtp['security'] === 'none' && $smtp['host'] !== '' && !(IP::valid($smtp['host']) && IP::isPrivate($smtp['host']))) {
        $errors['smtp_security'] = 'Without TLS only for a relay at a private IP address.';
        $smtp['security'] = 'starttls';
    }
    $smtp['user'] = mb_substr(trim((string)post('smtp_user')), 0, 200);
    if (trim((string)post('smtp_pass')) !== '') $smtp['pass_enc'] = Crypto::seal((string)post('smtp_pass'));
    $smtp['from'] = Validate::email((string)post('smtp_from')) ?? '';
    $smtp['extra'] = array_values(array_filter(array_map(fn($e) => Validate::email($e), preg_split('/[\s,]+/', (string)post('smtp_extra'), -1, PREG_SPLIT_NO_EMPTY) ?: [])));
    Settings::set('smtp', $smtp);
    if (trim((string)post('backup_pass')) !== '') {
        if ($e = PKI::passphraseProblem((string)post('backup_pass'))) $errors['backup_pass'] = $e;
        else Settings::set('backup', ['passphrase_enc' => Crypto::seal((string)post('backup_pass'))]);
    }
    Audit::log('settings.runtime', 'settings:runtime', ['ai_model' => $ai['model'], 'smtp_host' => $smtp['host']]);
    State::publish('meta', 'certs', 'traps');
    if (!$errors) { flash('Saved. These settings take effect at once.'); redirect('/settings#runtime'); }
}
if (is_post() && !in_array(post('action'), ['runtime', 'test_mail'], true)) {
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
    <?= f_text('admin_host', 'Admin host name', $g['admin_host'], $errors, 'Empty: the UI answers by IP, to private addresses only. Once set and its certificate exists, the UI answers only there (and through the SSH tunnel). It may be the sign-in host of a Microsoft provider; that host\'s /oauth2/ stays public.') ?>
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

<?php $ai = AI::settings(); $smtp = Notify::smtp(); $uh = Settings::get('unknown_hosts', []); ?>
<h2 class="h5 mt-5" id="runtime">Runtime settings <span class="text-muted small">(take effect at once, no apply needed)</span></h2>
<?= errors_box(array_intersect_key($errors, ['smtp_security' => 1, 'backup_pass' => 1])) ?>
<form method="post" class="col-xl-9" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="runtime">
<div class="row">
  <div class="col-lg-6">
    <h3 class="h6">AI (security scan, behaviour, honeypots)</h3>
    <?= f_text('ai_base_url', 'API base URL (OpenAI-compatible)', $ai['base_url'], [], 'OpenRouter: https://openrouter.ai/api/v1') ?>
    <?= f_text('ai_model', 'Model', $ai['model'], [], 'Empty turns the AI off; the deterministic checks keep working.') ?>
    <?= f_text('ai_key', 'API key' . ($ai['key_enc'] ? ' (set; empty keeps it)' : ''), '', [], 'Stored encrypted.', 'password', '', ['autocomplete' => 'new-password']) ?>
    <?= $ai['key_enc'] ? f_check('ai_key_clear', 'Remove the key', false) : '' ?>
    <div class="row"><div class="col-6"><?= f_text('ai_daily_cap', 'Calls per day at most', $ai['daily_cap'], [], '', 'number') ?></div>
      <div class="col-6"><?= f_text('ai_confidence', 'Block from confidence', $ai['confidence'], [], '0.5–0.99', 'text') ?></div></div>
    <?= f_check('ai_authorised', 'Also analyse authorised actors (pseudonymised; reported, never blocked)', (bool)$ai['analyse_authorised']) ?>
    <?= f_text('reaction_hours', 'Reaction time for risky findings (hours)', $ai['reaction_hours'], [], 'No reaction within this time blocks the (untrusted) address.', 'number') ?>
    <h3 class="h6 mt-3">Blocking</h3>
    <div class="row"><div class="col-6"><?= f_text('unknown_threshold', 'Unknown host names before a block', $uh['threshold'] ?? 5, [], '0 turns the rule off', 'number') ?></div>
      <div class="col-6"><?= f_text('unknown_window', 'within (minutes)', intdiv((int)($uh['window'] ?? 3600), 60), [], '', 'number') ?></div></div>
    <?= f_check('traps_enabled', 'Honeypots', (bool)(Settings::get('traps', [])['enabled'] ?? true)) ?>
    <?= f_check('firewall_enforcement', 'Firewall enforcement (blocks and blocklists drop on every port)', (bool)Settings::get('firewall_enforcement')) ?>
    <?= f_text('authorised_days', 'Authorised addresses expire after (days without a new authorisation)', (int)(Settings::get('trust', [])['authorised_days'] ?? 30), [], '', 'number') ?>
    <?= f_check('pki_strict', 'Strict certificates: from a CA that PSPM issues with, only certificates PSPM issued count', (bool)(Settings::get('pki', [])['strict'] ?? true)) ?>
  </div>
  <div class="col-lg-6">
    <h3 class="h6">E-mail notifications (SMTP relay)</h3>
    <div class="row"><div class="col-8"><?= f_text('smtp_host', 'Host', $smtp['host'], [], 'Empty: no e-mail') ?></div><div class="col-4"><?= f_text('smtp_port', 'Port', $smtp['port'], [], '', 'number') ?></div></div>
    <?= f_select('smtp_security', 'Security', $smtp['security'], ['starttls' => 'STARTTLS (port 587)', 'tls' => 'TLS (port 465)', 'none' => 'none (relay at a private address only)'], $errors) ?>
    <div class="row"><div class="col-6"><?= f_text('smtp_user', 'User (optional)', $smtp['user']) ?></div>
      <div class="col-6"><?= f_text('smtp_pass', 'Password' . ($smtp['pass_enc'] ? ' (set)' : ''), '', [], 'Sent only over TLS', 'password', '', ['autocomplete' => 'new-password']) ?></div></div>
    <?= f_text('smtp_from', 'Sender', $smtp['from'], [], 'Default: pspm@' . h(pspm_conf('BOX_FQDN', 'this-box'))) ?>
    <?= f_text('smtp_extra', 'Extra recipients for findings and health', implode(' ', $smtp['extra']), [], 'Addresses that are not users, e.g. a team mailbox') ?>
    <p class="small text-muted">Each user sets their own address and categories under <a href="/account">Account</a>.</p>
    <h3 class="h6 mt-3">Backups</h3>
    <?= f_text('backup_pass', 'Passphrase for the secrets in nightly backups' . (Settings::get('backup', [])['passphrase_enc'] ?? '' ? ' (set)' : ''), '', $errors, 'At least 16 characters. Keep it outside this box: without it the secrets in a backup cannot be restored.', 'password', '', ['autocomplete' => 'new-password']) ?>
  </div>
</div>
<button class="btn btn-primary">Save runtime settings</button>
</form>
<form method="post" class="row g-2 mt-2 col-xl-6"><?= csrf_field() ?><input type="hidden" name="action" value="test_mail">
  <div class="col-8"><input class="form-control form-control-sm" name="test_to" placeholder="send a test mail to …" value="<?= h($u['email'] ?? '') ?>"></div>
  <div class="col-4"><button class="btn btn-sm btn-outline-secondary w-100">Send test e-mail</button></div></form>
<?php page_end();
