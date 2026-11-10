<?php
// Global settings (plan §7.1). Static ones go through revisions; login protection is runtime.
declare(strict_types=1);

$u = Auth::require('admin');
$g = Settings::global();
$login = Settings::get('login');
$errors = [];
$rt = [];
if (is_post() && in_array(post('action'), ['runtime', 'test_mail', 'test_model'], true)) {
    if (post('action') === 'test_model') {
        // a fixed, harmless request with the saved settings of one model; the AI log keeps it
        $role = array_key_exists((string)post('role'), AI::ROLES) ? (string)post('role') : 'main';
        try {
            $t = AI::test($role);
            flash(AI::ROLES[$role] . ': ' . ($t['ok'] ? 'answered correctly' : 'answered, but not as asked') . " in {$t['ms']} ms (model "
                . ($t['model'] ?? '?') . '). The call is in Security → AI log.', $t['ok'] ? 'success' : 'warning');
        } catch (Throwable $e) {
            flash(AI::ROLES[$role] . ': ' . mb_substr($e->getMessage(), 0, 300), 'danger');
        }
        redirect('/settings#models');
    }
    if (post('action') === 'test_mail') {
        $to = Validate::email((string)post('test_to'));
        $ok = $to && Notify::mail([$to], '[PSPM] Test e-mail', "This is a test from PSPM.\n", $err);
        flash($ok ? "Test mail sent to $to." : 'The test mail failed: ' . ($to ? $err : 'not an e-mail address'), $ok ? 'success' : 'danger');
        redirect('/settings#runtime');
    }
    $lf = ['max_failures' => Validate::int(post('max_failures'), 3, 1000), 'window_secs' => Validate::int(post('window_mins'), 1, 1440),
        'ban_secs' => Validate::int(post('ban_hours'), 1, 8760)];
    if (in_array(null, $lf, true)) $errors['login'] = 'Sign-in protection: whole numbers within range.';
    else Settings::set('login', ['max_failures' => $lf['max_failures'], 'window_secs' => $lf['window_secs'] * 60, 'ban_secs' => $lf['ban_secs'] * 3600]);
    $ai = AI::settings();
    $u = trim((string)post('ai_base_url'));
    if ($u !== '' && ($p = AI::urlProblem($u))) $errors['ai_base_url'] = "Main model, API URL: $p";
    else $ai['base_url'] = $u ?: AI::DEFAULTS['base_url'];
    $ai['model'] = preg_match('#^[A-Za-z0-9._:/@-]{0,100}$#', trim((string)post('ai_model'))) ? trim((string)post('ai_model')) : $ai['model'];
    if (trim((string)post('ai_key')) !== '') $ai['key_enc'] = Crypto::seal(trim((string)post('ai_key')));
    if (isset($_POST['ai_key_clear'])) $ai['key_enc'] = '';
    $ai['daily_cap'] = Validate::int(post('ai_daily_cap'), 1, 10000) ?? $ai['daily_cap'];
    $ai['confidence'] = max(0.5, min(0.99, (float)post('ai_confidence', $ai['confidence'])));
    $ai['analyse_authorised'] = isset($_POST['ai_authorised']);
    $ai['reaction_hours'] = Validate::int(post('reaction_hours'), 1, 720) ?? $ai['reaction_hours'];
    Settings::set('ai', $ai);
    // the injection check
    $ck = array_replace(AI::CHECK_DEFAULTS, (array)Settings::get('ai_check', []));
    $ck['type'] = Validate::enum(post('check_type'), ['classifier', 'chat']) ?? 'classifier';
    $ck['model'] = preg_match('#^[A-Za-z0-9._:/@-]{0,100}$#', trim((string)post('check_model'))) ? trim((string)post('check_model')) : $ck['model'];
    $ck['same_as_main'] = isset($_POST['check_same']);
    $u = trim((string)post('check_base_url'));
    if ($u !== '' && ($p = AI::urlProblem($u))) $errors['check_base_url'] = "Injection check, API URL: $p";
    else $ck['base_url'] = $u;
    if (trim((string)post('check_key')) !== '') $ck['key_enc'] = Crypto::seal(trim((string)post('check_key')));
    if (isset($_POST['check_key_clear'])) $ck['key_enc'] = '';
    $ck['daily_cap'] = Validate::int(post('check_daily_cap'), 1, 100000) ?? $ck['daily_cap'];
    $ck['threshold'] = max(0.05, min(0.99, (float)post('check_threshold', $ck['threshold'])));
    Settings::set('ai_check', $ck);
    // the verifier
    $vf = array_replace(AI::VERIFY_DEFAULTS, (array)Settings::get('ai_verify', []));
    $vf['model'] = preg_match('#^[A-Za-z0-9._:/@-]{0,100}$#', trim((string)post('verify_model'))) ? trim((string)post('verify_model')) : $vf['model'];
    $vf['same_as_main'] = isset($_POST['verify_same']);
    $u = trim((string)post('verify_base_url'));
    if ($u !== '' && ($p = AI::urlProblem($u))) $errors['verify_base_url'] = "Verification model, API URL: $p";
    else $vf['base_url'] = $u;
    if (trim((string)post('verify_key')) !== '') $vf['key_enc'] = Crypto::seal(trim((string)post('verify_key')));
    if (isset($_POST['verify_key_clear'])) $vf['key_enc'] = '';
    $vf['daily_cap'] = Validate::int(post('verify_daily_cap'), 1, 100000) ?? $vf['daily_cap'];
    Settings::set('ai_verify', $vf);
    Settings::set('unknown_hosts', ['threshold' => Validate::int(post('unknown_threshold'), 0, 1000) ?? 5, 'window' => 60 * (Validate::int(post('unknown_window'), 1, 1440) ?? 60)]);
    Settings::set('traps', ['enabled' => isset($_POST['traps_enabled'])]);
    Settings::set('trust', ['authorised_days' => Validate::int(post('authorised_days'), 1, 365) ?? 30]);
    Settings::set('behaviour', ['interval_hours' => Validate::int(post('behaviour_hours'), 1, 168) ?? Behaviour::DEFAULT_INTERVAL_HOURS]);
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
if (is_post() && !in_array(post('action'), ['runtime', 'test_mail', 'test_model'], true)) {
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
    if (!$errors) {
        Settings::saveGlobal($norm);
        Audit::log('settings.update', 'settings:global', ['admin_host' => $norm['admin_host']]);
        flash('Configuration saved. It takes effect with the next apply: mark it ready on Changes, then run install.sh.');
        redirect('/settings');
    }
    $g = array_replace($g, $in);
}
page_start('Settings', '/settings');
$card = function (string $id, string $title, string $what): string {
    return '<div class="card mb-3" id="' . h($id) . '"><div class="card-header"><h3 class="h6">' . h($title) . '</h3>'
        . '<div class="small text-muted">' . h($what) . '</div></div><div class="card-body">';
};
$end = '</div></div>';
// One field group per model (docs/security-ai-improvements.md §4); $p is the field prefix.
$modelGroup = function (string $role, string $p, string $what, array $m, array $extra = []) use ($errors): string {
    $o = '<fieldset class="border rounded p-2 mb-3"><legend class="h6 float-none w-auto px-1 mb-1">' . h(AI::ROLES[$role]) . '</legend>'
        . '<div class="small text-muted mb-2">' . h($what) . '</div>';
    $o .= implode('', $extra['before'] ?? []);
    $o .= f_text("{$p}_model", 'Model', $m['model'], [], $extra['model_help'] ?? '');
    $o .= ($extra['same'] ?? '') . '<div class="' . h($extra['same_class'] ?? '') . '">';
    $o .= f_text("{$p}_base_url", 'API base URL', $m['base_url'], $errors, $extra['url_help'] ?? 'OpenAI-compatible, e.g. https://openrouter.ai/api/v1', 'text', "{$p}_base_url");
    $o .= f_text("{$p}_key", 'API key' . ($m['key_enc'] ? ' (set; empty keeps it)' : ''), '', [], 'Stored encrypted.', 'password', '', ['autocomplete' => 'new-password']);
    $o .= $m['key_enc'] ? f_check("{$p}_key_clear", 'Remove the key', false) : '';
    $o .= '</div>' . implode('', $extra['after'] ?? []);
    $o .= '<div class="row align-items-end"><div class="col-6">' . f_text("{$p}_daily_cap", 'Calls per day at most', $m['daily_cap'], [], '', 'number') . '</div>'
        . '<div class="col-6 mb-3"><button class="btn btn-sm btn-outline-secondary" form="test-model-form" name="role" value="' . h($role) . '">Test</button>'
        . ' <span class="small text-muted">uses the saved settings</span></div></div>';
    return $o . '</fieldset>';
};
$ai = AI::settings(); $smtp = Notify::smtp(); $uh = Settings::get('unknown_hosts', []);
?>
<h1 class="h4 mb-2">Settings</h1>
<p class="mb-2">Two kinds of settings: <strong>configuration</strong> is part of a revision and takes effect when it is applied
  with <code>install.sh</code>; <strong>runtime</strong> settings take effect as soon as they are saved.</p>
<nav class="section-nav small mb-4">
  <strong>Configuration:</strong> <a href="#admin-ui">Admin UI</a> · <a href="#certificates">Certificates</a> · <a href="#site-defaults">Site defaults</a> · <a href="#rate-limits">Rate limits</a>
  <span class="mx-2">|</span>
  <strong>Runtime:</strong> <a href="#signin-protection">Sign-in protection</a> · <a href="#models">Models</a> · <a href="#ai">AI decisions</a> · <a href="#blocking">Blocking and trust</a> · <a href="#mail">E-mail</a> · <a href="#backups">Backups</a>
</nav>

<div class="settings-group col-xxl-10" id="configuration">
<h2 class="h5">Configuration <span class="badge text-bg-warning align-middle">applied with install.sh</span></h2>
<?= errors_box(array_diff_key($errors, ['login' => 1, 'smtp_security' => 1, 'backup_pass' => 1, 'ai_base_url' => 1, 'check_base_url' => 1, 'verify_base_url' => 1]) ? ['Please correct the marked fields.'] : []) ?>
<form method="post"><?= csrf_field() ?>
<div class="row g-3">
  <div class="col-lg-6">
    <?= $card('admin-ui', 'Admin UI', 'Where the UI answers and who may open it; password and code are always needed.') ?>
      <?= f_text('admin_host', 'Admin host name', $g['admin_host'], $errors, 'Empty: the UI answers by IP, to private addresses only. Once set and its certificate exists, the UI answers only there (and through the SSH tunnel). It may be the sign-in host of a Microsoft provider; that host\'s /oauth2/ stays public.') ?>
      <div class="mb-3"><span class="form-label d-block">Who may open the UI on the host name</span>
        <?= f_check('admin_access[]', 'LAN', in_array('lan', $g['admin_access'], true), '', 'lan') ?>
        <?= f_check('admin_access[]', 'Access links for the admin UI (Access page; needs the admin host name)', in_array('cleared', $g['admin_access'], true), '', 'cleared') ?>
        <?= f_check('admin_access[]', 'Client certificate', in_array('cert', $g['admin_access'], true), '', 'cert') ?>
        <?= f_check('admin_access[]', 'Everyone (password and code only)', in_array('public', $g['admin_access'], true), '', 'public') ?>
        <?= field_err($errors, 'admin_access') ?></div>
      <?= f_area('lan_ranges', 'LAN ranges', implode("\n", $g['lan_ranges']), $errors, 'Used by the LAN condition of the UI and of every site. One network per line.', 4) ?>
    <?= $end ?>
    <?= $card('certificates', 'Certificates', 'Let\'s Encrypt account details.') ?>
      <?= f_text('acme_email', 'Let\'s Encrypt e-mail (optional)', $g['acme_email'], $errors, 'Expiry warnings from Let\'s Encrypt. PSPM watches expiry anyway (Certificates page).') ?>
    <?= $end ?>
  </div>
  <div class="col-lg-6">
    <?= $card('site-defaults', 'Site defaults', 'TLS and response headers for every site that does not set its own.') ?>
      <?= f_select('tls_profile', 'TLS profile', $g['tls_profile'], ['intermediate' => 'intermediate (TLS 1.2 + 1.3)', 'modern' => 'modern (TLS 1.3 only)']) ?>
      <?= f_check('security_headers', 'Security headers (nosniff, Referrer-Policy, hide X-Powered-By)', (bool)$g['security_headers']) ?>
      <?= f_check('error_pages', 'PSPM error pages (403, 404, 429, 502, 503, 504)', (bool)$g['error_pages']) ?>
      <?= f_check('hsts_enabled', 'HSTS', (bool)$g['hsts']['enabled']) ?>
      <div class="row"><div class="col-md-6"><?= f_text('hsts_max_age', 'HSTS max-age (s)', $g['hsts']['max_age'], $errors, '', 'number') ?></div>
        <div class="col-md-6 pt-md-4"><?= f_check('hsts_sub', 'includeSubDomains', (bool)$g['hsts']['include_subdomains']) ?></div></div>
    <?= $end ?>
    <?= $card('rate-limits', 'Rate limits', 'Requests per second per address; a site chooses standard or strict.') ?>
      <div class="row">
        <div class="col-6"><?= f_text('std_rate', 'Standard: requests/s', $g['rate_standard']['rate'], $errors, '', 'number') ?></div>
        <div class="col-6"><?= f_text('std_burst', 'Standard: burst', $g['rate_standard']['burst'], $errors, '', 'number') ?></div>
        <div class="col-6"><?= f_text('strict_rate', 'Strict: requests/s', $g['rate_strict']['rate'], $errors, '', 'number') ?></div>
        <div class="col-6"><?= f_text('strict_burst', 'Strict: burst', $g['rate_strict']['burst'], $errors, '', 'number') ?></div>
      </div>
    <?= $end ?>
  </div>
</div>
<button class="btn btn-primary">Save configuration</button> <span class="small text-muted ms-2">Then mark it ready on <a href="/changes">Changes</a> and run <code>install.sh</code>.</span>
</form>
</div>

<div class="settings-group col-xxl-10 mt-5" id="runtime">
<h2 class="h5">Runtime <span class="badge text-bg-success align-middle">takes effect at once</span></h2>
<?= errors_box(array_intersect_key($errors, ['login' => 1, 'smtp_security' => 1, 'backup_pass' => 1, 'ai_base_url' => 1, 'check_base_url' => 1, 'verify_base_url' => 1])) ?>
<form method="post" id="test-mail-form"><?= csrf_field() ?><input type="hidden" name="action" value="test_mail"></form>
<form method="post" id="test-model-form"><?= csrf_field() ?><input type="hidden" name="action" value="test_model"></form>
<form method="post" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="runtime">
<div class="row g-3">
  <div class="col-lg-6">
    <?= $card('signin-protection', 'Sign-in protection', 'Failed sign-ins to the UI from one address lead to a ban on every site.') ?>
      <div class="row">
        <div class="col-4"><?= f_text('max_failures', 'Failures', $login['max_failures'], $errors, '', 'number', 'login') ?></div>
        <div class="col-4"><?= f_text('window_mins', 'within (min)', intdiv((int)$login['window_secs'], 60), [], '', 'number') ?></div>
        <div class="col-4"><?= f_text('ban_hours', 'ban for (h)', intdiv((int)$login['ban_secs'], 3600), [], '', 'number') ?></div>
      </div>
    <?= $end ?>
    <?= $card('models', 'Models', 'One field group per model. Only pseudonymised evidence leaves the box; every call is in Security → AI log.') ?>
      <?= $modelGroup('main', 'ai', 'Scan verdicts, behaviour assessments and honeypot proposals. Empty model: AI off; honeypots and the guards keep working.', AI::model('main'),
          ['model_help' => 'e.g. a fast, inexpensive model']) ?>
      <?php $ck = AI::model('check'); ?>
      <?= $modelGroup('check', 'check', 'Screens every attacker-written string (paths, user agents) before a model sees it. Its answer has one fixed type, '
          . '{label: safe|injection, score}; anything else counts as injection. Flagged strings are removed and the address is tagged. Off or failing: '
          . 'user agents are left out and only path-shaped paths are sent.', $ck, [
          'before' => [f_select('check_type', 'Type', $ck['type'], ['classifier' => 'Classifier API (e.g. Llama Prompt Guard 2 behind a Hugging Face-style endpoint)',
              'chat' => 'Chat model (OpenAI-compatible) asked for the fixed type'])],
          'model_help' => 'Classifier: a name for the log and the cache. Chat: the model id. Empty: off.',
          'url_help' => 'Classifier: the full URL that takes {"inputs": [...]}. Chat: the OpenAI-compatible base URL.',
          'same' => f_check('check_same', 'Chat: same API URL and key as the main model', $ck['same_as_main']),
          'after' => [f_text('check_threshold', 'Injection from score', $ck['threshold'], [], '0.05–0.99; the score is the probability of an injection')]]) ?>
      <?php $vf = AI::model('verify'); ?>
      <?= $modelGroup('verify', 'verify', 'An independent second opinion on every automatic block, with the same evidence but not the first verdict. Both must say block; '
          . 'if they disagree, the address becomes a finding with the reaction time. Honeypot proposals count only when it agrees. Empty: off, as before.', $vf, [
          'model_help' => 'Best from another model family than the main model, e.g. a stronger one. Empty: off.',
          'same' => f_check('verify_same', 'Same API URL and key as the main model', $vf['same_as_main'])]) ?>
    <?= $end ?>
    <?= $card('ai', 'AI decisions', 'How AI answers turn into blocks; these apply to every model.') ?>
      <?= f_text('ai_confidence', 'Block from confidence', $ai['confidence'], [], '0.5–0.99') ?>
      <?= f_check('ai_authorised', 'Also analyse authorised actors (pseudonymised; reported, never blocked)', (bool)$ai['analyse_authorised']) ?>
      <?= f_text('reaction_hours', 'Reaction time for risky findings (hours)', $ai['reaction_hours'], [], 'No reaction within this time blocks the (untrusted) address.', 'number') ?>
    <?= $end ?>
  </div>
  <div class="col-lg-6">
    <?= $card('blocking', 'Blocking and trust', 'Automatic blocks, honeypots, the firewall, and how long authorisations last.') ?>
      <div class="row"><div class="col-6"><?= f_text('unknown_threshold', 'Unknown host names before a block', $uh['threshold'] ?? 5, [], '0 turns the rule off', 'number') ?></div>
        <div class="col-6"><?= f_text('unknown_window', 'within (minutes)', intdiv((int)($uh['window'] ?? 3600), 60), [], '', 'number') ?></div></div>
      <?= f_check('traps_enabled', 'Honeypots', (bool)(Settings::get('traps', [])['enabled'] ?? true)) ?>
      <?= f_check('firewall_enforcement', 'Firewall enforcement (blocks and blocklists drop on every port)', (bool)Settings::get('firewall_enforcement')) ?>
      <?= f_text('authorised_days', 'Authorised addresses expire after (days without a new authorisation)', (int)(Settings::get('trust', [])['authorised_days'] ?? 30), [], '', 'number') ?>
      <?= f_text('behaviour_hours', 'Search for risky behaviour every (hours)', Behaviour::intervalHours(), [], 'Default 12. Looks at the last 24 hours each time. Reaction deadlines and reminders are checked every 5 minutes regardless.', 'number') ?>
      <?= f_check('pki_strict', 'Strict certificates: from a CA that PSPM issues with, only certificates PSPM issued count', (bool)(Settings::get('pki', [])['strict'] ?? true)) ?>
    <?= $end ?>
    <?= $card('mail', 'E-mail notifications', 'SMTP relay for findings, health problems and account events. Each user sets their address under Account.') ?>
      <div class="row"><div class="col-8"><?= f_text('smtp_host', 'Host', $smtp['host'], [], 'Empty: no e-mail') ?></div><div class="col-4"><?= f_text('smtp_port', 'Port', $smtp['port'], [], '', 'number') ?></div></div>
      <?= f_select('smtp_security', 'Security', $smtp['security'], ['starttls' => 'STARTTLS (port 587)', 'tls' => 'TLS (port 465)', 'none' => 'none (relay at a private address only)'], $errors) ?>
      <div class="row"><div class="col-6"><?= f_text('smtp_user', 'User (optional)', $smtp['user'], [], '') ?></div>
        <div class="col-6"><?= f_text('smtp_pass', 'Password' . ($smtp['pass_enc'] ? ' (set)' : ''), '', [], 'Sent only over TLS', 'password', '', ['autocomplete' => 'new-password']) ?></div></div>
      <?= f_text('smtp_from', 'Sender', $smtp['from'], [], 'Default: pspm@' . pspm_conf('BOX_FQDN', 'this-box')) ?>
      <?= f_text('smtp_extra', 'Extra recipients for findings and health', implode(' ', $smtp['extra']), [], 'Addresses that are not users, e.g. a team mailbox') ?>
      <div class="input-group input-group-sm"><input class="form-control" form="test-mail-form" name="test_to" placeholder="send a test mail to …" value="<?= h($u['email'] ?? '') ?>">
        <button class="btn btn-outline-secondary" form="test-mail-form">Send test e-mail</button></div>
      <div class="form-text">Uses the saved settings: save first.</div>
    <?= $end ?>
    <?= $card('backups', 'Backups', 'Nightly at 03:17: a database dump and a JSON export whose secrets are encrypted with this passphrase.') ?>
      <?= f_text('backup_pass', 'Passphrase for the secrets in nightly backups' . (Settings::get('backup', [])['passphrase_enc'] ?? '' ? ' (set)' : ''), '', $errors, 'At least 16 characters. Keep it outside this box: without it the secrets in a backup cannot be restored.', 'password', '', ['autocomplete' => 'new-password']) ?>
    <?= $end ?>
  </div>
</div>
<button class="btn btn-primary">Save runtime settings</button>
</form>
</div>
<?php page_end();
