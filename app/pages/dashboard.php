<?php
// The first page (plan §8.4): a grid of tiles, green / amber / red, each linking to its page.
declare(strict_types=1);

$u = Auth::require('viewer');

function tile(string $title, string $level, string $body, string $href = ''): string
{
    $border = ['green' => 'success', 'amber' => 'warning', 'red' => 'danger', 'grey' => 'secondary'][$level] ?? 'secondary';
    $t = $href ? '<a href="' . h($href) . '" class="stretched-link text-reset text-decoration-none">' . h($title) . '</a>' : h($title);
    return '<div class="col"><div class="card h-100 border-' . $border . ' border-2 tile"><div class="card-body position-relative">'
        . '<h2 class="h6 card-title d-flex justify-content-between">' . $t . badge($level, ['green' => 'OK', 'amber' => 'Check', 'red' => 'Problem', 'grey' => '—'][$level] ?? '') . '</h2>'
        . '<div class="small">' . $body . '</div></div></div></div>';
}

$tiles = [];

// Proxy
$master = Live::nginxMaster();
$rel = Live::currentRelease();
$liveRev = Live::revision();
$summary = Live::summary();
$lastApply = DB::one('SELECT * FROM applies ORDER BY finished_at DESC LIMIT 1');
$drift = $rel ? Live::drift() : [];
$driftRed = array_filter($drift, fn($d) => $d['level'] === 'red');
$driftAmber = array_filter($drift, fn($d) => $d['level'] === 'amber');
$level = !$master || $driftRed ? 'red' : ($driftAmber || ($lastApply && !in_array($lastApply['result'], ['applied', 'warnings', 'dry_run'], true)) ? 'amber' : 'green');
if (!$rel) $level = 'grey';
$b = '<div>nginx: ' . ($master ? 'running' . (Live::runsPspmConfig($master) ? '' : ' <strong>(not PSPM\'s configuration)</strong>') : '<strong>not running</strong>') . '</div>';
$b .= '<div>Applied: ' . ($liveRev ? 'revision ' . h($liveRev['id']) . ($lastApply ? ', ' . h(ago($lastApply['finished_at'])) . ' by ' . h($lastApply['ssh_user'] ?: '?') : '') : 'nothing yet') . '</div>';
if ($lastApply) $b .= '<div>Last run: ' . h(str_replace('_', ' ', $lastApply['result'])) . '</div>';
foreach (array_merge($driftRed, $driftAmber) as $d) $b .= '<div class="text-danger">' . h($d['message']) . '</div>';
$adminHost = $summary['admin']['host'] ?? '';
$b .= '<div>UI reached ' . (($summary['admin']['in_effect'] ?? false) ? 'at <code>' . h($adminHost) . '</code>' : 'by IP from private addresses') . ', and through the SSH tunnel</div>';
$tiles[] = tile('Proxy', $level, $b, '/changes');

// Changes
$latest = Revisions::latest();
$working = Revisions::workingChanged();
if ($latest && (int)($liveRev['id'] ?? 0) !== (int)$latest['id']) {
    $b = '<div>Revision ' . h($latest['id']) . ' is ready. On the server run</div><div class="input-group input-group-sm mt-1"><input class="form-control font-monospace" readonly value="sudo /opt/pspm/install.sh" id="applycmd">'
        . '<button class="btn btn-outline-secondary position-relative z-2" data-copy="#applycmd" type="button">Copy</button></div>';
    $tiles[] = tile('Changes', 'amber', $b . ($working ? '<div class="mt-1">More edits are not marked ready yet.</div>' : ''), '/changes');
} elseif ($working) {
    $tiles[] = tile('Changes', 'amber', 'Edits are not marked <em>Ready to apply</em> yet.', '/changes');
} else {
    $tiles[] = tile('Changes', 'green', 'Everything is applied.', '/changes');
}

// Sites
$sites = Model::sites();
$enabled = array_filter($sites, fn($s) => $s['enabled']);
$pending = array_filter($summary['sites'] ?? [], fn($s) => $s['pending']);
$byPolicy = [];
foreach ($enabled as $s) { $k = implode(', ', $s['access']['conditions']); $byPolicy[$k] = ($byPolicy[$k] ?? 0) + 1; }
$b = '<div>' . count($enabled) . ' enabled, ' . (count($sites) - count($enabled)) . ' disabled</div>';
foreach ($byPolicy as $k => $n) $b .= '<div>' . $n . ' × ' . h($k) . '</div>';
if ($pending) $b .= '<div>Waiting for a certificate: ' . h(implode(', ', array_column($pending, 'host'))) . '</div>';
$tiles[] = tile('Sites', $pending ? 'amber' : (count($sites) ? 'green' : 'grey'), $b, '/sites');

// Certificates
// server certificates (Let's Encrypt, IP certificate, trusted CAs): the worst state counts
$server = Live::serverCertificates();
$rank = ['grey' => 0, 'green' => 1, 'amber' => 2, 'red' => 3];
$level = 'grey';
$b = '';
$le = array_values(array_filter($server, fn($c) => $c['kind'] === "Let's Encrypt"));
if ($le) {
    $days = (int)floor((strtotime($le[0]['not_after']) - time()) / 86400);   // sorted by end date
    $b .= '<div>' . count($le) . ' Let\'s Encrypt certificates; next expiry: ' . h($le[0]['name']) . ' in ' . $days . ' days</div>';
} else {
    $b .= '<div>No Let\'s Encrypt certificate yet.</div>';
}
foreach ($server as $c) {
    if (str_starts_with($c['kind'], 'Client CA')) continue;   // CAs: the check below (every CA, not only trusted ones)
    if ($rank[$c['state'][0]] > $rank[$level]) $level = $c['state'][0];
    if (in_array($c['state'][0], ['amber', 'red'], true)) $b .= '<div class="text-' . ($c['state'][0] === 'red' ? 'danger' : 'warning-emphasis') . '">' . h($c['name'] . ': ' . $c['state'][1]) . '</div>';
}
if ($level === 'grey' && $le) $level = 'green';
if ($pendingN = count(Live::pendingCertificates())) { $b .= "<div>$pendingN waiting for a certificate</div>"; if ($rank[$level] < 2) $level = 'amber'; }
$soon = (int)DB::val("SELECT count(*) FROM client_certs WHERE revoked_at IS NULL AND not_after BETWEEN now() AND now() + interval '30 days'");
$new7 = DB::all("SELECT subject_cn FROM client_certs WHERE issued_at > now() - interval '7 days' ORDER BY issued_at DESC");
$caSoon = DB::all("SELECT name FROM cas WHERE not_after < now() + interval '1 year'");
if ($soon) { $b .= "<div>$soon client certificates expire within 30 days</div>"; if ($level !== 'red') $level = 'amber'; }
if ($new7) $b .= '<div>Issued in 7 days: ' . h(implode(', ', array_slice(array_column($new7, 'subject_cn'), 0, 5))) . (count($new7) > 5 ? ' …' : '') . '</div>';
if ($caSoon) { $b .= '<div class="text-danger">CA expiring within a year: ' . h(implode(', ', array_column($caSoon, 'name'))) . '</div>'; $level = 'red'; }
$tiles[] = tile('Certificates', $level, $b, '/certificates#server');

// Access
$cleared = (int)DB::val('SELECT count(*) FROM cleared_ips WHERE expires_at IS NULL OR expires_at > now()');
$used = (int)DB::val("SELECT count(*) FROM audit_log WHERE action = 'link.use' AND at > now() - interval '24 hours'");
$bans = (int)DB::val('SELECT count(*) FROM banned_ips WHERE expires_at > now()');
$tiles[] = tile('Access', 'green', "<div>$cleared cleared addresses</div><div>$used link visits in 24 h</div><div>$bans login bans</div>", '/access');

// Blocks
$blocks = (int)DB::val('SELECT count(*) FROM blocks WHERE expires_at > now()');
$fw = Status::read('firewall');
$b = "<div>$blocks active in nginx</div>";
$fwProblem = Status::firewallProblem($fw);
$fwCount = fn(string $s) => ($n = $fw['sets'][$s] ?? 0) === -1 ? 'not loaded' : (string)$n;
if ($fw) $b .= '<div>' . h($fwCount('pspm-block4')) . ' + ' . h($fwCount('pspm-block6')) . ' in the firewall</div>';
else $b .= '<div>Firewall state: no report from the agent yet</div>';
if ($fwProblem) $b .= '<div class="text-danger small">' . h($fwProblem) . '</div>';
$tiles[] = tile('Blocks', $fwProblem ? 'red' : ($fw ? 'green' : 'grey'), $b);

// Blocklists
$lists = DB::all('SELECT name, mode, enabled, last_status FROM blocklists WHERE enabled');
if ($lists) {
    $lv = ['green' => 0, 'amber' => 0, 'red' => 0];
    foreach ($lists as $l) { $st = json_dec($l['last_status']) ?? []; $lv[$st['level'] ?? 'amber'] = ($lv[$st['level'] ?? 'amber'] ?? 0) + 1; }
    $drop = 0;
    foreach (($fw['counters'] ?? []) as $c) if (str_contains($c['rule'], 'pspm-feed')) $drop += $c['packets'];
    $b = "<div>{$lv['green']} OK, {$lv['amber']} warning, {$lv['red']} failed</div>";
    if ($fw) $b .= '<div>' . (int)(($fw['sets']['pspm-feed4'] ?? 0) + ($fw['sets']['pspm-feed6'] ?? 0)) . ' entries loaded; ' . $drop . ' packets dropped since the rules were set</div>';
    $tiles[] = tile('Blocklists', $lv['red'] ? 'red' : ($lv['amber'] ? 'amber' : 'green'), $b, '/security?tab=blocklists');
}

// Security scan
$ai = AI::settings();
$scanState = Settings::get('scan', []);
$lastRun = DB::one('SELECT started_at, stats FROM scan_runs ORDER BY id DESC LIMIT 1');
$runAge = $lastRun ? time() - strtotime($lastRun['started_at']) : null;
$b = '<div>Mode: ' . h($ai['mode']) . ' · AI: ' . (AI::configured() ? h($ai['model']) : 'off') . '</div><div>Last run: ' . ($lastRun ? h(ago($lastRun['started_at'])) : 'never') . '</div>';
$b .= '<div>Blocks in 24 h: ' . (int)DB::val("SELECT count(*) FROM block_history WHERE created_by = 'system' AND created_at > now() - interval '24 hours'") . '</div>';
if ($scanState['breaker_tripped'] ?? false) $b .= '<div class="text-danger">Circuit breaker tripped: dry-run until an admin resets it</div>';
$tiles[] = tile('Security scan', ($scanState['breaker_tripped'] ?? false) ? 'red' : ($runAge === null || $runAge > 600 ? 'amber' : 'green'), $b, '/security');

// Behaviour
$open = DB::all("SELECT actor_type, actor, pattern, risk, authorised, deadline FROM risk_findings WHERE status = 'open' ORDER BY risk DESC");
if ($open) {
    $auth = array_filter($open, fn($f) => $f['authorised']);
    $next = array_filter($open, fn($f) => $f['deadline']);
    usort($next, fn($a, $b) => strcmp($a['deadline'], $b['deadline']));
    $b = '<div>' . count($open) . ' open findings, highest risk ' . (int)$open[0]['risk'] . '</div>';
    if ($next) $b .= '<div>Next block if nobody reacts: ' . h(Behaviour::describe($next[0]['actor_type'], $next[0]['actor'])) . ' ' . h(ago($next[0]['deadline'])) . '</div>';
    if ($auth) $b .= '<div class="text-danger">' . count($auth) . ' concern authorised actors</div>';
    $tiles[] = tile('Behaviour', $auth ? 'red' : 'amber', $b, '/security?tab=behaviour');
} else {
    $tiles[] = tile('Behaviour', 'green', 'No open findings.', '/security?tab=behaviour');
}

// Sign-in
$provs = Signin::providers();
if ($provs) {
    $down = 0; $b = '';
    foreach ($provs as $p) { $r = Signin::ready((int)$p['port']); if ($r === false && Signin::users($p['id'])) $down++; $b .= '<div>' . h($p['name']) . ': ' . ($r ? 'running' : 'not running') . '</div>'; }
    $sign = (int)DB::val("SELECT count(*) FROM behaviour_hours WHERE actor_type = 'user' AND hour > now() - interval '24 hours'");
    $b .= "<div>Active signed-in users in 24 h: $sign</div>";
    $tiles[] = tile('Sign-in', $down ? 'red' : 'green', $b, Auth::can('admin') ? '/signin' : '');
}

// System
$dbSize = (int)DB::val('SELECT pg_database_size(current_database())');
$disk = Status::diskFree('/');
$agentAge = Status::age('firewall');
$backups = glob(PSPM_VAR . '/backups/*', GLOB_ONLYDIR) ?: [];
rsort($backups);
$lastBackup = $backups ? (int)filemtime($backups[0]) : null;
$level = 'green';
if ($disk && $disk['pct_used'] > 90) $level = 'red';
elseif (($disk && $disk['pct_used'] > 80) || $agentAge === null || $agentAge > 300) $level = 'amber';
$b = '<div>PostgreSQL up, ' . h(human_bytes($dbSize)) . '</div>';
$b .= '<div>Last backup: ' . ($lastBackup ? h(human_secs(time() - $lastBackup)) . ' ago' : 'none yet') . '</div>';
if ($disk) $b .= '<div>Disk: ' . h($disk['pct_used']) . '% used, ' . h(human_bytes($disk['free'])) . ' free</div>';
$b .= '<div>Agent: ' . ($agentAge === null ? 'no heartbeat yet' : 'heartbeat ' . h(human_secs($agentAge)) . ' ago') . '</div>';
if (Notify::configured()) {
    $mailFail = (int)DB::val("SELECT count(*) FROM notification_outbox WHERE status IN ('pending', 'failed') AND attempts > 2");
    $lastMail = DB::val("SELECT max(sent_at) FROM notification_outbox WHERE status IN ('sent', 'digested')");
    $b .= '<div>E-mail: ' . ($mailFail ? "<strong>$mailFail undelivered</strong>" : 'ok') . ', last sent ' . h(ago($lastMail)) . '</div>';
    if ($mailFail) $level = 'red';
} else {
    $b .= '<div>E-mail: no SMTP relay set</div>';
}
$up = Status::read('updates');
$b .= '<div>Code: ' . h(Status::codeCommit()) . (($up['behind'] ?? 0) > 0 ? ', <strong>' . h($up['behind']) . ' updates available</strong>' : '') . '</div>';
$tiles[] = tile('System', $level, $b);

// Debian packages: the agent counts every hour; apt-get update runs at most once a day (pspm-apt.timer)
$apt = Status::read('apt');
if (!$apt) {
    $tiles[] = tile('Packages', 'grey', '<div>No report yet: the agent counts the upgradable packages every hour.</div>');
} else {
    $level = 'green';
    $b = '';
    $n = $apt['upgradable'] ?? null;
    $sec = (int)($apt['security'] ?? 0);
    if ($n === null) { $level = 'amber'; $b .= '<div>The upgradable packages could not be listed (see the agent log).</div>'; }
    elseif ($n === 0) $b .= '<div>All packages are up to date.</div>';
    else {
        $b .= '<div><strong>' . h($n) . '</strong> can be upgraded' . ($sec ? ', <strong>' . h($sec) . ' security</strong>' : '') . '</div>';
        $list = array_map(fn($p) => '<li>' . h($p['name']) . ' <span class="text-muted">' . h($p['from']) . ' → ' . h($p['to']) . '</span>'
            . ($p['security'] ? ' ' . badge('amber', 'security') : '') . '</li>', array_slice($apt['packages'] ?? [], 0, 40));
        $b .= '<details><summary>Packages</summary><ul class="list-unstyled mb-1">' . implode('', $list) . (count($apt['packages'] ?? []) > 40 ? '<li>…</li>' : '') . '</ul></details>';
        $b .= '<div class="text-muted">Install with <code>sudo apt upgrade</code>; PSPM never upgrades by itself. Security updates install automatically every day.</div>';
    }
    // security updates should be gone within a day (unattended-upgrades)
    if ($sec && !empty($apt['security_since']) && time() - strtotime($apt['security_since']) > 2 * 86400) {
        $level = 'amber';
        $b .= '<div class="text-warning-emphasis">Security updates have been waiting since ' . h(ago($apt['security_since'])) . ': is unattended-upgrades working? (<code>journalctl -u apt-daily-upgrade</code>)</div>';
    }
    if (!empty($apt['reboot_required'])) {
        $level = 'amber';
        $b .= '<div class="text-warning-emphasis">Reboot required' . (($apt['reboot_packages'] ?? []) ? ' (' . h(implode(', ', array_slice($apt['reboot_packages'], 0, 4))) . ')' : '') . '</div>';
    }
    if (!empty($apt['update_error'])) { $level = 'amber'; $b .= '<div class="text-warning-emphasis">apt-get update failed: ' . h(mb_substr($apt['update_error'], 0, 160)) . '</div>'; }
    $listsAge = !empty($apt['last_update']) ? time() - strtotime($apt['last_update']) : null;
    if ($listsAge === null || $listsAge > 3 * 86400) $level = 'amber';
    $b .= '<div class="text-muted">Package lists ' . ($listsAge === null ? 'never refreshed' : 'from ' . h(ago($apt['last_update']))) . ', counted ' . h(ago($apt['checked'] ?? null)) . '</div>';
    $tiles[] = tile('Packages', $level, $b);
}

// Recent activity
$rows = DB::all('SELECT at, actor, action, object FROM audit_log ORDER BY at DESC LIMIT 10');
$b = '<ul class="list-unstyled mb-0">';
foreach ($rows as $r) $b .= '<li><span class="text-muted">' . h(fmt_time($r['at'], 'H:i')) . '</span> ' . h($r['actor']) . ' · ' . h($r['action']) . ($r['object'] ? ' <span class="text-muted">' . h($r['object']) . '</span>' : '') . '</li>';
$tiles[] = tile('Recent activity', 'grey', $b . '</ul>', '/activity');

page_start('Dashboard', '/');
echo '<div class="row row-cols-1 row-cols-md-2 row-cols-xl-3 g-3">' . implode('', $tiles) . '</div>';
page_end();
