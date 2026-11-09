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
$certs = Live::certs();
usort($certs, fn($a, $b) => strcmp($a['not_after'], $b['not_after']));
if ($certs) {
    $next = $certs[0];
    $days = (int)floor((strtotime($next['not_after']) - time()) / 86400);
    $b = '<div>' . count($certs) . ' Let\'s Encrypt certificates</div><div>Next expiry: ' . h($next['name']) . ' in ' . $days . ' days</div>';
    $tiles[] = tile('Certificates', $days < 7 ? 'red' : ($days < 20 ? 'amber' : 'green'), $b);
} else {
    $tiles[] = tile('Certificates', 'grey', 'No Let\'s Encrypt certificate yet.');
}

// Access
$cleared = (int)DB::val('SELECT count(*) FROM cleared_ips WHERE expires_at IS NULL OR expires_at > now()');
$used = (int)DB::val("SELECT count(*) FROM audit_log WHERE action = 'link.use' AND at > now() - interval '24 hours'");
$bans = (int)DB::val('SELECT count(*) FROM banned_ips WHERE expires_at > now()');
$tiles[] = tile('Access', 'green', "<div>$cleared cleared addresses</div><div>$used link visits in 24 h</div><div>$bans login bans</div>", '/access');

// Blocks
$blocks = (int)DB::val('SELECT count(*) FROM blocks WHERE expires_at > now()');
$fw = Status::read('firewall');
$b = "<div>$blocks active in nginx</div>";
if ($fw) $b .= '<div>' . h($fw['sets']['pspm-block4'] ?? 0) . ' + ' . h($fw['sets']['pspm-block6'] ?? 0) . ' in the firewall</div>';
else $b .= '<div>Firewall state: no report from the agent yet</div>';
$tiles[] = tile('Blocks', $fw ? 'green' : 'grey', $b);

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
$up = Status::read('updates');
$b .= '<div>Code: ' . h(Status::codeCommit()) . (($up['behind'] ?? 0) > 0 ? ', <strong>' . h($up['behind']) . ' updates available</strong>' : '') . '</div>';
$tiles[] = tile('System', $level, $b);

// Recent activity
$rows = DB::all('SELECT at, actor, action, object FROM audit_log ORDER BY at DESC LIMIT 10');
$b = '<ul class="list-unstyled mb-0">';
foreach ($rows as $r) $b .= '<li><span class="text-muted">' . h(fmt_time($r['at'], 'H:i')) . '</span> ' . h($r['actor']) . ' · ' . h($r['action']) . ($r['object'] ? ' <span class="text-muted">' . h($r['object']) . '</span>' : '') . '</li>';
$tiles[] = tile('Recent activity', 'grey', $b . '</ul>', '/activity');

page_start('Dashboard', '/');
echo '<div class="row row-cols-1 row-cols-md-2 row-cols-xl-3 g-3">' . implode('', $tiles) . '</div>';
page_end();
