<?php
// Security (plan §15, §14.5): scan, blocks, AI verdicts, behaviour, honeypots, blocklists, trust.
declare(strict_types=1);

$u = Auth::require('viewer');
$tab = (string)get('tab', 'overview');
$tabs = ['overview' => 'Overview', 'behaviour' => 'Behaviour', 'traps' => 'Honeypots', 'blocklists' => 'Blocklists', 'trusted' => 'Trusted', 'ailog' => 'AI log', 'verdicts' => 'AI verdicts'];
if (!isset($tabs[$tab])) $tab = 'overview';
$errors = [];
if (is_post()) {
    $a = (string)post('action');
    try {
        $back = '/security?tab=' . rawurlencode($tab);
        if (in_array($a, ['blocklist_save', 'blocklist_delete', 'scan_mode', 'breaker_reset'], true)) Auth::require('admin'); else Auth::require('operator');
        switch ($a) {
            case 'run_now':
                SecScan::setState('run_now', ['at' => gmdate('c'), 'by' => Audit::actor()]);
                flash('The scan runs a full round within a minute.');
                break;
            case 'scan_mode':
                $ai = AI::settings();
                $ai['mode'] = Validate::enum(post('mode'), ['enforce', 'dry-run', 'collect']) ?? 'enforce';
                Settings::set('ai', $ai);
                // back to enforce: the feedback rule counts AI blocks from now on, and its note goes
                if ($ai['mode'] === 'enforce') Settings::set('scan', array_replace(Settings::get('scan', []), ['feedback_since' => SecScan::preciseNow(), 'feedback_tripped' => null]));
                Audit::log('scan.mode', null, ['mode' => $ai['mode']]);
                flash("Scan mode: {$ai['mode']}.");
                break;
            case 'breaker_reset':
                Settings::set('scan', array_replace(Settings::get('scan', []), ['breaker_tripped' => false]));
                Audit::log('scan.breaker_reset');
                flash('Circuit breaker reset; the scan blocks again.');
                break;
            case 'unblock':
                $c = IP::normCidr((string)post('ip')) ?? throw new InvalidArgumentException('Not an address.');
                Blocks::remove($c, trim((string)post('reason')), post('trust') === '1');
                flash("$c unblocked" . (post('trust') === '1' ? ' and trusted.' : '.'));
                break;
            case 'unblock_all':
                $n = DB::val("SELECT count(*) FROM blocks WHERE source <> 'manual'");
                foreach (DB::all("SELECT ip::text AS ip FROM blocks WHERE source <> 'manual'") as $b) Blocks::remove($b['ip'], 'remove all', false);
                flash("$n automatic blocks removed.");
                break;
            case 'finding':
                flash(Behaviour::act((int)post('id'), (string)post('do'), trim((string)post('note'))));
                break;
            case 'trap_state':
                Traps::setState((int)post('id'), (string)post('state'));
                flash('Trap updated.');
                break;
            case 'trap_pin':
                flash(Traps::pin((int)post('id')) ? 'Pinned: always active, counts towards the ' . Traps::MAX_ACTIVE . '.' : 'Unpinned: the ranking decides whether it stays active.');
                break;
            case 'trap_delete':
                DB::q('DELETE FROM traps WHERE id = ?', [(int)post('id')]);
                State::publish('traps');
                Audit::log('trap.delete', 'trap:' . (int)post('id'));
                flash('Trap deleted.');
                break;
            case 'trap_add':
                $host = trim((string)post('host')) ?: '*';
                if ($host !== '*' && !Validate::host($host)) throw new InvalidArgumentException('Host: a host name or *.');
                $id = Traps::add($host === '*' ? '*' : Validate::host($host), post('kind') === 'prefix' ? 'prefix' : 'exact', (string)post('path'), 'shadow', Audit::actor(), trim((string)post('note')));
                if (!$id) throw new InvalidArgumentException('Not an allowed trap path (it must start with /, a prefix needs at least ' . Traps::MIN_PREFIX . ' characters, and / or /.pspm/ are never traps).');
                State::publish('traps');
                Audit::log('trap.add', "trap:$id");
                flash('Trap added in shadow mode: it is matched and logged, but blocks only once you activate it.');
                break;
            case 'trust_add':
                $c = IP::normCidr((string)post('ip')) ?? throw new InvalidArgumentException('Not an address or network.');
                DB::q("INSERT INTO trusted_ips (ip, kind, source, note) VALUES (?::cidr, 'trusted', 'admin', ?) ON CONFLICT (ip) DO UPDATE SET kind = 'trusted', source = 'admin', note = excluded.note, expires_at = NULL",
                    [$c, mb_substr(trim((string)post('note')), 0, 200)]);
                Audit::log('trust.add', "ip:$c");
                State::publish('trusted');
                flash("$c is trusted: never blocked automatically, every port open in the firewall.");
                break;
            case 'trust_remove':
                DB::q('DELETE FROM trusted_ips WHERE ip = ?::cidr', [(string)post('ip')]);
                Audit::log('trust.remove', 'ip:' . post('ip'));
                State::publish('trusted');
                flash('Removed.');
                break;
            case 'blocklist_save':
                [$b, $errors] = Blocklists::validate(['name' => post('name'), 'url' => post('url'), 'format' => post('format'), 'field' => post('field'),
                    'refresh_hours' => post('refresh_hours'), 'mode' => post('mode'), 'enabled' => isset($_POST['enabled'])]);
                if ($errors) throw new InvalidArgumentException(implode(' ', $errors));
                $auth = trim((string)post('auth_header'));
                if ($auth !== '' && !preg_match('/^[A-Za-z0-9-]+: [\x20-\x7e]+$/', $auth)) throw new InvalidArgumentException('Header: "Name: value".');
                Blocklists::save(Validate::uuid(post('id')), $b, $auth === '' ? (isset($_POST['clear_auth']) ? '' : null) : $auth);
                flash('Blocklist saved. It is fetched within 15 minutes (or now with "Fetch now").');
                break;
            case 'blocklist_fetch':
                $r = Blocklists::run((string)post('id'));
                flash('Fetched: ' . implode('; ', array_map(fn($k, $v) => "$k: " . ($v['message'] ?? ''), array_keys($r), $r)));
                break;
            case 'blocklist_accept':
                Blocklists::acceptHeld((string)post('id'));
                flash('The new list replaces the old one.');
                break;
            case 'blocklist_delete':
                Blocklists::delete((string)post('id'));
                flash('Blocklist deleted.');
                break;
        }
        redirect($back);
    } catch (InvalidArgumentException $e) {
        $errors = [$e->getMessage()];
    }
}
$ai = AI::settings();
$scan = Settings::get('scan', []);
page_start('Security', '/security');
echo '<h1 class="h4 mb-3">Security</h1>' . errors_box($errors) . '<ul class="nav nav-tabs mb-3">';
foreach ($tabs as $k => $l) echo '<li class="nav-item"><a class="nav-link' . ($k === $tab ? ' active' : '') . '" href="/security?tab=' . h($k) . '">' . h($l) . '</a></li>';
echo '</ul>';
$canOp = Auth::can('operator');
$canAdmin = Auth::can('admin');

if ($tab === 'overview'):
    $last = DB::one('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1');
    $fw = Status::read('firewall');
    $blocks = DB::all('SELECT * FROM blocks WHERE expires_at > now() ORDER BY created_at DESC LIMIT 300');
    $bySource = [];
    foreach ($blocks as $b) $bySource[$b['source']] = ($bySource[$b['source']] ?? 0) + 1;
    ?>
    <div class="row g-3">
      <div class="col-lg-4"><div class="card"><div class="card-body small">
        <h2 class="h6">Scan</h2>
        <div>Mode: <strong><?= h($ai['mode']) ?></strong> · AI: <?= AI::configured() ? h($ai['model']) : 'off (no model or key; set it in Settings)' ?></div>
        <?php $fb = Settings::get('scan', [])['feedback_tripped'] ?? null; if ($fb && $ai['mode'] === 'dry-run'): ?>
          <div class="text-warning-emphasis">Switched to dry-run by itself at <?= h(fmt_time($fb['at'])) ?>: admins removed <?= h($fb['removed']) ?> of <?= h($fb['blocks']) ?> AI blocks
            within 7 days. Check them (AI log), then set the mode back to enforce.</div><?php endif; ?>
        <div>Last run: <?= $last ? h(ago($last['started_at'])) . ' — ' . h($last['stats']) : 'never' ?></div>
        <div>AI calls in 24 h: <?= AI::callsToday() ?> / <?= h($ai['daily_cap']) ?></div>
        <?php if ($scan['breaker_tripped'] ?? false): ?><div class="text-danger mt-1">Circuit breaker tripped <?= h(ago($scan['breaker_at'] ?? null)) ?>: the scan only reports what it would block.</div>
          <?= $canAdmin ? post_button('/security', 'Reset the breaker', ['action' => 'breaker_reset'], 'btn-outline-danger btn-sm mt-1') : '' ?><?php endif; ?>
        <?php if ($canOp): ?><div class="mt-2"><?= post_button('/security', 'Run now', ['action' => 'run_now']) ?></div><?php endif; ?>
        <?php if ($canAdmin): ?>
        <form method="post" class="d-flex gap-1 mt-2"><?= csrf_field() ?><input type="hidden" name="action" value="scan_mode">
          <select class="form-select form-select-sm" name="mode"><?php foreach (['enforce' => 'enforce', 'dry-run' => 'dry-run (report only)', 'collect' => 'collect (no AI calls)'] as $k => $l): ?><option value="<?= $k ?>" <?= $ai['mode'] === $k ? 'selected' : '' ?>><?= h($l) ?></option><?php endforeach; ?></select>
          <button class="btn btn-sm btn-outline-secondary">Set</button></form><?php endif; ?>
      </div></div></div>
      <div class="col-lg-8"><div class="card"><div class="card-body small">
        <h2 class="h6">Blocks <span class="text-muted"><?= count($blocks) ?> active in nginx<?= $fw ? ', ' . (int)(($fw['sets']['pspm-block4'] ?? 0) + ($fw['sets']['pspm-block6'] ?? 0)) . ' in the firewall' : '' ?></span></h2>
        <div><?php foreach ($bySource as $s => $n) echo badge('grey', "$s: $n") . ' '; ?></div>
        <table class="table table-sm mt-2"><thead><tr><th>Address</th><th>Source</th><th>Reason</th><th>Until</th><th></th></tr></thead><tbody>
        <?php foreach (array_slice($blocks, 0, 100) as $b): ?>
          <tr><td><code><?= h($b['ip']) ?></code></td><td><?= h($b['source']) ?></td><td><?= h($b['reason']) ?></td><td><?= h(fmt_time($b['expires_at'])) ?></td>
            <td class="text-nowrap"><?php if ($canOp): ?><form method="post" class="d-inline"><?= csrf_field() ?><input type="hidden" name="action" value="unblock"><input type="hidden" name="ip" value="<?= h($b['ip']) ?>">
              <input class="form-control form-control-sm d-inline w-auto" name="reason" placeholder="reason"> <button class="btn btn-link btn-sm p-0">Remove</button>
              <button class="btn btn-link btn-sm p-0" name="trust" value="1">Remove and trust</button></form><?php endif; ?></td></tr>
        <?php endforeach; ?></tbody></table>
        <?= $canOp && $blocks ? post_button('/security', 'Remove all automatic blocks', ['action' => 'unblock_all'], 'btn-outline-danger btn-sm', 'Remove every automatic block?') : '' ?>
      </div></div></div>
    </div>
<?php elseif ($tab === 'behaviour'):
    $findings = DB::all("SELECT * FROM risk_findings ORDER BY (status = 'open') DESC, created_at DESC LIMIT 200"); ?>
    <p class="small text-muted">Behaviour over time per address, certificate, signed-in user and access link (plan §15.7). Findings about authorised actors are never blocked automatically.
      A risky untrusted address is blocked when nobody reacts within <?= h($ai['reaction_hours']) ?> hours.</p>
    <?php $lastS = Behaviour::lastSearch(); $nextS = Behaviour::nextSearch(); ?>
    <p class="small">Search for findings every <?= h(Behaviour::intervalHours()) ?> hours (<a href="/settings#blocking">Settings</a>):
      last <?= $lastS ? h(date('Y-m-d H:i', $lastS)) : 'never' ?>, next <?= $nextS ? h(date('Y-m-d H:i', max($nextS, time()))) : 'with the next scan round' ?>.
      <em>Run now</em> on the overview searches at once. Reaction deadlines and reminders are checked every 5 minutes.</p>
    <table class="table table-sm small align-middle"><thead><tr><th>#</th><th>Actor</th><th>Pattern</th><th>Risk</th><th>Status</th><th>Evidence</th><th></th></tr></thead><tbody>
    <?php foreach ($findings as $f): $ev = json_dec($f['evidence']) ?? []; $assess = json_dec($f['ai'] ?? 'null'); ?>
      <tr class="<?= $f['status'] === 'open' ? '' : 'text-muted' ?>"><td><?= h($f['id']) ?></td>
        <td><?= h(Behaviour::describe($f['actor_type'], $f['actor'])) ?> <?= $f['authorised'] ? badge('red', 'authorised') : '' ?></td>
        <td><?= h(Behaviour::PATTERNS[$f['pattern']] ?? $f['pattern']) ?> <?= badge($f['class'] === 'attack' ? 'red' : 'amber', $f['class']) ?></td>
        <td><?= h($f['risk']) ?></td>
        <td><?= h($f['status']) ?><?php if ($f['status'] === 'open' && $f['deadline']): ?><div class="text-danger">blocks <?= h(ago($f['deadline'])) ?></div><?php endif; ?></td>
        <td><code class="small"><?= h(json_enc($ev)) ?></code><?php if ($assess): ?><div><?= h($assess['reason'] ?? '') ?> <span class="text-muted"><?= h($assess['suggested_action'] ?? '') ?></span></div><?php endif; ?>
          <?php if (!$assess): ?><div class="text-muted">not assessed by AI</div><?php endif; ?></td>
        <td class="text-nowrap"><?php if ($canOp && $f['status'] === 'open'): ?>
          <?php foreach (array_filter(['block' => $f['actor_type'] === 'ip' ? 'Block' : '', 'revoke_cert' => $f['actor_type'] === 'cert' ? 'Revoke certificate' : '',
              'revoke_link' => $f['actor_type'] === 'link' ? 'Revoke link' : '', 'end_clearance' => $f['actor_type'] === 'ip' && $f['authorised'] ? 'End clearance' : '',
              'expected' => 'Mark as expected', 'close' => 'Close']) as $do => $l): ?>
            <?= post_button('/security?tab=behaviour', $l, ['action' => 'finding', 'id' => $f['id'], 'do' => $do], 'btn-outline-secondary btn-sm') ?>
          <?php endforeach; endif; ?></td></tr>
    <?php endforeach; ?>
    <?php if (!$findings): ?><tr><td colspan="7" class="text-muted">No findings.</td></tr><?php endif; ?></tbody></table>
<?php elseif ($tab === 'traps'):
    $traps = DB::all("SELECT * FROM traps ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'shadow' THEN 1 WHEN 'proposed' THEN 2 ELSE 3 END, rank NULLS LAST, score DESC, id LIMIT 600");
    $nActive = (int)DB::val("SELECT count(*) FROM traps WHERE state = 'active'");
    $lastRank = SecScan::state('last_trap_ranking');
    // why a trap is where it is (docs/security-ai-improvements.md §1)
    $why = function (array $t) use ($nActive): string {
        if ($t['state'] === 'active') return $t['pinned'] ? 'pinned: always active' : 'rank ' . $t['rank'] . ' of ' . Traps::MAX_ACTIVE;
        if ($t['state'] === 'shadow' && $t['eligible_at'] !== null) return 'waiting, rank ' . $t['rank'] . ': the ' . Traps::MAX_ACTIVE . ' places are taken by better ones';
        if ($t['state'] === 'shadow') return 'observed; eligible ' . ago(gmdate('c', strtotime((string)$t['shadow_since']) + Traps::TRACKS[$t['track']]['shadow_secs']));
        if ($t['state'] === 'proposed') return 'needs ' . Traps::TRACKS[$t['track']]['votes'] . ' votes and ' . Traps::TRACKS[$t['track']]['attackers'] . ' attackers';
        if ($t['state'] === 'rejected') return 'a backend serves this path';
        return '';
    }; ?>
    <p class="small text-muted">Paths only attackers ask for. The first request to an <em>active</em> trap from an untrusted address blocks it. <em>Shadow</em> traps are matched and logged only.
      A path that a backend serves is rejected and can never be activated.</p>
    <p class="small">Only the <?= Traps::MAX_ACTIVE ?> best are active (<?= $nActive ?> now). Score: distinct attackers in 30 days, ×1.5 on the fast track, ×1.2 for all hosts (*),
      × recency (1 within 7 days, 0.5 within 30, 0.2 older). Pinned traps are always active. A waiting trap replaces an active one when its score is 20 % higher;
      ranked once a day and after each mining run<?= $lastRank ? ' (last: ' . h(fmt_time($lastRank['at'])) . ')' : '' ?>.</p>
    <table class="table table-sm small align-middle"><thead><tr><th>Host</th><th>Path</th><th>State</th><th>Score</th><th>Track</th><th>Votes</th><th>Attackers</th><th>Hits</th><th>Note</th><th></th></tr></thead><tbody>
    <?php foreach ($traps as $t): ?>
      <tr><td><?= h($t['host']) ?></td><td><code><?= h($t['path']) ?></code><?= $t['kind'] === 'prefix' ? '…' : '' ?></td>
        <td><?= badge(['active' => 'red', 'shadow' => 'amber', 'proposed' => 'info', 'rejected' => 'grey'][$t['state']] ?? 'grey', $t['state']) ?> <?= $t['pinned'] ? badge('info', 'pinned') : '' ?>
          <div class="text-muted"><?= h($why($t)) ?></div></td>
        <td><?= h(round((float)$t['score'], 1)) ?></td>
        <td><?= h($t['track']) ?></td><td><?= h($t['votes']) ?></td><td><?= h($t['attackers']) ?></td><td><?= h($t['hits']) ?></td><td><?= h($t['note']) ?></td>
        <td class="text-nowrap"><?php if ($canOp): foreach (['active' => 'Activate', 'shadow' => 'Shadow', 'disabled' => 'Disable'] as $s => $l) if ($t['state'] !== $s && $t['state'] !== 'rejected') echo post_button('/security?tab=traps', $l, ['action' => 'trap_state', 'id' => $t['id'], 'state' => $s]) . ' ';
            echo post_button('/security?tab=traps', $t['pinned'] ? 'Unpin' : 'Pin', ['action' => 'trap_pin', 'id' => $t['id']]) . ' ' . post_button('/security?tab=traps', 'Delete', ['action' => 'trap_delete', 'id' => $t['id']], 'btn-outline-danger btn-sm'); endif; ?></td></tr>
    <?php endforeach; ?>
    <?php if (!$traps): ?><tr><td colspan="10" class="text-muted">No traps yet. With an AI model set, the scan proposes them from refused requests; you can also add them here.</td></tr><?php endif; ?></tbody></table>
    <?php if ($canOp): ?>
    <form method="post" class="row g-2 col-xl-9"><?= csrf_field() ?><input type="hidden" name="action" value="trap_add">
      <div class="col-md-3"><input class="form-control form-control-sm" name="host" placeholder="host name or *" value="*"></div>
      <div class="col-md-2"><select class="form-select form-select-sm" name="kind"><option value="exact">exact</option><option value="prefix">prefix</option></select></div>
      <div class="col-md-3"><input class="form-control form-control-sm" name="path" placeholder="/.env"></div>
      <div class="col-md-2"><input class="form-control form-control-sm" name="note" placeholder="note"></div>
      <div class="col-md-2"><button class="btn btn-sm btn-primary w-100">Add (shadow)</button></div></form>
    <?php endif; ?>
<?php elseif ($tab === 'blocklists'):
    $lists = Blocklists::all();
    $fw = Status::read('firewall');
    $edit = Validate::uuid(get('id')) ? DB::one('SELECT * FROM blocklists WHERE id = ?', [get('id')]) : null; ?>
    <p class="small text-muted">Lists of addresses that the firewall drops on every port (or only counts, in observe mode). Private, reserved and allowed addresses are never affected.
      If a download fails, the last good list stays for up to 7 days.</p>
    <table class="table table-sm small align-middle"><thead><tr><th>Name</th><th>Mode</th><th>Status</th><th>Entries</th><th>Overlap with allowed</th><th>Last fetch</th><th></th></tr></thead><tbody>
    <?php foreach ($lists as $b): $st = json_dec($b['last_status']) ?? []; ?>
      <tr><td><?= h($b['name']) ?><div class="text-muted text-truncate"><?= h($b['url']) ?></div></td>
        <td><?= h($b['mode']) ?><?= $b['enabled'] ? '' : ' ' . badge('grey', 'disabled') ?></td>
        <td><?= badge($st['level'] ?? 'grey', $st['level'] ?? 'not fetched') ?> <?= h($st['message'] ?? '') ?></td>
        <td><?= h($st['entries'] ?? '—') ?></td><td><?= h(Blocklists::overlap($b['id'])) ?></td><td><?= h(ago($b['last_fetch_at'])) ?></td>
        <td class="text-nowrap"><?php if ($canOp): ?><?= post_button('/security?tab=blocklists', 'Fetch now', ['action' => 'blocklist_fetch', 'id' => $b['id']]) ?>
          <?= $b['held'] ? post_button('/security?tab=blocklists', 'Accept anyway', ['action' => 'blocklist_accept', 'id' => $b['id']], 'btn-outline-danger btn-sm', 'Replace the current list with the suspicious new one?') : '' ?><?php endif; ?>
          <?php if ($canAdmin): ?><a class="btn btn-sm btn-outline-secondary" href="/security?tab=blocklists&amp;id=<?= h($b['id']) ?>">Edit</a>
          <?= post_button('/security?tab=blocklists', 'Delete', ['action' => 'blocklist_delete', 'id' => $b['id']], 'btn-outline-danger btn-sm', "Delete {$b['name']}?") ?><?php endif; ?></td></tr>
    <?php endforeach; ?>
    <?php if (!$lists): ?><tr><td colspan="7" class="text-muted">No blocklists.</td></tr><?php endif; ?></tbody></table>
    <?php if ($fw): ?><p class="small">Firewall: <?= (int)(($fw['sets']['pspm-feed4'] ?? 0) + ($fw['sets']['pspm-feed6'] ?? 0)) ?> entries dropping, <?= (int)(($fw['sets']['pspm-watch4'] ?? 0) + ($fw['sets']['pspm-watch6'] ?? 0)) ?> observed.</p><?php endif; ?>
    <?php if ($canAdmin): $e = $edit ?? ['id' => '', 'name' => '', 'url' => '', 'format' => 'plain', 'field' => 'cidr', 'refresh_hours' => 24, 'mode' => 'observe', 'enabled' => true]; ?>
    <h2 class="h6"><?= $edit ? 'Edit ' . h($edit['name']) : 'Add a blocklist' ?></h2>
    <form method="post" class="card card-body col-xl-8"><?= csrf_field() ?><input type="hidden" name="action" value="blocklist_save"><input type="hidden" name="id" value="<?= h($e['id']) ?>">
      <div class="row g-2">
        <div class="col-md-4"><?= f_text('name', 'Name', $e['name']) ?></div>
        <div class="col-md-8"><?= f_text('url', 'URL (https)', $e['url']) ?></div>
        <div class="col-md-3"><?= f_select('format', 'Format', $e['format'], ['plain' => 'plain (one address/network per line)', 'jsonl' => 'JSON lines']) ?></div>
        <div class="col-md-3"><?= f_text('field', 'JSON field', $e['field']) ?></div>
        <div class="col-md-3"><?= f_text('refresh_hours', 'Refresh (hours)', $e['refresh_hours'], [], '', 'number') ?></div>
        <div class="col-md-3"><?= f_select('mode', 'Mode', $e['mode'], ['observe' => 'observe (count only)', 'block' => 'block']) ?></div>
        <div class="col-md-8"><?= f_text('auth_header', 'Auth header (optional, stored encrypted)', '', [], 'e.g. "Authorization: Bearer …"; empty keeps the current one') ?></div>
        <div class="col-md-4 pt-4"><?= f_check('enabled', 'Enabled', (bool)$e['enabled']) ?><?= $edit ? f_check('clear_auth', 'Remove the auth header', false) : '' ?></div>
      </div>
      <div><button class="btn btn-primary btn-sm">Save</button></div></form>
    <?php endif; ?>
<?php elseif ($tab === 'trusted'):
    $rows = DB::all("SELECT * FROM trusted_ips ORDER BY kind DESC, last_seen DESC LIMIT 500"); ?>
    <p class="small text-muted"><strong>Trusted</strong> (by an admin): never blocked automatically, every port open in the firewall.
      <strong>Authorised</strong> (certificate, access link, sign-in): never blocked automatically, web ports only; expires after <?= (int)(Settings::get('trust', [])['authorised_days'] ?? 30) ?> days without a new authorisation.</p>
    <table class="table table-sm small"><thead><tr><th>Address</th><th>Kind</th><th>Source</th><th>Last seen</th><th>Note</th><th></th></tr></thead><tbody>
    <?php foreach ($rows as $r): ?><tr><td><code><?= h($r['ip']) ?></code></td><td><?= h($r['kind']) ?></td><td><?= h(preg_replace('/^(cert:[0-9a-f]{8})[0-9a-f]+$/', '$1…', $r['source'])) ?></td>
      <td><?= h(ago($r['last_seen'])) ?></td><td><?= h($r['note']) ?></td><td><?= $canOp ? post_button('/security?tab=trusted', 'Remove', ['action' => 'trust_remove', 'ip' => $r['ip']], 'btn-link btn-sm p-0') : '' ?></td></tr><?php endforeach; ?>
    </tbody></table>
    <?php if ($canOp): ?><form method="post" class="row g-2 col-xl-6"><?= csrf_field() ?><input type="hidden" name="action" value="trust_add">
      <div class="col-5"><input class="form-control form-control-sm" name="ip" placeholder="address or network"></div>
      <div class="col-4"><input class="form-control form-control-sm" name="note" placeholder="e.g. monitoring"></div>
      <div class="col-3"><button class="btn btn-sm btn-primary w-100">Trust</button></div></form><?php endif; ?>
<?php elseif ($tab === 'ailog'):
    // every API call of every model: what was sent, what came back, what PSPM did with it
    $n = in_array((int)get('n'), [10, 50, 200], true) ? (int)get('n') : 10;
    $calls = DB::all("SELECT * FROM ai_calls ORDER BY id DESC LIMIT $n");
    $fig = [];
    foreach (DB::all("SELECT role, count(*) AS calls, count(*) FILTER (WHERE error IS NOT NULL) AS errors, coalesce(sum(tokens_in), 0) AS tin,
                             coalesce(sum(tokens_out), 0) AS tout, sum(cost) AS cost, round(avg(duration_ms)) AS ms
                      FROM ai_calls WHERE at > now() - interval '24 hours' GROUP BY role") as $f) $fig[$f['role']] = $f;
    $removed = (int)DB::val("SELECT count(*) FROM block_history WHERE source = 'ai' AND removed_by IS NOT NULL AND removed_by NOT LIKE 'system%' AND created_at > now() - interval '7 days'");
    $aiBlocks = (int)DB::val("SELECT count(*) FROM block_history WHERE source = 'ai' AND created_at > now() - interval '7 days'");
    $byCall = [];
    if ($calls) {
        $ids = implode(',', array_map('intval', array_column($calls, 'id')));
        foreach (DB::all("SELECT * FROM ai_verdicts WHERE call_id IN ($ids) OR verify_call_id IN ($ids) ORDER BY id") as $v) {
            if ($v['call_id'] !== null) $byCall[$v['call_id']][] = $v;
            if ($v['verify_call_id'] !== null) $byCall[$v['verify_call_id']][] = $v;   // the verifier's call shows the same lines
        }
    }
    $pretty = fn($x) => h(json_encode($x, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)); ?>
    <p class="small">Every call to an AI model, with the data as it was sent (pseudonymised), the answer, and what PSPM did with it.
      Full requests and answers are kept for 30 days. Pseudonyms are resolved here only: the mapping never leaves the box.</p>
    <?php $injections = (int)DB::val("SELECT count(*) FROM ai_check_cache WHERE label = 'injection' AND at > now() - interval '24 hours'");
          $unchecked = (int)DB::val("SELECT count(*) FROM ai_calls WHERE role <> 'check' AND at > now() - interval '24 hours' AND request::text LIKE ?", ['%' . AI::CHECK_UNAVAILABLE . '%']); ?>
    <table class="table table-sm small mb-3"><thead><tr><th>Model (24 h)</th><th>Calls / cap</th><th>Errors</th><th>Tokens in / out</th><th>Cost</th><th>Average duration</th></tr></thead><tbody>
    <?php foreach (AI::ROLES as $role => $label): $f = $fig[$role] ?? null; $mm = AI::model($role); ?>
      <tr><td><?= h($label) ?> <span class="text-muted"><?= h($mm['model'] ?: 'not set') ?></span>
        <?= $role === 'check' ? '<div>injection attempts found: ' . ($injections ? badge('amber', (string)$injections) : '0') . '</div>'
            . '<div>prompts sent without the check: ' . ($unchecked ? badge('amber', (string)$unchecked) . ' (they carried only paths and product names)' : '0') . '</div>' : '' ?>
        <?php if ($pz = AI::paused($role)): ?><div><?= badge('amber', 'paused') ?> until <?= h(fmt_time($pz['until'], 'H:i')) ?> after HTTP <?= h($pz['status']) ?> (<?= h($pz['minutes']) ?> min)</div><?php endif; ?></td>
        <td><?= h($f['calls'] ?? 0) ?> / <?= h($mm['daily_cap']) ?></td><td><?= ($f['errors'] ?? 0) ? badge('red', (string)$f['errors']) : '0' ?></td>
        <td><?= h(number_format((int)($f['tin'] ?? 0))) ?> / <?= h(number_format((int)($f['tout'] ?? 0))) ?></td>
        <td><?= isset($f['cost']) && $f['cost'] !== null ? '$' . h(number_format((float)$f['cost'], 4)) : '—' ?></td><td><?= isset($f['ms']) ? h($f['ms']) . ' ms' : '—' ?></td></tr>
    <?php endforeach; ?>
    </tbody></table>
    <?php $agree = DB::one("SELECT count(*) FILTER (WHERE verify_verdict IS NOT NULL) AS asked,
                                   count(*) FILTER (WHERE verify_verdict IN ('block', 'attack')) AS agreed
                            FROM ai_verdicts WHERE kind IN ('verdict', 'behaviour') AND created_at > now() - interval '7 days'"); ?>
    <p class="small">AI blocks in 7 days: <?= h($aiBlocks) ?>, removed by an admin since: <?= $removed ? badge($removed * 5 > max(1, $aiBlocks) ? 'amber' : 'grey', (string)$removed) : '0' ?>.
      <?php if ((int)$agree['asked']): ?>The verification model agreed on <?= h($agree['agreed']) ?> of <?= h($agree['asked']) ?> blocks in 7 days.<?php endif; ?></p>
    <div class="small mb-2">Show the last <?php foreach ([10, 50, 200] as $k): ?><a class="<?= $k === $n ? 'fw-bold' : '' ?>" href="/security?tab=ailog&amp;n=<?= $k ?>"><?= $k ?></a> <?php endforeach; ?>calls</div>
    <table class="table table-sm small align-middle"><thead><tr><th>When</th><th>Purpose</th><th>Model</th><th>Result</th><th>Duration</th><th>Tokens</th><th>Cost</th></tr></thead><tbody>
    <?php foreach ($calls as $c):
        $res = json_dec($c['result'] ?? 'null'); $ps = json_dec($c['pseudonyms']) ?: []; $vs = $byCall[$c['id']] ?? []; ?>
      <tr>
        <td class="text-nowrap"><?= h(fmt_time($c['at'], 'Y-m-d H:i:s')) ?></td>
        <td><?= h(AI::PURPOSES[$c['purpose']] ?? $c['purpose']) ?><div class="text-muted"><?= h(AI::ROLES[$c['role']] ?? $c['role']) ?></div></td>
        <td><?= h($c['model']) ?><?= $c['model_answer'] && $c['model_answer'] !== $c['model'] ? '<div class="text-muted">answered: ' . h($c['model_answer']) . '</div>' : '' ?></td>
        <td>
          <?php if ($c['error']): ?><?= badge('red', 'error') ?> <span class="text-break"><?= h(mb_substr($c['error'], 0, 240)) ?></span>
          <?php elseif ($vs): ?><ul class="list-unstyled mb-0"><?php foreach ($vs as $v): ?>
            <li><code><?= h($v['subject']) ?></code>: <?= $v['verdict'] !== null ? h($v['verdict']) . ($v['confidence'] !== null ? ' ' . h(round((float)$v['confidence'], 2)) : '') : '<span class="text-muted">no verdict</span>' ?>
              <?= $v['verify_verdict'] !== null ? '· verifier: ' . h($v['verify_verdict']) . ($v['verify_confidence'] !== null ? ' ' . h(round((float)$v['verify_confidence'], 2)) : '') . ' ' : '' ?>
              <?= $v['outcome'] ? '→ <strong>' . h($v['outcome']) . '</strong>' : '' ?><?= !empty(json_dec($v['evidence'])['injection_attempted']) ? ' ' . badge('amber', 'injection removed') : '' ?>
              <?= $v['reason'] ? ' <span class="text-muted">' . h(mb_substr($v['reason'], 0, 120)) . '</span>' : '' ?></li>
          <?php endforeach; ?></ul>
          <?php elseif ($c['purpose'] === 'check' && is_array($res) && isset($res[0]['label'])): $bad = array_filter($res, fn($x) => ($x['label'] ?? '') === 'injection'); ?>
            <?= count($res) - count($bad) ?> safe<?= $bad ? ', ' . badge('amber', count($bad) . ' injection') : '' ?>
            <?php if ($bad): ?><ul class="list-unstyled mb-0"><?php foreach ($bad as $x): ?><li><code><?= h($x['text'] ?? '') ?></code> <?= h(round((float)($x['score'] ?? 1), 2)) ?><?= !empty($x['invalid']) ? ' (answer not of the fixed type)' : '' ?></li><?php endforeach; ?></ul><?php endif; ?>
          <?php elseif ($c['purpose'] === 'test'): ?><?= ($res['ok'] ?? null) === true ? badge('green', 'ok') : badge('amber', 'unexpected answer') ?>
          <?php else: ?><?= badge('green', 'answered') ?><?php endif; ?>
          <?= !empty($res['_dropped']) ? '<div>' . badge('amber', $res['_dropped'] . ' dropped') . ' not of the expected type</div>' : '' ?>
          <details class="mt-1"><summary class="text-muted">show request and answer</summary>
            <div class="mt-1"><strong>Sent</strong> (HTTP <?= h($c['status']) ?>)<pre class="small mb-1"><?= $pretty(json_dec($c['request'])) ?></pre>
            <strong>Answer</strong><pre class="small mb-1"><?= h((string)$c['response']) ?></pre>
            <?php if ($ps): ?><strong>Pseudonyms</strong> (this box only)<pre class="small mb-0"><?php foreach ($ps as $k => $real) echo h("$k = $real") . "\n"; ?></pre><?php endif; ?></div>
          </details></td>
        <td class="text-nowrap"><?= h($c['duration_ms']) ?> ms</td>
        <td class="text-nowrap"><?= $c['tokens_in'] !== null ? h($c['tokens_in']) . ' / ' . h($c['tokens_out']) : '—' ?></td>
        <td><?= $c['cost'] !== null ? '$' . h(number_format((float)$c['cost'], 5)) : '—' ?></td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$calls): ?><tr><td colspan="7" class="text-muted">No AI calls yet<?= AI::configured() ? '.' : ': set a main model under Settings → Models.' ?></td></tr><?php endif; ?>
    </tbody></table>
<?php else:
    $rows = DB::all('SELECT * FROM ai_verdicts ORDER BY id DESC LIMIT 200'); ?>
    <table class="table table-sm small"><thead><tr><th>When</th><th>Kind</th><th>Subject</th><th>Verdict</th><th>Confidence</th><th>Reason</th><th>Outcome</th><th>Evidence sent</th></tr></thead><tbody>
    <?php foreach ($rows as $r): ?><tr><td class="text-nowrap"><?= h(fmt_time($r['created_at'])) ?></td><td><?= h($r['kind']) ?></td><td><code><?= h($r['subject']) ?></code></td>
      <td><?= h($r['verdict']) ?></td><td><?= $r['confidence'] !== null ? h(round((float)$r['confidence'], 2)) : '' ?></td><td><?= h($r['reason']) ?></td><td><?= h($r['outcome']) ?></td>
      <td><details><summary>show</summary><pre class="small mb-0"><?= h(json_encode(json_dec($r['evidence']), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre></details></td></tr><?php endforeach; ?>
    <?php if (!$rows): ?><tr><td colspan="8" class="text-muted">No AI verdicts yet.</td></tr><?php endif; ?></tbody></table>
<?php endif;
page_end();
