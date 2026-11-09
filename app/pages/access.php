<?php
// Access links (one site each, or the admin UI), cleared addresses, login bans, blocks (plan §11).
declare(strict_types=1);

$u = Auth::require('viewer');
$created = null;
$createdFor = 'site';
// The admin UI accepts links once "cleared" is in its admin access and an admin host name is set
// (links are used on that name; by IP the UI answers only to private addresses).
$g = Settings::global();
$adminHost = Access::liveAdminHost();
$adminLinks = $adminHost !== '' && in_array('cleared', $g['admin_access'], true);
if (is_post()) {
    Auth::require('operator');
    $a = post('action');
    if ($a === 'create_link') {
        $forAdmin = post('site') === 'admin';
        $site = $forAdmin ? null : Model::site((string)post('site'));
        $grant = post('grant') === 'permanent' ? null : Validate::int(post('grant'), 3600, 90 * 86400);
        $until = trim((string)post('valid_until')) !== '' ? (strtotime((string)post('valid_until') . ' 23:59:59') ?: null) : null;
        $max = trim((string)post('max_uses')) !== '' ? Validate::int(post('max_uses'), 1, 100000) : null;
        $after = trim((string)post('after', '/')) ?: '/';
        if ($forAdmin && !Auth::can('admin')) flash('Only admins create links to the admin UI.', 'danger');
        elseif ($forAdmin && !$adminLinks) flash('The admin UI does not accept access links: set an admin host name and tick "Access links" under Settings → Admin access, then apply.', 'danger');
        elseif (!$forAdmin && (!$site || !in_array('cleared', $site['access']['conditions'], true))) flash('Choose a site whose policy accepts cleared addresses.', 'danger');
        elseif (post('grant') !== 'permanent' && $grant === null) flash('Choose how long a visit clears the address.', 'danger');
        elseif ($after !== '/' && !Validate::path($after)) flash('The path after the grant must start with / (no spaces, quotes, $).', 'danger');
        elseif (trim((string)post('label')) === '') flash('Give the link a label: who it is for.', 'danger');
        else {
            [$lid, $token] = Access::createLink($site['id'] ?? null, mb_substr(trim((string)post('label')), 0, 100), $grant, $until ? gmdate('c', $until) : null, $max, $after);
            $created = 'https://' . ($forAdmin ? $adminHost : $site['hosts'][0]) . '/.pspm/access/' . $token;
            $createdFor = $forAdmin ? 'admin' : 'site';
        }
    } elseif ($a === 'revoke_link' && ($id = Validate::uuid(post('id')))) {
        Access::revokeLink($id);
        flash('Link revoked; the addresses it cleared are no longer cleared.');
    } elseif ($a === 'remove_cleared' && ($sid = (post('site') === 'admin' ? 'admin' : Validate::uuid(post('site')))) && ($ip = IP::normCidr((string)post('ip')))) {
        DB::q('DELETE FROM cleared_ips WHERE scope = ? AND ip = ?::cidr', [$sid, $ip]);
        Audit::log('cleared.remove', "ip:$ip", ['site' => $sid]);
        State::publish('cleared');
        flash("$ip is no longer cleared for that site.");
    } elseif ($a === 'purge') {
        DB::q('DELETE FROM cleared_ips WHERE expires_at < now()');
        DB::q('DELETE FROM banned_ips WHERE expires_at < now()');
        DB::q('DELETE FROM blocks WHERE expires_at < now()');
        flash('Expired entries removed.');
    } elseif ($a === 'unban' && ($ip = IP::normCidr((string)post('ip')))) {
        Access::unban($ip);
        Audit::log('unban', "ip:$ip");
        State::publish('banned');
        flash("$ip may sign in again.");
    } elseif ($a === 'unblock' && ($ip = IP::normCidr((string)post('ip')))) {
        Access::unblock($ip);
        Audit::log('unblock', "ip:$ip");
        State::publish('blocked');
        flash("$ip unblocked.");
    } elseif ($a === 'block') {
        $ip = IP::normCidr((string)post('ip'));
        $days = Validate::int(post('days'), 1, 365);
        $len = $ip ? (int)explode('/', $ip)[1] : 0;
        if (!$ip || !$days) flash('An address or network, and a duration.', 'danger');
        elseif (IP::neverBlocked($ip)) flash('Private, loopback and link-local ranges are never blocked.', 'danger');
        elseif ((IP::family($ip) === 4 && $len < 16) || (IP::family($ip) === 6 && $len < 32)) flash('At most a /16 (IPv4) or /32 (IPv6).', 'danger');
        else {
            DB::q("INSERT INTO blocks (ip, source, reason, firewall, expires_at, created_by) VALUES (?::cidr, 'manual', ?, ?, now() + make_interval(days => ?), ?)
                   ON CONFLICT (ip) DO UPDATE SET reason = excluded.reason, firewall = excluded.firewall, expires_at = excluded.expires_at",
                [$ip, mb_substr(trim((string)post('reason')) ?: 'manual', 0, 200), !isset($_POST['nginx_only']), $days, Audit::actor()]);
            Audit::log('block', "ip:$ip", ['days' => $days]);
            State::publish('blocked');
            flash("$ip blocked for $days days.");
        }
    }
    if (!$created) redirect('/access');
}

$sites = Model::sites();
$linkSites = array_filter($sites, fn($s) => in_array('cleared', $s['access']['conditions'], true));
$adminLabel = 'PSPM admin UI';
$links = DB::all("SELECT l.*, coalesce(s.name, ?) AS site FROM access_links l LEFT JOIN sites s ON s.id = l.site_id
                  ORDER BY l.target, s.name, l.created_at DESC", [$adminLabel]);
$cleared = DB::all("SELECT c.*, coalesce(s.name, ?) AS site, l.label FROM cleared_ips c LEFT JOIN sites s ON s.id = c.site_id LEFT JOIN access_links l ON l.id = c.link_id
                    WHERE c.expires_at IS NULL OR c.expires_at > now() ORDER BY c.scope = 'admin' DESC, s.name, c.created_at DESC", [$adminLabel]);
$bans = DB::all('SELECT * FROM banned_ips WHERE expires_at > now() ORDER BY created_at DESC');
$blocks = DB::all('SELECT * FROM blocks WHERE expires_at > now() ORDER BY created_at DESC LIMIT 200');
$canEdit = Auth::can('operator');
page_start('Access', '/access');
?>
<h1 class="h4 mb-3">Access</h1>
<?php if ($created): ?>
  <div class="alert alert-success">The link, shown once — send it to the person it is for:
    <div class="input-group mt-2"><input class="form-control font-monospace" readonly value="<?= h($created) ?>" id="newlink"><button class="btn btn-outline-secondary" type="button" data-copy="#newlink">Copy</button></div>
    <div class="small mt-1"><?= $createdFor === 'admin'
        ? 'It opens the admin UI\'s sign-in page for the address it is used from; signing in still needs a PSPM account. It works only on the admin host name.'
        : 'It opens only this site, and only once the site is applied with <code>cleared</code> in its policy.' ?></div></div>
<?php endif; ?>
<div class="row g-4">
<div class="col-xl-7">
  <h2 class="h6">Access links</h2>
  <table class="table table-sm small align-middle"><thead><tr><th>Site</th><th>Label</th><th>Grant</th><th>Uses</th><th>Valid</th><th></th></tr></thead><tbody>
  <?php foreach ($links as $l): $dead = $l['revoked_at'] || ($l['valid_until'] && strtotime($l['valid_until']) < time()); ?>
    <tr class="<?= $dead ? 'text-muted' : '' ?>"><td><?= h($l['site']) ?></td><td><?= h($l['label']) ?></td>
      <td><?= $l['grant_secs'] === null ? 'permanent' : h(human_secs((int)$l['grant_secs'])) ?></td>
      <td><?= h($l['uses']) ?><?= $l['max_uses'] !== null ? ' / ' . h($l['max_uses']) : '' ?> <span class="text-muted"><?= $l['last_used_at'] ? h(ago($l['last_used_at'])) : '' ?></span></td>
      <td><?= $l['revoked_at'] ? 'revoked' : ($l['valid_until'] ? h(fmt_time($l['valid_until'], 'Y-m-d')) : 'until revoked') ?></td>
      <td><?= !$l['revoked_at'] && $canEdit ? post_button('/access', 'Revoke', ['action' => 'revoke_link', 'id' => $l['id']], 'btn-outline-danger btn-sm', 'Revoke this link and end its clearances?') : '' ?></td></tr>
  <?php endforeach; ?></tbody></table>
  <?php if ($canEdit): ?>
    <?php $canAdminLink = $adminLinks && Auth::can('admin'); ?>
    <?php if (!$adminLinks && Auth::can('admin')): ?><p class="small text-muted">Links to the admin UI: set an admin host name and tick <em>Access links</em> under Settings → Admin access, then apply.</p><?php endif; ?>
    <?php if (!$linkSites && !$canAdminLink): ?><p class="small text-muted">No site accepts cleared addresses yet. Add <em>Cleared</em> to a site's access policy first.</p>
    <?php else: ?>
    <form method="post" class="card card-body mb-3"><?= csrf_field() ?><input type="hidden" name="action" value="create_link">
      <div class="row g-2">
        <div class="col-md-4"><label class="form-label small">Opens</label><select class="form-select form-select-sm" name="site"><?php foreach ($linkSites as $s): ?><option value="<?= h($s['id']) ?>"><?= h($s['hosts'][0]) ?></option><?php endforeach; ?>
          <?php if ($canAdminLink): ?><option value="admin"><?= h($adminLabel . ' (' . $adminHost . ')') ?></option><?php endif; ?></select></div>
        <div class="col-md-4"><label class="form-label small">For (label)</label><input class="form-control form-control-sm" name="label" placeholder="Anna, laptop"></div>
        <div class="col-md-4"><label class="form-label small">A visit clears the address for</label><select class="form-select form-select-sm" name="grant">
          <?php foreach ([3600 => '1 hour', 28800 => '8 hours', 86400 => '1 day', 604800 => '7 days', 2592000 => '30 days', 7776000 => '90 days', 'permanent' => 'permanent'] as $k => $v): ?><option value="<?= h($k) ?>" <?= $k === 604800 ? 'selected' : '' ?>><?= h($v) ?></option><?php endforeach; ?></select></div>
        <div class="col-md-4"><label class="form-label small">Link valid until (optional)</label><input class="form-control form-control-sm" type="date" name="valid_until"></div>
        <div class="col-md-4"><label class="form-label small">Max. uses (optional)</label><input class="form-control form-control-sm" type="number" name="max_uses" min="1"></div>
        <div class="col-md-4"><label class="form-label small">Afterwards open path</label><input class="form-control form-control-sm" name="after" value="/"></div>
      </div>
      <div class="mt-2"><button class="btn btn-primary btn-sm">Create link</button></div>
    </form>
    <?php endif; ?>
  <?php endif; ?>

  <h2 class="h6">Cleared addresses</h2>
  <table class="table table-sm small"><thead><tr><th>Site</th><th>Address</th><th>Through</th><th>Until</th><th></th></tr></thead><tbody>
  <?php foreach ($cleared as $c): ?><tr><td><?= h($c['site']) ?></td><td><code><?= h($c['ip']) ?></code></td><td><?= h($c['label'] ?? 'manual') ?></td>
    <td><?= $c['expires_at'] ? h(fmt_time($c['expires_at'])) : 'permanent' ?></td>
    <td><?= $canEdit ? post_button('/access', 'Remove', ['action' => 'remove_cleared', 'site' => $c['scope'], 'ip' => $c['ip']], 'btn-link btn-sm p-0') : '' ?></td></tr><?php endforeach; ?>
  </tbody></table>
  <?= $canEdit ? post_button('/access', 'Purge expired entries', ['action' => 'purge']) : '' ?>
</div>
<div class="col-xl-5">
  <h2 class="h6">Login bans</h2>
  <table class="table table-sm small"><thead><tr><th>Address</th><th>Reason</th><th>Until</th><th></th></tr></thead><tbody>
  <?php foreach ($bans as $b): ?><tr><td><code><?= h($b['ip']) ?></code></td><td><?= h($b['reason']) ?></td><td><?= h(fmt_time($b['expires_at'])) ?></td>
    <td><?= $canEdit ? post_button('/access', 'Lift', ['action' => 'unban', 'ip' => $b['ip']], 'btn-link btn-sm p-0') : '' ?></td></tr><?php endforeach; ?>
  <?php if (!$bans): ?><tr><td colspan="4" class="text-muted">None.</td></tr><?php endif; ?>
  </tbody></table>

  <h2 class="h6">Blocks</h2>
  <table class="table table-sm small"><thead><tr><th>Address</th><th>Source</th><th>Reason</th><th>Until</th><th></th></tr></thead><tbody>
  <?php foreach ($blocks as $b): ?><tr><td><code><?= h($b['ip']) ?></code><?= $b['firewall'] ? '' : ' ' . badge('grey', 'nginx only') ?></td><td><?= h($b['source']) ?></td><td><?= h($b['reason']) ?></td><td><?= h(fmt_time($b['expires_at'])) ?></td>
    <td><?= $canEdit ? post_button('/access', 'Unblock', ['action' => 'unblock', 'ip' => $b['ip']], 'btn-link btn-sm p-0') : '' ?></td></tr><?php endforeach; ?>
  <?php if (!$blocks): ?><tr><td colspan="5" class="text-muted">None.</td></tr><?php endif; ?>
  </tbody></table>
  <?php if ($canEdit): ?>
  <form method="post" class="row g-2"><?= csrf_field() ?><input type="hidden" name="action" value="block">
    <div class="col-5"><input class="form-control form-control-sm" name="ip" placeholder="203.0.113.7 or 203.0.113.0/24"></div>
    <div class="col-3"><select class="form-select form-select-sm" name="days"><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option><option value="365">1 year</option></select></div>
    <div class="col-4"><input class="form-control form-control-sm" name="reason" placeholder="Reason"></div>
    <div class="col-8"><div class="form-check"><input class="form-check-input" type="checkbox" name="nginx_only" value="1" id="ngo"><label class="form-check-label small" for="ngo">nginx only (not in the firewall)</label></div></div>
    <div class="col-4"><button class="btn btn-outline-danger btn-sm w-100">Block</button></div>
  </form>
  <?php endif; ?>
</div>
</div>
<?php page_end();
