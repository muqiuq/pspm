<?php
declare(strict_types=1);

$u = Auth::require('viewer');
if (is_post()) {
    Auth::require('admin');
    if (post('action') === 'delete' && ($id = Validate::uuid(post('id')))) {
        Model::deleteSite($id);
        flash('Site deleted. It stays live until the next apply.');
    }
    redirect('/sites');
}
$sites = Model::sites();
$backends = Model::backends();
$live = [];
foreach (Live::summary()['sites'] ?? [] as $s) $live[$s['id']] = $s;
$liveDoc = Live::revision()['document'] ?? null;
$liveSites = [];
foreach ($liveDoc['sites'] ?? [] as $s) $liveSites[$s['id']] = $s;

page_start('Sites', '/sites');
?>
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1 class="h4 mb-0">Sites</h1>
  <?php if (Auth::can('admin')): ?><a class="btn btn-primary btn-sm" href="/sites/edit">Add site</a><?php endif; ?>
</div>
<?php if (!$sites): ?>
  <p class="text-muted">No sites yet. A site is one or more host names, the backend they lead to, and who may reach it.</p>
<?php else: ?>
<table class="table table-sm table-hover align-middle">
  <thead><tr><th>Host names</th><th>Backend</th><th>Access</th><th>TLS</th><th>State</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($sites as $id => $s):
      $b = $backends[$s['proxy']['backend']]['name'] ?? '—';
      $st = $live[$id] ?? null;
      $cfg = $s; unset($cfg['id'], $cfg['updated_at']);
      $lv = $liveSites[$id] ?? null;
      if ($lv) unset($lv['id']);
      $changed = !$lv || json_canonical($lv, false) !== json_canonical($cfg, false);
  ?>
    <tr>
      <td><a href="/sites/edit?id=<?= h($id) ?>"><?= h($s['hosts'][0]) ?></a><?php if (count($s['hosts']) > 1): ?> <span class="text-muted small">+<?= count($s['hosts']) - 1 ?></span><?php endif; ?>
        <?php if ($s['description']): ?><div class="small text-muted"><?= h($s['description']) ?></div><?php endif; ?></td>
      <td><?= h($b) ?></td>
      <td><?= h(implode(', ', $s['access']['conditions'])) ?></td>
      <td><?= $s['tls']['mode'] === 'none' ? 'none' : ($st && $st['pending'] ? badge('amber', 'pending', 'Waiting for its certificate: the next install.sh run requests it') : ($st ? badge('green', 'ok') : '—')) ?></td>
      <td><?= !$s['enabled'] ? badge('grey', 'disabled') : '' ?> <?= $changed ? badge('amber', 'not applied', 'Changed since the last apply') : '' ?></td>
      <td class="text-end"><?php if (Auth::can('admin')): ?><?= post_button('/sites', 'Delete', ['action' => 'delete', 'id' => $id], 'btn-outline-danger btn-sm', 'Delete site ' . $s['hosts'][0] . '?') ?><?php endif; ?></td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif;
page_end();
