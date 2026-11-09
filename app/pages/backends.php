<?php
declare(strict_types=1);

$u = Auth::require('viewer');
if (is_post()) {
    Auth::require('admin');
    if (post('action') === 'delete' && ($id = Validate::uuid(post('id')))) {
        $err = Model::deleteBackend($id);
        flash($err ?? 'Backend deleted.', $err ? 'danger' : 'success');
    }
    redirect('/backends');
}
$backends = Model::backends();
page_start('Backends', '/backends');
?>
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1 class="h4 mb-0">Backends</h1>
  <?php if (Auth::can('admin')): ?><a class="btn btn-primary btn-sm" href="/backends/edit">Add backend</a><?php endif; ?>
</div>
<?php if (!$backends): ?>
  <p class="text-muted">No backends yet. A backend is the server (or group of servers) a site forwards to.</p>
<?php else: ?>
<table class="table table-sm table-hover align-middle">
  <thead><tr><th>Name</th><th>Servers</th><th>Protocol</th><th>Used by</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($backends as $id => $b): ?>
    <tr>
      <td><a href="/backends/edit?id=<?= h($id) ?>"><?= h($b['name']) ?></a></td>
      <td><?= h(implode(', ', array_column($b['servers'], 'addr'))) ?></td>
      <td><?= h($b['protocol']) ?><?= $b['protocol'] === 'https' ? ' <span class="text-muted small">verify: ' . h($b['tls_verify']) . '</span>' : '' ?></td>
      <td class="small"><?= h(implode(', ', Model::backendUsers($id)) ?: '—') ?></td>
      <td class="text-end"><?php if (Auth::can('admin')): ?><?= post_button('/backends', 'Delete', ['action' => 'delete', 'id' => $id], 'btn-outline-danger btn-sm', 'Delete backend ' . $b['name'] . '?') ?><?php endif; ?></td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif;
page_end();
