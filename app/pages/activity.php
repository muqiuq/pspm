<?php
declare(strict_types=1);

$u = Auth::require('viewer');
$q = trim((string)get('q'));
$before = Validate::int(get('before'), 1, PHP_INT_MAX);
$where = []; $p = [];
if ($q !== '') { $where[] = '(actor ILIKE ? OR action ILIKE ? OR object ILIKE ?)'; array_push($p, "%$q%", "%$q%", "%$q%"); }
if ($before) { $where[] = 'id < ?'; $p[] = $before; }
$rows = DB::all('SELECT * FROM audit_log' . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY id DESC LIMIT 100', $p);
page_start('Activity', '/activity');
?>
<h1 class="h4 mb-3">Activity</h1>
<form class="row g-2 mb-3"><div class="col-md-4"><input class="form-control form-control-sm" name="q" value="<?= h($q) ?>" placeholder="Filter: user, action, object"></div>
  <div class="col-auto"><button class="btn btn-sm btn-outline-secondary">Filter</button></div></form>
<table class="table table-sm small"><thead><tr><th>When</th><th>Who</th><th>From</th><th>Action</th><th>Object</th><th>Details</th></tr></thead><tbody>
<?php foreach ($rows as $r): ?>
  <tr><td class="text-nowrap"><?= h(fmt_time($r['at'], 'Y-m-d H:i:s')) ?></td><td><?= h($r['actor']) ?></td><td><?= h($r['ip']) ?></td>
    <td><?= h($r['action']) ?></td><td><?= h($r['object']) ?></td><td><code class="small"><?= h($r['details'] === '{}' ? '' : $r['details']) ?></code></td></tr>
<?php endforeach; ?></tbody></table>
<?php if (count($rows) === 100): ?><a class="btn btn-sm btn-outline-secondary" href="/activity?q=<?= h(rawurlencode($q)) ?>&amp;before=<?= h(end($rows)['id']) ?>">Older</a><?php endif; ?>
<?php page_end();
