<?php
// Working copy vs what is live, "Ready to apply", revisions, applies, drift (plan §7.7, §6.8).
declare(strict_types=1);

$u = Auth::require('viewer');
if (is_post()) {
    Auth::require('admin');
    if (post('action') === 'ready') {
        [$rid, $errs] = Revisions::commit((string)post('message'));
        if ($errs) { flash('Not ready: ' . implode(' · ', array_slice($errs, 0, 5)), 'danger'); }
        else flash("Revision $rid is ready. On the server run: sudo /opt/pspm/install.sh");
    } elseif (post('action') === 'revert' && ($rid = Validate::int(post('revision'), 1, PHP_INT_MAX))) {
        Revisions::revertTo($rid);
        flash("The working copy now matches revision $rid. Mark it ready to apply it.");
    } elseif (post('action') === 'load_live' && ($live = Live::revision())) {
        if (!empty($live['id']) && Revisions::get((int)$live['id'])) Revisions::revertTo((int)$live['id']);
        flash('The working copy now matches the live configuration.');
    }
    redirect('/changes');
}

$liveRev = Live::revision();
$latest = Revisions::latest();
$working = Revisions::workingChanged();
$doc = Model::document();
$preview = (new Renderer(['id' => 'working copy', 'document' => $doc], Live::previewFacts()))->render();
$liveFiles = Live::files(null, true);
$diffs = $preview['errors'] ? [] : Diff::trees($liveFiles, $preview['files']);
unset($diffs['conf/release.conf']);
$drift = Live::drift();

page_start('Changes', '/changes');
?>
<h1 class="h4 mb-3">Changes</h1>
<div class="row g-3">
  <div class="col-xl-7">
    <div class="card mb-3"><div class="card-body">
      <h2 class="h6">Working copy</h2>
      <p class="mb-2">Live: <?= $liveRev ? 'revision ' . h($liveRev['id']) . ' (release <code>' . h(Live::currentRelease()) . '</code>)' : 'nothing applied yet' ?>.
        Newest revision: <?= $latest ? h($latest['id']) . ' by ' . h($latest['author']) . ', ' . h(ago($latest['created_at'])) : 'none' ?>.</p>
      <?php if ($preview['errors']): ?>
        <div class="alert alert-danger py-2 mb-2"><strong>Cannot be applied yet:</strong><ul class="mb-0"><?php foreach ($preview['errors'] as $e): ?><li><?= h($e) ?></li><?php endforeach; ?></ul></div>
      <?php endif; ?>
      <?php if ($working && Auth::can('admin') && !$preview['errors']): ?>
        <form method="post" class="row g-2 mb-2"><?= csrf_field() ?><input type="hidden" name="action" value="ready">
          <div class="col"><input class="form-control" name="message" placeholder="What changed (optional)"></div>
          <div class="col-auto"><button class="btn btn-primary">Ready to apply</button></div></form>
      <?php elseif (!$working): ?>
        <p class="text-muted mb-2">No edits since revision <?= h($latest['id'] ?? '—') ?>.</p>
      <?php endif; ?>
      <?php if ($latest && (int)($liveRev['id'] ?? 0) !== (int)$latest['id']): ?>
        <div class="alert alert-warning py-2 mb-0">Revision <?= h($latest['id']) ?> is ready. Apply it on the server:
          <div class="input-group input-group-sm mt-1"><input class="form-control font-monospace" readonly value="sudo /opt/pspm/install.sh" id="cmd1"><button class="btn btn-outline-secondary" type="button" data-copy="#cmd1">Copy</button></div></div>
      <?php endif; ?>
      <?php foreach ($preview['warnings'] as $w): ?><div class="small text-warning-emphasis">⚠ <?= h($w) ?></div><?php endforeach; ?>
    </div></div>

    <h2 class="h6">What the working copy changes in nginx <span class="text-muted small">(preview with the facts of the last apply)</span></h2>
    <?php if (!$diffs && !$preview['errors']): ?><p class="text-muted">No difference to the live files.</p><?php endif; ?>
    <?php foreach ($diffs as $p => $d): ?>
      <details class="mb-2"><summary><code><?= h($p) ?></code> <?= badge($d['status'] === 'removed' ? 'red' : 'amber', $d['status']) ?></summary>
        <pre class="diff small border rounded p-2"><?php foreach (explode("\n", $d['diff']) as $line):
            $cls = str_starts_with($line, '+') ? 'add' : (str_starts_with($line, '-') ? 'del' : (str_starts_with($line, '@@') ? 'hunk' : ''));
            echo '<span class="' . $cls . '">' . h($line) . "</span>\n"; endforeach; ?></pre></details>
    <?php endforeach; ?>
  </div>
  <div class="col-xl-5">
    <div class="card mb-3"><div class="card-body">
      <h2 class="h6">Changes made outside PSPM</h2>
      <?php if (!$drift): ?><p class="text-muted mb-0">None. The live files match the applied release.</p><?php endif; ?>
      <?php foreach ($drift as $d): ?>
        <div class="mb-2"><?= badge($d['level'], $d['check']) ?> <?= h($d['message']) ?>
          <?php if (!empty($d['files'])): foreach ($d['files'] as $kind => $files): foreach ($files as $f): ?>
            <div class="small ms-3"><?= h($kind) ?>: <a href="/changes/file?path=<?= h(rawurlencode($f)) ?>&amp;drift=1"><code><?= h($f) ?></code></a></div>
          <?php endforeach; endforeach; endif; ?></div>
      <?php endforeach; ?>
      <?php if ($drift && array_filter($drift, fn($d) => $d['check'] === 'files')): ?><p class="small text-muted mb-0">The next <code>install.sh</code> run lists these, replaces them only after you confirm, and keeps the edited release as <em>previous</em>.</p><?php endif; ?>
      <?php if ($liveRev && $latest && (int)$liveRev['id'] > (int)$latest['id'] && Auth::can('admin')): ?>
        <p class="small mt-2">The database is older than the live configuration.</p><?= post_button('/changes', 'Load the live configuration as working copy', ['action' => 'load_live'], 'btn-outline-primary btn-sm') ?>
      <?php endif; ?>
    </div></div>

    <div class="card mb-3"><div class="card-body">
      <h2 class="h6">Applies</h2>
      <table class="table table-sm small mb-0"><thead><tr><th>When</th><th>Rev.</th><th>By</th><th>Result</th><th></th></tr></thead><tbody>
      <?php foreach (Revisions::applies(15) as $a): ?>
        <tr><td><?= h(fmt_time($a['finished_at'])) ?></td><td><?= h($a['revision_id']) ?></td><td><?= h($a['ssh_user']) ?></td>
          <td><?= badge(in_array($a['result'], ['applied', 'dry_run'], true) ? 'green' : ($a['result'] === 'warnings' ? 'amber' : 'red'), str_replace('_', ' ', $a['result'])) ?></td>
          <td><a href="/changes/apply?id=<?= h($a['id']) ?>">log</a></td></tr>
      <?php endforeach; ?></tbody></table>
    </div></div>

    <div class="card mb-3"><div class="card-body">
      <h2 class="h6">Revisions</h2>
      <table class="table table-sm small mb-0"><thead><tr><th>#</th><th>When</th><th>By</th><th>Message</th><th></th></tr></thead><tbody>
      <?php foreach (Revisions::list(20) as $r): ?>
        <tr><td><?= h($r['id']) ?><?= (int)($liveRev['id'] ?? 0) === (int)$r['id'] ? ' ' . badge('green', 'live') : '' ?></td><td><?= h(fmt_time($r['created_at'])) ?></td><td><?= h($r['author']) ?></td><td><?= h($r['message']) ?></td>
          <td><?php if (Auth::can('admin')): ?><?= post_button('/changes', 'Revert to', ['action' => 'revert', 'revision' => $r['id']], 'btn-link btn-sm p-0', "Replace the working copy with revision {$r['id']}?") ?><?php endif; ?></td></tr>
      <?php endforeach; ?></tbody></table>
    </div></div>

    <div class="card"><div class="card-body">
      <h2 class="h6">Live nginx files (read-only)</h2>
      <?php foreach (array_keys(Live::files()) as $p): ?><div class="small"><a href="/changes/file?path=<?= h(rawurlencode($p)) ?>"><code><?= h($p) ?></code></a></div><?php endforeach; ?>
    </div></div>
  </div>
</div>
<?php page_end();
