<?php
declare(strict_types=1);

$u = Auth::require('viewer');
$a = DB::one('SELECT * FROM applies WHERE id = ?', [(int)get('id')]);
if (!$a) page_error(404, 'No such apply.');
$log = null;
if ($a['log_file'] && str_starts_with($a['log_file'], PSPM_LOG . '/') && is_readable($a['log_file'])) $log = (string)file_get_contents($a['log_file']);
page_start('Apply ' . $a['id'], '/changes');
?>
<h1 class="h5">Apply of revision <?= h($a['revision_id']) ?> — <?= h(str_replace('_', ' ', $a['result'])) ?></h1>
<p class="small">Release <code><?= h($a['release']) ?></code> · by <?= h($a['ssh_user']) ?> · <?= h(fmt_time($a['started_at'], 'Y-m-d H:i:s')) ?> – <?= h(fmt_time($a['finished_at'], 'H:i:s')) ?> · code <?= h($a['code_commit']) ?></p>
<?php if ($a['message']): ?><div class="alert alert-<?= in_array($a['result'], ['applied', 'dry_run'], true) ? 'success' : 'warning' ?> py-2"><?= h($a['message']) ?></div><?php endif; ?>
<h2 class="h6">Log <span class="text-muted small"><?= h($a['log_file']) ?></span></h2>
<pre class="border rounded p-2 small log"><?= h($log ?? ($a['log_excerpt'] ?: 'The log file is not readable.')) ?></pre>
<a href="/changes">Back</a>
<?php page_end();
