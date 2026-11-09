<?php
declare(strict_types=1);

$u = Auth::require('viewer');
page_start('About');
?>
<h1 class="h4">PSPM <span class="text-muted">· Secure Proxy Manager</span></h1>
<p class="small text-muted">Philipp's Secure Proxy Manager</p>
<table class="table table-sm col-md-6 w-auto">
  <tr><th>Version</th><td><?= h(pspm_version()) ?></td></tr>
  <tr><th>Code</th><td><code><?= h(Status::codeCommit()) ?></code></td></tr>
  <tr><th>Schema</th><td><?= h(DB::schemaVersion()) ?></td></tr>
  <tr><th>Live release</th><td><code><?= h(Live::currentRelease() ?? '—') ?></code></td></tr>
  <tr><th>PHP</th><td><?= h(PHP_VERSION) ?></td></tr>
</table>
<?php page_end();
