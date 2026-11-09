<?php
// Export, import, backups (plan §16, §10.4). Admins only, with re-authentication.
declare(strict_types=1);

$u = Auth::require('admin');
$errors = [];
$preview = null;
$tmpDir = PSPM_VAR . '/tmp';
if (is_post()) {
    Auth::requireReauth();
    $a = post('action');
    try {
        if ($a === 'export') {
            $doc = Export::build((string)post('passphrase'), isset($_POST['history']));
            header('Content-Type: application/json');
            header('Content-Disposition: attachment; filename="pspm-export-' . gmdate('Ymd-His') . '.json"');
            header('Cache-Control: no-store');
            echo Export::encode($doc);
            exit;
        }
        if ($a === 'preview') {
            $f = $_FILES['file'] ?? null;
            if (!$f || $f['error'] !== UPLOAD_ERR_OK || $f['size'] > 64 * 1024 * 1024) throw new InvalidArgumentException('Choose an export file (at most 64 MB).');
            $json = (string)file_get_contents($f['tmp_name']);
            @unlink($f['tmp_name']);
            [$doc, $secrets] = Export::open($json, (string)post('passphrase'));
            $token = Crypto::token(18);
            file_put_contents("$tmpDir/import-$token.json", $json);
            chmod("$tmpDir/import-$token.json", 0600);
            DB::q("INSERT INTO nonces (nonce, user_id, purpose, expires_at) VALUES (?, ?, 'import', now() + interval '30 minutes')", [$token, $u['id']]);
            $preview = ['token' => $token, 'p' => Export::preview($doc, $secrets, $u['username'])];
            // the passphrase is needed again at confirmation; it is never stored
        } elseif ($a === 'import') {
            $token = (string)post('token');
            if (!preg_match('/^[A-Za-z0-9_-]{20,40}$/', $token) || !DB::q("DELETE FROM nonces WHERE nonce = ? AND user_id = ? AND purpose = 'import' AND expires_at > now()", [$token, $u['id']])->rowCount()) {
                throw new InvalidArgumentException('The preview expired. Upload the file again.');
            }
            if (post('confirm') !== 'IMPORT') throw new InvalidArgumentException('Type IMPORT to confirm.');
            $file = "$tmpDir/import-$token.json";
            [$doc, $secrets] = Export::open((string)file_get_contents($file), (string)post('passphrase'));
            $before = Export::encode(Export::build((string)post('passphrase'), true));
            write_atomic($tmpDir . '/pre-import-' . gmdate('Ymd-His') . '.json', $before, 0600);
            $stats = Export::apply($doc, $secrets, $u['username']);
            @unlink($file);
            flash('Imported (' . array_sum($stats) . ' records). Runtime state is live; mark the configuration ready on Changes and run install.sh. '
                . (isset($secrets['tls']) ? 'The Let\'s Encrypt material in the file is restored only by scripts/import.sh on the server.' : ''));
            redirect('/backup');
        }
    } catch (InvalidArgumentException $e) {
        $errors[] = $e->getMessage();
    }
}
foreach (glob("$tmpDir/import-*.json") ?: [] as $f) if (filemtime($f) < time() - 3600) @unlink($f);
$backups = [];
foreach (glob(PSPM_VAR . '/backups/*', GLOB_ONLYDIR) ?: [] as $d) {
    $files = array_map('basename', glob("$d/*") ?: []);
    $backups[] = ['name' => basename($d), 'time' => filemtime($d), 'files' => $files, 'size' => array_sum(array_map(fn($f) => filesize("$d/$f"), $files))];
}
usort($backups, fn($a, $b) => $b['time'] <=> $a['time']);
$fresh = Auth::reauthFresh();
page_start('Backup', '/backup');
?>
<h1 class="h4 mb-3">Backup, export and import</h1>
<?= errors_box($errors) ?>
<?php if ($preview): $p = $preview['p']; ?>
  <div class="card card-body mb-4 border-warning">
    <h2 class="h6">Import preview — exported <?= h($p['exported_at']) ?></h2>
    <div class="row small">
      <div class="col-md-6"><table class="table table-sm"><?php foreach ($p['counts'] as $k => $n): ?><tr><td><?= h($k) ?></td><td><?= h($n) ?></td></tr><?php endforeach; ?></table></div>
      <div class="col-md-6"><strong>Users</strong><ul><?php foreach ($p['users'] as $x): ?><li><?= h($x) ?></li><?php endforeach; ?></ul>
        <div>Sites: <?= h($p['diff']['sites'][0]) ?> now → <?= h($p['diff']['sites'][1]) ?>; backends: <?= h($p['diff']['backends'][0]) ?> → <?= h($p['diff']['backends'][1]) ?></div>
        <?php foreach ($p['conflicts'] as $c): ?><div class="text-danger"><?= h($c) ?></div><?php endforeach; ?>
        <?php if ($p['tls']): ?><div class="text-muted">The file has Let's Encrypt material; only <code>scripts/import.sh</code> on the server restores it.</div><?php endif; ?></div>
    </div>
    <form method="post" class="row g-2" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="import"><input type="hidden" name="token" value="<?= h($preview['token']) ?>">
      <div class="col-md-4"><input class="form-control" type="password" name="passphrase" placeholder="export passphrase again" required></div>
      <div class="col-md-4"><input class="form-control" name="confirm" placeholder="type IMPORT" required></div>
      <div class="col-md-4"><button class="btn btn-danger w-100">Replace everything</button></div>
    </form>
    <p class="small text-muted mt-2 mb-0">The current state is exported first. Everything is written in one transaction; your own account is kept as it is.</p>
  </div>
<?php endif; ?>
<?php if (!$fresh): ?>
  <p><a class="btn btn-outline-primary" href="/reauth?next=/backup">Confirm it is you to export or import</a></p>
<?php else: ?>
<div class="row g-4">
  <div class="col-lg-6"><div class="card card-body">
    <h2 class="h6">Export</h2>
    <p class="small">Everything in one JSON file: configuration, revisions, access, certificates, sign-in, security state, users. Secrets (password hashes, keys,
      API keys) are in an encrypted part. Let's Encrypt keys only with <code>sudo /opt/pspm/scripts/export.sh --with-tls</code> on the server.</p>
    <form method="post" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="export">
      <?= f_text('passphrase', 'Export passphrase (at least 16 characters)', '', [], 'Needed for the import. Keep it apart from the file.', 'password', '', ['autocomplete' => 'new-password']) ?>
      <?= f_check('history', 'Include history (audit log, activity, findings)', true) ?>
      <button class="btn btn-primary btn-sm">Export and download</button></form>
  </div></div>
  <div class="col-lg-6"><div class="card card-body">
    <h2 class="h6">Import</h2>
    <form method="post" enctype="multipart/form-data" autocomplete="off"><?= csrf_field() ?><input type="hidden" name="action" value="preview">
      <div class="mb-2"><input class="form-control form-control-sm" type="file" name="file" accept=".json,application/json" required></div>
      <?= f_text('passphrase', 'Export passphrase', '', [], '', 'password') ?>
      <button class="btn btn-outline-primary btn-sm">Show what would change</button></form>
  </div></div>
</div>
<?php endif; ?>
<h2 class="h6 mt-4">Backups on this box</h2>
<p class="small text-muted">Before every install.sh run and every night (<?= (Settings::get('backup', [])['passphrase_enc'] ?? '') ? 'with' : 'without' ?> a JSON export; the passphrase is set in Settings). Copy them off the box yourself.
  Restore: <code>sudo /opt/pspm/scripts/import.sh &lt;export.json&gt;</code>, or on a new box <code>install.sh --import &lt;file&gt;</code>.</p>
<table class="table table-sm small"><thead><tr><th>Backup</th><th>When</th><th>Files</th><th>Size</th></tr></thead><tbody>
<?php foreach ($backups as $b): ?><tr><td><?= h($b['name']) ?></td><td><?= h(date('Y-m-d H:i', $b['time'])) ?></td><td><?= h(implode(', ', $b['files'])) ?></td><td><?= h(human_bytes($b['size'])) ?></td></tr><?php endforeach; ?>
<?php if (!$backups): ?><tr><td colspan="4" class="text-muted">None yet.</td></tr><?php endif; ?></tbody></table>
<?php page_end();
