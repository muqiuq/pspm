<?php
// Revisions and apply records for install.sh (run as pspm).
//   revision.php export [--id N]          newest (or given) committed revision as JSON
//   revision.php latest-id
//   revision.php record-apply < apply.json
//   revision.php commit-working "message"  (used by --import and tests)
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=' . (getenv('PSPM_ACTOR') ?: 'root (install.sh)'));

$cmd = $argv[1] ?? '';
try {
    switch ($cmd) {
        case 'export':
            $id = null;
            if (($i = array_search('--id', $argv, true)) !== false) $id = (int)($argv[$i + 1] ?? 0);
            $r = Revisions::export($id);
            if (!$r) { fwrite(STDERR, $id ? "no revision $id\n" : "no committed revision yet\n"); exit(5); }
            echo json_enc($r);
            break;
        case 'latest-id':
            echo (Revisions::latest()['id'] ?? 0) . "\n";
            break;
        case 'record-apply':
            $a = json_dec(stream_get_contents(STDIN));
            DB::q('INSERT INTO applies (revision_id, release, manifest_sha, code_commit, ssh_user, result, message, log_file, log_excerpt, started_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [($a['revision_id'] ?? 0) ?: null, (string)$a['release'], $a['manifest_sha'] ?? null, $a['code_commit'] ?? null, $a['ssh_user'] ?? null,
                 (string)$a['result'], $a['message'] ?? null, $a['log_file'] ?? null, mb_substr((string)($a['log_excerpt'] ?? ''), 0, 20000), (string)$a['started_at']]);
            Audit::log('apply.' . $a['result'], 'release:' . $a['release'], ['revision' => $a['revision_id'] ?? null]);
            echo "recorded\n";
            break;
        case 'commit-working':
            [$id, $errs] = Revisions::commit($argv[2] ?? 'committed by install.sh');
            if ($errs) { fwrite(STDERR, implode("\n", $errs) . "\n"); exit(2); }
            echo "$id\n";
            break;
        default:
            fwrite(STDERR, "usage: revision.php export [--id N] | latest-id | record-apply | commit-working [message]\n");
            exit(64);
    }
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(3);
}
