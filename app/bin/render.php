<?php
// The renderer as a filter: {"revision": …, "facts": …} on stdin, result JSON on stdout.
// Run by install.sh as the user pspm-render, which can read neither the DB nor any secret.
// Exit: 0 ok, 2 the revision is invalid (errors in the output), 1 crash.
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';

try {
    $in = json_dec(stream_get_contents(STDIN));
    if (!is_array($in) || !isset($in['revision'], $in['facts'])) throw new RuntimeException('input must be {"revision":…, "facts":…}');
    $out = (new Renderer($in['revision'], $in['facts']))->render();
    echo json_enc($out);
    exit($out['errors'] ? 2 : 0);
} catch (Throwable $e) {
    fwrite(STDERR, 'render failed: ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine() . "\n");
    exit(1);
}
