<?php
declare(strict_types=1);

$u = Auth::require('viewer');
$path = (string)get('path');
$files = Live::files();
if (!isset($files[$path])) page_error(404, 'No such file in the live release.');
page_start('Live file', '/changes');
echo '<h1 class="h5"><code>' . h($path) . '</code> <span class="text-muted small">release ' . h(Live::currentRelease()) . '</span></h1>';
$manifest = Live::manifest();
$d = Live::dir();
if (get('drift') && isset($manifest[$path]) && hash('sha256', $files[$path]) !== $manifest[$path]) {
    echo '<div class="alert alert-warning py-2">This file was changed outside PSPM. The applied version is not kept separately, but the '
        . 'renderer can show what it would write: see Changes.</div>';
}
echo '<pre class="border rounded p-2 small">' . h($files[$path]) . '</pre><a href="/changes">Back</a>';
page_end();
