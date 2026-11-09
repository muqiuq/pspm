<?php
declare(strict_types=1);

$u = Auth::require('viewer');
$name = preg_match('/^[a-z0-9-]+$/', (string)get('page', 'index')) ? (string)get('page', 'index') : 'index';
$file = PSPM_APP . "/help/$name.md";
if (!is_readable($file)) page_error(404, 'No such help page.');
$pages = [];
foreach (glob(PSPM_APP . '/help/*.md') ?: [] as $f) {
    $first = strtok((string)file_get_contents($f), "\n");
    $pages[basename($f, '.md')] = ltrim((string)$first, '# ');
}
page_start('Help', '/help');
echo '<div class="row"><div class="col-md-3"><div class="list-group mb-3">';
foreach ($pages as $k => $t) echo '<a class="list-group-item list-group-item-action' . ($k === $name ? ' active' : '') . '" href="/help/' . h($k) . '">' . h($t) . '</a>';
echo '</div></div><div class="col-md-9 help">' . Markdown::render((string)file_get_contents($file)) . '</div></div>';
page_end();
