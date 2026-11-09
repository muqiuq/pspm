<?php
// What a revision changes, for the install.sh review (plan §6.3 step 3). Lines starting
// with OPENS are changes that widen access; install.sh shows them in red.
//   php review.php <old revision.json | /dev/null> <new revision.json>
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';

$load = function (string $f): array {
    if ($f === '/dev/null' || !is_readable($f)) return ['sites' => [], 'backends' => [], 'global' => Settings::GLOBAL_DEFAULTS];
    $r = json_dec((string)file_get_contents($f));
    return $r['document'] ?? $r;
};
$old = $load($argv[1] ?? '/dev/null');
$new = $load($argv[2] ?? '');
$byId = fn(array $l) => array_column($l, null, 'id');
$os = $byId($old['sites'] ?? []); $ns = $byId($new['sites'] ?? []);
$rank = fn(array $c) => in_array('public', $c, true) ? 99 : count($c);
$lines = [];
$opens = [];
$conds = fn(array $s) => $s['access']['conditions'] ?? [];
foreach ($ns as $id => $s) {
    $name = $s['hosts'][0];
    if (!isset($os[$id])) {
        if (!empty($s['enabled'])) {
            $lines[] = "+ site $name (" . implode(', ', $conds($s)) . ')';
            $opens[] = "new site $name, reachable by: " . implode(', ', $conds($s));
        } else $lines[] = "+ site $name (disabled)";
        continue;
    }
    $o = $os[$id];
    if ($o === $s) continue;
    $what = [];
    if (($o['enabled'] ?? false) !== ($s['enabled'] ?? false)) {
        $what[] = $s['enabled'] ? 'enabled' : 'disabled';
        if ($s['enabled']) $opens[] = "site $name enabled";
    }
    if ($o['hosts'] !== $s['hosts']) {
        $what[] = 'host names';
        if ($added = array_diff($s['hosts'], $o['hosts'])) $opens[] = "site $name answers new host names: " . implode(', ', $added);
    }
    if ($conds($o) !== $conds($s)) {
        $what[] = 'access ' . implode(',', $conds($o)) . ' → ' . implode(',', $conds($s));
        if (array_diff($conds($s), $conds($o))) $opens[] = "site $name accepts more: " . implode(', ', $conds($s));
    }
    $orout = array_column($o['routes'] ?? [], null, 'id');
    foreach ($s['routes'] ?? [] as $r) {
        $or = $orout[$r['id']] ?? null;
        $pub = in_array('public', $r['overrides']['access']['conditions'] ?? [], true);
        if ($pub && (!$or || !in_array('public', $or['overrides']['access']['conditions'] ?? [], true))) {
            $opens[] = "site $name: route " . implode(' ', $r['paths']) . ' is public';
        }
    }
    $newPorts = array_diff(array_column($s['listeners'] ?? [], 'port'), array_column($o['listeners'] ?? [], 'port'));
    if ($newPorts) $opens[] = "site $name listens on new ports: " . implode(', ', $newPorts);
    foreach (['tls', 'port80', 'client_certs', 'limits', 'proxy', 'headers', 'routes', 'listeners', 'description'] as $k) {
        if (($o[$k] ?? null) !== ($s[$k] ?? null)) $what[] = $k;
    }
    $lines[] = "~ site $name: " . implode(', ', array_unique($what));
}
foreach ($os as $id => $s) if (!isset($ns[$id])) $lines[] = '- site ' . $s['hosts'][0];
$ob = $byId($old['backends'] ?? []); $nb = $byId($new['backends'] ?? []);
foreach ($nb as $id => $b) {
    if (!isset($ob[$id])) $lines[] = "+ backend {$b['name']} (" . implode(', ', array_column($b['servers'], 'addr')) . ')';
    elseif ($ob[$id] !== $b) $lines[] = "~ backend {$b['name']}";
}
foreach ($ob as $id => $b) if (!isset($nb[$id])) $lines[] = "- backend {$b['name']}";
$og = $old['global'] ?? []; $ng = $new['global'] ?? [];
foreach ($ng as $k => $v) if (($og[$k] ?? null) !== $v) $lines[] = "~ setting $k";
if (($og['admin_host'] ?? '') !== ($ng['admin_host'] ?? '')) $opens[] = 'admin host name: ' . (($ng['admin_host'] ?? '') ?: '(none: the UI answers by IP to private addresses)');
if (array_diff($ng['admin_access'] ?? [], $og['admin_access'] ?? [])) $opens[] = 'admin UI reachable by: ' . implode(', ', $ng['admin_access']);
if (array_diff($ng['lan_ranges'] ?? [], $og['lan_ranges'] ?? [])) $opens[] = 'LAN ranges now include: ' . implode(', ', array_diff($ng['lan_ranges'], $og['lan_ranges'] ?? []));

echo $lines ? "Changes:\n" . implode("\n", array_map(fn($l) => "  $l", $lines)) . "\n" : "No configuration changes (only facts such as certificates).\n";
foreach ($opens as $o) echo "OPENS: $o\n";
