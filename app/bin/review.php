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
$op = array_column($old['providers'] ?? [], null, 'id'); $np = array_column($new['providers'] ?? [], null, 'id');
$noSignin = ['mode' => 'none', 'provider' => '', 'groups' => [], 'emails' => [], 'domains' => []];
// Who may sign in on a site: its own limits, or else everyone the provider accepts.
$signinWho = function (array $si) use ($np): string {
    $p = $np[$si['provider'] ?? ''] ?? null;
    $who = [];
    foreach (['groups' => 'groups', 'emails' => 'e-mails', 'domains' => 'e-mail domains'] as $k => $label) {
        if (!empty($si[$k])) $who[] = "$label " . implode(' ', $si[$k]);
    }
    if (!$who) $who[] = !$p ? 'any account' : (in_array('*', $p['email_domains'], true) ? 'any account of the tenant' : 'any account from ' . implode(' ', $p['email_domains']));
    return ($p ? $p['name'] . ': ' : '') . implode('; ', $who);
};
// The access of a site in words, sign-in included (plan §12.3: alternative = OR, required = AND).
$reach = function (array $s) use ($conds, $signinWho, $noSignin): string {
    $si = ($s['access']['signin'] ?? []) + $noSignin;
    $c = implode(', ', $conds($s));
    if ($si['mode'] === 'alternative') return "$c, or Microsoft sign-in (" . $signinWho($si) . ')';
    if ($si['mode'] === 'required') return "$c, and only after Microsoft sign-in (" . $signinWho($si) . ')';
    return $c;
};
$routeOpens = function (string $name, array $s, ?array $o) use (&$opens): void {
    $orout = array_column($o['routes'] ?? [], null, 'id');
    foreach ($s['routes'] ?? [] as $r) {
        $or = $o === null ? null : ($orout[$r['id']] ?? null);
        $paths = implode(' ', $r['paths']);
        $pub = in_array('public', $r['overrides']['access']['conditions'] ?? [], true);
        if ($pub && (!$or || !in_array('public', $or['overrides']['access']['conditions'] ?? [], true))) $opens[] = "site $name: route $paths is public";
        $rs = $r['overrides']['access']['signin'] ?? null;
        if ($rs === 'alternative' && ($or['overrides']['access']['signin'] ?? null) !== 'alternative' && ($s['access']['signin']['mode'] ?? 'none') !== 'alternative') {
            $opens[] = "site $name: route $paths accepts Microsoft sign-in as an alternative";
        }
        // "none" only widens a site that requires sign-in (with "alternative" it narrows)
        if ($rs === 'none' && ($or['overrides']['access']['signin'] ?? null) !== 'none' && ($s['access']['signin']['mode'] ?? 'none') === 'required') $opens[] = "site $name: route $paths without the required sign-in";
    }
};
foreach ($ns as $id => $s) {
    $name = $s['hosts'][0];
    if (!isset($os[$id])) {
        if (!empty($s['enabled'])) {
            $lines[] = "+ site $name (" . $reach($s) . ')';
            $opens[] = "new site $name, reachable by: " . $reach($s);
            $routeOpens($name, $s, null);
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
    if (($o['access']['signin'] ?? $noSignin) !== ($s['access']['signin'] ?? $noSignin)) $what[] = 'sign-in';
    elseif (($o['access'] ?? null) !== ($s['access'] ?? null) && $conds($o) === $conds($s)) $what[] = 'access';
    $routeOpens($name, $s, $o);
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
    elseif ($ob[$id] !== $b) {
        $hb = fn(array $x) => (int)($x['header_buffer'] ?? Validate::HEADER_BUFFER_DEFAULT);
        $what = array_keys(array_filter(['servers' => 1, 'protocol' => 1, 'tls_verify' => 1, 'tls_name' => 1, 'custom_ca' => 1, 'keepalive' => 1, 'name' => 1],
            fn($_, $k) => ($ob[$id][$k] ?? null) !== ($b[$k] ?? null), ARRAY_FILTER_USE_BOTH));
        if ($hb($ob[$id]) !== $hb($b)) $what[] = 'response header buffer ' . $hb($ob[$id]) . 'k → ' . $hb($b) . 'k';
        $lines[] = "~ backend {$b['name']}" . ($what ? ': ' . implode(', ', $what) : '');
    }
}
foreach ($ob as $id => $b) if (!isset($nb[$id])) $lines[] = "- backend {$b['name']}";
$oc = array_column($old['cas'] ?? [], null, 'id'); $nc = array_column($new['cas'] ?? [], null, 'id');
foreach ($nc as $id => $c) if (!isset($oc[$id])) { $lines[] = "+ trusted CA {$c['name']}"; $opens[] = "nginx trusts a new CA for client certificates: {$c['name']} (SHA-256 " . substr($c['fingerprint_sha256'], 0, 16) . '…)'; }
foreach ($oc as $id => $c) if (!isset($nc[$id])) $lines[] = "- trusted CA {$c['name']}";
foreach ($np as $id => $p) {
    if (!isset($op[$id])) { $lines[] = "+ sign-in provider {$p['name']} ({$p['signin_host']})"; $opens[] = "new sign-in provider {$p['name']}: tenant {$p['tenant_id']}, client {$p['client_id']}"; continue; }
    $o = $op[$id];
    if ($o === $p) continue;
    $lines[] = "~ sign-in provider {$p['name']}";
    if ($o['tenant_id'] !== $p['tenant_id'] || $o['client_id'] !== $p['client_id']) $opens[] = "sign-in provider {$p['name']} now uses tenant {$p['tenant_id']}, client {$p['client_id']}";
    if (in_array('*', $p['email_domains'], true) && !in_array('*', $o['email_domains'], true) || array_diff($p['email_domains'], $o['email_domains'])) {
        $opens[] = "sign-in provider {$p['name']} accepts more e-mail domains: " . implode(', ', $p['email_domains']);
    }
}
foreach ($op as $id => $p) if (!isset($np[$id])) $lines[] = "- sign-in provider {$p['name']}";
foreach ($ns as $id => $s) {
    if (!isset($os[$id])) continue;
    $o = ($os[$id]['access']['signin'] ?? []) + $noSignin;
    $n = ($s['access']['signin'] ?? []) + $noSignin;
    $name = $s['hosts'][0];
    if ($o['mode'] !== 'none' && $n['mode'] === 'none') $opens[] = "site $name: sign-in removed";
    if ($o['mode'] === 'none' && $n['mode'] === 'alternative') $opens[] = "site $name: Microsoft sign-in added as an alternative (" . $signinWho($n) . ')';
    if ($o['mode'] === 'required' && $n['mode'] === 'alternative') $opens[] = "site $name: sign-in is now an alternative instead of required (" . $signinWho($n) . ')';
    if ($o['mode'] !== 'none' && $n['mode'] !== 'none' && $o['provider'] !== $n['provider']) $opens[] = "site $name: signs in with another provider (" . $signinWho($n) . ')';
    if ($o['mode'] !== 'none' && $n['mode'] !== 'none') {
        foreach (['groups', 'emails', 'domains'] as $k) {
            if ($o[$k] && (!$n[$k] || array_diff($n[$k], $o[$k]))) $opens[] = "site $name: more users may sign in ($k: " . ($n[$k] ? implode(' ', $n[$k]) : 'no limit') . ')';
        }
    }
}
$og = $old['global'] ?? []; $ng = $new['global'] ?? [];
foreach ($ng as $k => $v) if (($og[$k] ?? null) !== $v) $lines[] = "~ setting $k";
if (($og['admin_host'] ?? '') !== ($ng['admin_host'] ?? '')) {
    $sharedWith = array_values(array_filter($np, fn($p) => ($ng['admin_host'] ?? '') !== '' && $p['signin_host'] === $ng['admin_host']));
    $opens[] = 'admin host name: ' . (($ng['admin_host'] ?? '') ?: '(none: the UI answers by IP to private addresses)')
        . ($sharedWith ? " (also the sign-in host of {$sharedWith[0]['name']}: /oauth2/ there stays public, the UI keeps the admin access)" : '');
}
if (array_diff($ng['admin_access'] ?? [], $og['admin_access'] ?? [])) $opens[] = 'admin UI reachable by: ' . implode(', ', $ng['admin_access']);
if (array_diff($ng['lan_ranges'] ?? [], $og['lan_ranges'] ?? [])) $opens[] = 'LAN ranges now include: ' . implode(', ', array_diff($ng['lan_ranges'], $og['lan_ranges'] ?? []));

echo $lines ? "Changes:\n" . implode("\n", array_map(fn($l) => "  $l", $lines)) . "\n" : "No configuration changes (only facts such as certificates).\n";
foreach ($opens as $o) echo "OPENS: $o\n";
