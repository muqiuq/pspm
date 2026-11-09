<?php
// pspm-agent (root): loads the firewall sets from the snapshot files, keeps the chain
// PSPM-INPUT in place, writes status for the dashboard and the SSH login message
// (plan §14.2, §14.3, §8.2). It is the only root process that reads data written by the
// UI, so every entry is validated here again, and it can only fill its own sets.
//
//   php pspm-agent.php setup    create sets, chain and jump (idempotent)
//   php pspm-agent.php sync     fill the sets, repair the chain, write status
//   php pspm-agent.php off|on   remove / restore the jump (install.sh firewall off|on)
//   php pspm-agent.php apt      package status; apt-get update at most once a day (pspm-apt.timer)
declare(strict_types=1);

const STATE = '/var/lib/pspm/state';
const STATUS = '/var/lib/pspm/status';
const ETC = '/etc/pspm';
const NGX = '/etc/pspm/nginx';
const REPO = '/opt/pspm';
const AGENT_STATE = '/var/lib/pspm/agent-state.json';
const CHAIN = 'PSPM-INPUT';
const NEVER_BLOCKED = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1/128', 'fc00::/7', 'fe80::/10'];
const PEER_GRACE = 3600;
// The kernel refuses ipset timeouts above UINT_MAX/2 milliseconds (about 24.8 days). Longer
// entries (30-day authorisations and blocks) are loaded with this cap, and their set is
// reloaded a day before the capped timeout runs out (load_set).
const IPSET_MAX_TIMEOUT = 2147483;
const RELOAD_MARGIN = 86400;

const SETS = [
    'pspm-allow4'    => ['hash:net', 'inet', 0, 65536],
    'pspm-allow6'    => ['hash:net', 'inet6', 0, 65536],
    'pspm-allowweb4' => ['hash:net', 'inet', 86400, 262144],
    'pspm-allowweb6' => ['hash:net', 'inet6', 86400, 262144],
    'pspm-block4'    => ['hash:net', 'inet', 86400, 262144],
    'pspm-block6'    => ['hash:net', 'inet6', 86400, 262144],
    'pspm-feed4'     => ['hash:net', 'inet', 604800, 1048576],
    'pspm-feed6'     => ['hash:net', 'inet6', 604800, 1048576],
    'pspm-watch4'    => ['hash:net', 'inet', 604800, 1048576],
    'pspm-watch6'    => ['hash:net', 'inet6', 604800, 1048576],
    'pspm-webports'  => ['bitmap:port', '', 0, 0],
];

$errors = [];
function logmsg(string $m): void { fwrite(STDERR, "pspm-agent: $m\n"); }
function sh(array $argv, ?string $stdin = null): array
{
    $p = proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($p)) return [127, '', 'cannot run ' . $argv[0]];
    if ($stdin !== null) fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    return [proc_close($p), (string)$out, (string)$err];
}

// ---------------------------------------------------------------- addresses

function parse_cidr(string $c): ?array
{
    $c = trim($c);
    $len = null;
    if (str_contains($c, '/')) { [$c, $l] = explode('/', $c, 2); if (!ctype_digit($l)) return null; $len = (int)$l; }
    $bin = @inet_pton($c);
    if ($bin === false) return null;
    $max = strlen($bin) * 8;
    $len ??= $max;
    if ($len < 0 || $len > $max) return null;
    $out = '';
    for ($i = 0; $i < strlen($bin); $i++) { $bits = max(0, min(8, $len - $i * 8)); $out .= chr(ord($bin[$i]) & (0xff << (8 - $bits)) & 0xff); }
    return [$out, $len, strlen($bin) === 4 ? 4 : 6];
}

function overlaps(string $a, string $b): bool
{
    $pa = parse_cidr($a); $pb = parse_cidr($b);
    if (!$pa || !$pb || $pa[2] !== $pb[2]) return false;
    $len = min($pa[1], $pb[1]);
    return parse_cidr(inet_ntop($pa[0]) . "/$len")[0] === parse_cidr(inet_ntop($pb[0]) . "/$len")[0];
}

function never_blocked(string $c): bool
{
    foreach (NEVER_BLOCKED as $n) if (overlaps($n, $c)) return true;
    return false;
}

/** "a.b.c.d", "a.b.c.d/n", "x:x::/n", or a client key "a:b:c:d::/64" → [canonical cidr, family] */
function norm(string $c): ?array
{
    $p = parse_cidr($c);
    return $p ? [inet_ntop($p[0]) . '/' . $p[1], $p[2], $p[1]] : null;
}

// ---------------------------------------------------------------- snapshots

/** @return list<array{0:string,1:int,2:string}> key, expires (0 = never), value */
function snapshot(string $name, ?string $file = null, ?array &$meta = null): array
{
    $f = $file ?? STATE . "/$name.tsv";
    $meta = [];
    if (!is_readable($f)) return [];
    $out = [];
    $now = time();
    foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $l) {
        if ($l[0] === '#') { if (preg_match('/^#\s*(\S+)\s+(.*)$/', $l, $m)) $meta[$m[1]] = $m[2]; continue; }
        $parts = explode("\t", $l);
        if (count($parts) !== 3 || !ctype_digit($parts[1])) continue;
        $exp = (int)$parts[1];
        if ($exp !== 0 && $exp <= $now) continue;
        $out[] = [$parts[0], $exp, $parts[2]];
    }
    return $out;
}

function ssh_peers(array &$state): array
{
    $now = time();
    $peers = $state['peers'] ?? [];
    [$rc, $out] = sh(['loginctl', 'list-sessions', '--no-legend', '--no-pager']);
    if ($rc === 0) {
        foreach (explode("\n", trim($out)) as $line) {
            $id = preg_split('/\s+/', trim($line))[0] ?? '';
            if ($id === '' || !preg_match('/^[A-Za-z0-9]+$/', $id)) continue;
            [, $props] = sh(['loginctl', 'show-session', $id, '-p', 'Remote', '-p', 'RemoteHost', '-p', 'State']);
            $p = [];
            foreach (explode("\n", $props) as $kv) if (str_contains($kv, '=')) { [$k, $v] = explode('=', $kv, 2); $p[$k] = $v; }
            if (($p['Remote'] ?? '') === 'yes' && ($ip = $p['RemoteHost'] ?? '') !== '' && @inet_pton($ip) !== false) $peers[$ip] = $now;
        }
    }
    foreach ($peers as $ip => $seen) if ($now - $seen > PEER_GRACE) unset($peers[$ip]);
    $state['peers'] = $peers;
    return array_keys($peers);
}

// ---------------------------------------------------------------- sets and rules

function set_create_args(string $name, ?string $as = null): array
{
    [$type, $fam, $timeout, $max] = SETS[$name];
    $a = [$as ?? $name, $type];
    if ($type === 'bitmap:port') return [...$a, 'range', '0-65535'];
    $a = [...$a, 'family', $fam];
    if ($timeout > 0) $a = [...$a, 'timeout', (string)$timeout];
    return [...$a, 'maxelem', (string)$max];
}

function setup_sets(): void
{
    global $errors;
    foreach (array_keys(SETS) as $s) {
        [$rc, , $err] = sh(['ipset', '-exist', 'create', ...set_create_args($s)]);
        if ($rc !== 0) $errors[] = "ipset create $s: " . trim($err);
    }
}

function desired_rules(int $fam): array
{
    $s = fn(string $base) => $base . $fam;
    $r = ['-A ' . CHAIN . ' -i lo -j RETURN'];
    foreach ($fam === 4 ? ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] : ['fc00::/7', 'fe80::/10'] as $n) $r[] = '-A ' . CHAIN . " -s $n -j RETURN";
    $r[] = '-A ' . CHAIN . ' -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN';
    $r[] = '-A ' . CHAIN . ' -m set --match-set ' . $s('pspm-allow') . ' src -j RETURN';
    $r[] = '-A ' . CHAIN . ' -p tcp -m set --match-set ' . $s('pspm-allowweb') . ' src -m set --match-set pspm-webports dst -j RETURN';
    $r[] = '-A ' . CHAIN . ' -m set --match-set ' . $s('pspm-block') . ' src -j DROP';
    $r[] = '-A ' . CHAIN . ' -m set --match-set ' . $s('pspm-watch') . ' src';
    $r[] = '-A ' . CHAIN . ' -m set --match-set ' . $s('pspm-feed') . ' src -j DROP';
    return $r;
}

function canon_rule(string $r): string
{
    return preg_replace(['/\s+/', '#/32\b#', '#/128\b#'], [' ', '', ''], trim($r)) ?? $r;
}

/** Make the chain match, and the jump be the first rule of INPUT (or absent when off). */
function setup_rules(bool $jump): array
{
    global $errors;
    $state = [];
    foreach ([4 => 'iptables', 6 => 'ip6tables'] as $fam => $bin) {
        $want = desired_rules($fam);
        [$rc, $cur] = sh([$bin, '-w', '5', '-S', CHAIN]);
        $curRules = array_values(array_filter(explode("\n", trim($cur)), fn($l) => str_starts_with($l, '-A ')));
        $same = $rc === 0 && array_map('canon_rule', $curRules) === array_map('canon_rule', $want);
        if (!$same) {
            $in = "*filter\n:" . CHAIN . " - [0:0]\n" . implode("\n", $want) . "\nCOMMIT\n";
            [$rc2, , $err] = sh(["$bin-restore", '-w', '5', '--noflush'], $in);
            if ($rc2 !== 0) { $errors[] = "$bin-restore: " . trim($err); $state["chain$fam"] = 'error'; }
            else $state["chain$fam"] = $rc === 0 ? 'repaired' : 'created';
        } else {
            $state["chain$fam"] = 'ok';
        }
        [, $input] = sh([$bin, '-w', '5', '-S', 'INPUT']);
        $lines = array_values(array_filter(explode("\n", trim($input)), fn($l) => str_starts_with($l, '-A INPUT')));
        $jumps = array_keys(array_filter($lines, fn($l) => canon_rule($l) === '-A INPUT -j ' . CHAIN));
        if (!$jump) {
            foreach ($jumps as $_) sh([$bin, '-w', '5', '-D', 'INPUT', '-j', CHAIN]);
            $state["jump$fam"] = 'off';
        } elseif ($jumps === [0]) {
            $state["jump$fam"] = 'ok';
        } else {
            foreach ($jumps as $_) sh([$bin, '-w', '5', '-D', 'INPUT', '-j', CHAIN]);
            [$rc3, , $err] = sh([$bin, '-w', '5', '-I', 'INPUT', '1', '-j', CHAIN]);
            $state["jump$fam"] = $rc3 === 0 ? ($jumps ? 'moved to first' : 'added') : 'error';
            if ($rc3 !== 0) $errors[] = "$bin -I INPUT: " . trim($err);
        }
    }
    return $state;
}

/** Seconds until an entry expiring at $exp runs out in the kernel (0 = permanent), capped at the ipset limit. */
function ipset_timeout(int $exp, int $now): int
{
    return $exp === 0 ? 0 : min(IPSET_MAX_TIMEOUT, max(1, $exp - $now));
}

/** The restore script for a set; the second value is true when a timeout had to be capped. */
function set_script(string $name, array $entries, int $now): array
{
    $tmp = $name . '-tmp';
    $script = 'create ' . implode(' ', set_create_args($name, $tmp)) . "\nflush $tmp\n";
    $capped = false;
    foreach ($entries as $e => $exp) {
        $t = '';
        if (SETS[$name][2] !== 0) {                   // only sets with timeout support
            $t = ' timeout ' . ipset_timeout($exp, $now);
            $capped = $capped || ($exp !== 0 && $exp - $now > IPSET_MAX_TIMEOUT);
        }
        $script .= "add $tmp $e$t\n";
    }
    return [$script . "swap $tmp $name\ndestroy $tmp\n", $capped];
}

/** The entry an "Error in line N" of ipset restore refers to (line 1 create, 2 flush, then the entries). */
function restore_culprit(string $err, string $script): string
{
    if (!preg_match('/Error in line (\d+)/', $err, $m)) return '';
    $line = explode("\n", $script)[(int)$m[1] - 1] ?? '';
    return str_starts_with($line, 'add ') ? ' [entry: ' . substr($line, strpos($line, ' ', 4) + 1) . ']' : '';
}

/**
 * Replace a set's content atomically (build, swap, destroy). Skipped when the content is
 * unchanged, unless a capped timeout is about to run out (reload deadline in the agent state).
 */
function load_set(string $name, array $entries, array &$agentState): int
{
    global $errors;
    ksort($entries);
    [$type, , , $max] = SETS[$name];
    if ($max > 0 && count($entries) > $max) {
        $errors[] = "$name: " . count($entries) . " entries, capped at $max";
        $entries = array_slice($entries, 0, $max, true);
    }
    $now = time();
    $hash = hash('sha256', json_encode($entries));
    $due = $agentState['reload'][$name] ?? null;
    [$rc] = sh(['ipset', '-n', 'list', $name]);
    if ($rc === 0 && ($agentState['hash'][$name] ?? '') === $hash && ($due === null || $now < $due)) return count($entries);
    $tmp = $name . '-tmp';
    sh(['ipset', 'destroy', $tmp]);   // left over from an interrupted run
    [$script, $capped] = set_script($name, $entries, $now);
    [$rc, , $err] = sh(['ipset', '-exist', 'restore'], $script);
    if ($rc !== 0) {
        $errors[] = "ipset restore $name: " . trim($err) . restore_culprit($err, $script) . '; the set keeps its previous content';
        sh(['ipset', 'destroy', $tmp]);
        return -1;
    }
    $agentState['hash'][$name] = $hash;
    if ($capped) $agentState['reload'][$name] = $now + IPSET_MAX_TIMEOUT - RELOAD_MARGIN;
    else unset($agentState['reload'][$name]);
    return count($entries);
}

// ---------------------------------------------------------------- sync

function sync(): array
{
    global $errors;
    $agentState = is_readable(AGENT_STATE) ? (json_decode((string)file_get_contents(AGENT_STATE), true) ?: []) : [];
    $off = is_file(ETC . '/firewall-off');
    setup_sets();
    $rules = setup_rules(!$off);
    $enforce = !preg_match('/^enforce\s*=\s*0/m', (string)@file_get_contents(STATE . '/firewall.conf'));

    $sets = array_fill_keys(array_keys(SETS), []);
    $add = function (string $set, string $cidr, int $exp) use (&$sets) {
        if (!isset($sets[$set][$cidr]) || ($sets[$set][$cidr] !== 0 && ($exp === 0 || $exp > $sets[$set][$cidr]))) $sets[$set][$cidr] = $exp;
    };
    $dropped = 0;
    // allow: never-block file, admin-trusted, logged-in SSH peers (every port)
    foreach (file(ETC . '/never-block', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $l) {
        $l = trim(preg_replace('/#.*/', '', $l) ?? '');
        if ($l === '') continue;
        if ($n = norm($l)) $add('pspm-allow' . $n[1], $n[0], 0); else $errors[] = "never-block: not an address: $l";
    }
    $peers = ssh_peers($agentState);
    foreach ($peers as $ip) if (($n = norm($ip)) && !never_blocked($n[0])) $add('pspm-allow' . $n[1], $n[0], 0);
    foreach (snapshot('trusted') as [$key, $exp, $kind]) {
        $n = norm($key);
        if (!$n || $n[2] < ($n[1] === 4 ? 16 : 32)) { $dropped++; continue; }
        $add(($kind === 'trusted' ? 'pspm-allow' : 'pspm-allowweb') . $n[1], $n[0], $kind === 'trusted' ? 0 : $exp);
    }
    // allowweb: cleared addresses (key "site|client key")
    foreach (snapshot('cleared') as [$key, $exp]) {
        $ck = explode('|', $key, 2)[1] ?? '';
        if ($n = norm($ck)) $add('pspm-allowweb' . $n[1], $n[0], $exp); else $dropped++;
    }
    // block: PSPM blocks (firewall ones) and login bans
    if ($enforce) {
        foreach ([['blocked', true], ['banned', false]] as [$snap, $needFw]) {
            foreach (snapshot($snap) as [$key, $exp, $val]) {
                if ($needFw && $val !== 'fw') continue;
                $n = norm($key);
                if (!$n || never_blocked($n[0]) || $n[2] < ($n[1] === 4 ? 16 : 32)) { $dropped++; continue; }
                $add('pspm-block' . $n[1], $n[0], $exp);
            }
        }
        // external blocklists (plan §14.5): "block" → feed set, "observe" → counting-only watch set
        foreach (glob(STATE . '/blocklists/*.tsv') ?: [] as $f) {
            $entries = snapshot('', $f, $meta);
            $set = ($meta['mode'] ?? '') === 'block' ? 'pspm-feed' : 'pspm-watch';
            foreach ($entries as [$key, $exp]) {
                $n = norm($key);
                if (!$n || never_blocked($n[0]) || $n[2] < ($n[1] === 4 ? 8 : 16)) { $dropped++; continue; }
                $add($set . $n[1], $n[0], $exp);
            }
        }
    }
    // web ports for authorised addresses
    $ports = [];
    foreach (file(ETC . '/webports', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: ['80', '443'] as $p) {
        if (ctype_digit(trim($p)) && (int)$p >= 1 && (int)$p <= 65535) $ports[(string)(int)$p] = 0;
    }
    $ports += ['80' => 0, '443' => 0];
    $sets['pspm-webports'] = $ports;

    $counts = [];
    foreach ($sets as $name => $entries) $counts[$name] = load_set($name, $entries, $agentState);

    $counters = [];
    foreach ([4 => 'iptables', 6 => 'ip6tables'] as $fam => $bin) {
        [$rc, $out] = sh([$bin, '-w', '5', '-L', CHAIN, '-v', '-x', '-n']);
        foreach (array_slice(explode("\n", trim($out)), 2) as $i => $line) {
            $f = preg_split('/\s+/', trim($line));
            if (count($f) >= 2) $counters["v$fam:" . ($i + 1)] = ['packets' => (int)$f[0], 'rule' => trim(implode(' ', array_slice($f, 2)))];
        }
    }
    $status = ['heartbeat' => gmdate('c'), 'firewall_off' => $off, 'enforce' => $enforce, 'rules' => $rules,
        'sets' => $counts, 'dropped_invalid' => $dropped, 'peers' => $peers, 'counters' => $counters, 'errors' => $errors];
    write_json(STATUS . '/firewall.json', $status);
    @file_put_contents(AGENT_STATE, json_encode($agentState));
    @chmod(AGENT_STATE, 0600);
    check_updates();
    // package counts: every hour from the lists as they are (the daily pspm-apt.timer refreshes them)
    if (!is_file(STATUS . '/apt.json') || time() - (int)filemtime(STATUS . '/apt.json') >= 3600) apt_status(false);
    write_motd();
    return $status;
}

function write_json(string $path, array $data): void
{
    $tmp = "$path.tmp";
    file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    @chgrp($tmp, 'pspm'); @chmod($tmp, 0640);
    rename($tmp, $path);
}

/** Once a day: git fetch (no merge) so the dashboard can say that updates exist. */
function check_updates(): void
{
    $f = STATUS . '/updates.json';
    if (is_file($f) && time() - filemtime($f) < 86400) return;
    if (!is_dir(REPO . '/.git')) return;
    [$rc, , $err] = sh(['timeout', '60', 'git', '-C', REPO, 'fetch', '--quiet', 'origin']);
    $behind = null;
    if ($rc === 0) {
        [$rc2, $n] = sh(['git', '-C', REPO, 'rev-list', '--count', 'HEAD..@{u}']);
        if ($rc2 === 0) $behind = (int)trim($n);
    }
    write_json($f, ['checked' => gmdate('c'), 'behind' => $behind, 'error' => $rc === 0 ? null : trim($err)]);
}

// ---------------------------------------------------------------- apt

/** Packages that can be upgraded, from the package lists as they are (downloads nothing). */
function apt_upgradable(): ?array
{
    [$rc, $out] = sh(['env', 'LC_ALL=C', 'apt', 'list', '--upgradable']);   // stderr: "no stable CLI" warning
    return $rc === 0 ? apt_parse($out) : null;
}

/** The lines of "apt list --upgradable"; the security archive's suites end in -security. */
function apt_parse(string $out): array
{
    $pk = [];
    foreach (explode("\n", $out) as $l) {
        // libssl3t64/stable-security,stable 3.5.7-1~deb13u4 amd64 [upgradable from: 3.5.7-1~deb13u3]
        if (!preg_match('#^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]#', $l, $m)) continue;
        $pk[] = ['name' => $m[1], 'suite' => $m[2], 'to' => $m[3], 'from' => $m[4], 'security' => str_contains($m[2], '-security')];
    }
    return $pk;
}

/**
 * The package status for the dashboard (status/apt.json). "apt-get update" runs at most once
 * a day: only when the lists are older than 20 hours (Debian's apt-daily usually refreshes
 * them already, with the stamp below). Counting reads the lists as they are.
 */
function apt_status(bool $update): array
{
    $prev = json_decode((string)@file_get_contents(STATUS . '/apt.json'), true) ?: [];
    $stamp = '/var/lib/apt/periodic/update-success-stamp';   // touched by apt-daily after a good update
    $last = max((int)@filemtime($stamp), (int)strtotime((string)($prev['last_update'] ?? '')));
    $st = ['checked' => gmdate('c'), 'last_update' => $last ? gmdate('c', $last) : null, 'update_error' => $prev['update_error'] ?? null,
        'update_attempt' => $prev['update_attempt'] ?? null];
    if ($update && time() - $last >= 20 * 3600) {
        $st['update_attempt'] = gmdate('c');
        for ($try = 1; $try <= 3; $try++) {   // the lists lock may be held by apt-daily or unattended-upgrades
            [$rc, , $err] = sh(['timeout', '600', 'env', 'LC_ALL=C', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', '-q', 'update']);
            if ($rc === 0 || !str_contains($err, 'lock')) break;
            sleep(60);
        }
        if ($rc === 0) { $st['last_update'] = gmdate('c'); $st['update_error'] = null; }
        else $st['update_error'] = substr(trim($err) ?: "apt-get update: exit $rc", 0, 500);
    }
    $pk = apt_upgradable();
    $reboot = is_file('/run/reboot-required');
    $st += ['ok' => $pk !== null, 'upgradable' => $pk === null ? null : count($pk),
        'security' => $pk === null ? null : count(array_filter($pk, fn($p) => $p['security'])),
        'packages' => array_slice($pk ?? [], 0, 300),
        'reboot_required' => $reboot,
        'reboot_packages' => $reboot ? array_values(array_filter(array_map('trim', @file('/run/reboot-required.pkgs') ?: []))) : []];
    // security updates are installed by unattended-upgrades; note since when some wait
    $st['security_since'] = $st['security'] ? ($prev['security_since'] ?? gmdate('c')) : null;
    write_json(STATUS . '/apt.json', $st);
    return $st;
}

/** The SSH login message (plan §8.2): instant to print, no DB needed. */
function write_motd(): void
{
    $host = trim((string)shell_exec('hostname -f 2>/dev/null')) ?: gethostname();
    $rev = json_decode((string)@file_get_contents(NGX . '/current/revision.json'), true) ?: [];
    $sum = json_decode((string)@file_get_contents(NGX . '/current/summary.json'), true) ?: [];
    $journal = (string)@file_get_contents('/var/lib/pspm/apply.journal');
    preg_match('/^started=(.*)$/m', $journal, $st);
    preg_match('/^user=(.*)$/m', $journal, $us);
    $lines = [];
    $head = 'PSPM · Secure Proxy Manager';
    if (!empty($rev['id'])) {
        $head .= ' · revision ' . $rev['id'];
        if (!empty($st[1])) $head .= ', applied ' . date('Y-m-d H:i', strtotime($st[1]) ?: time()) . (!empty($us[1]) ? ' by ' . $us[1] : '');
    } else {
        $head .= ' · nothing applied yet';
    }
    $lines[] = $head;
    if (!empty($sum['admin']['in_effect'])) {
        $lines[] = '  UI:       https://' . $sum['admin']['host'] . '/';
    } else {
        [, $out] = sh(['ip', '-o', 'addr', 'show', 'scope', 'global']);
        foreach (explode("\n", trim($out)) as $l) {
            if (!preg_match('#^\d+:\s+(\S+)\s+(inet6?)\s([0-9a-fA-F:.]+)/#', $l, $m)) continue;
            if (preg_match('/^(docker|br-|veth|virbr|lxcbr|podman|cni)/', $m[1])) continue;   // container bridges
            $m = [$m[0], $m[2], $m[3]];
            foreach (['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'] as $n) {
                if (overlaps($n, $m[2])) { $lines[] = '  UI:       https://' . ($m[1] === 'inet6' ? "[{$m[2]}]" : $m[2]) . '/   (from private addresses)'; break; }
            }
        }
    }
    $lines[] = "  Tunnel:   ssh -L 9443:127.0.0.1:9443 root@$host   then https://localhost:9443/";
    $latest = json_decode((string)@file_get_contents(STATE . '/revision.json'), true)['latest'] ?? null;
    if ($latest && (int)$latest !== (int)($rev['id'] ?? 0)) $lines[] = "  Pending:  revision $latest is ready, apply with: sudo " . REPO . '/install.sh';
    if (is_file(NGX . '/current/MANIFEST.sha256')) {
        [$rc] = sh(['sh', '-c', 'cd ' . NGX . '/current && sha256sum --quiet -c MANIFEST.sha256 >/dev/null 2>&1']);
        if ($rc !== 0) $lines[] = '  Drift:    files of the live release were changed by hand (sudo ' . REPO . '/install.sh status)';
    }
    $up = json_decode((string)@file_get_contents(STATUS . '/updates.json'), true);
    if (($up['behind'] ?? 0) > 0) $lines[] = "  Updates:  {$up['behind']} new commits, deploy with: sudo " . REPO . '/install.sh update';
    $apt = json_decode((string)@file_get_contents(STATUS . '/apt.json'), true) ?: [];
    if (($apt['upgradable'] ?? 0) > 0) $lines[] = "  Packages: {$apt['upgradable']} can be upgraded" . (($apt['security'] ?? 0) > 0 ? " ({$apt['security']} security)" : '') . ': sudo apt upgrade';
    if (!empty($apt['reboot_required'])) $lines[] = '  Reboot:   required (' . (implode(', ', array_slice($apt['reboot_packages'] ?? [], 0, 3)) ?: 'updated packages') . ')';
    $tmp = STATUS . '/motd.tmp';
    file_put_contents($tmp, implode("\n", $lines) . "\n");
    chmod($tmp, 0644);
    rename($tmp, STATUS . '/motd');
}

// ---------------------------------------------------------------- main

if (defined('PSPM_AGENT_LIBRARY')) return;   // tests load the functions only
if (posix_geteuid() !== 0) { logmsg('must run as root'); exit(1); }
@mkdir(STATUS, 0750, true);
$cmd = $argv[1] ?? 'sync';
$lock = fopen('/run/lock/pspm-agent.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX)) { logmsg('cannot take the agent lock'); exit(1); }
switch ($cmd) {
    case 'setup':
        setup_sets();
        $r = setup_rules(!is_file(ETC . '/firewall-off'));
        echo json_encode($r) . "\n";
        break;
    case 'sync':
        $s = sync();
        echo 'sets: ' . json_encode($s['sets']) . "\n";
        break;
    case 'apt':
        $s = apt_status(true);
        echo 'packages: ' . json_encode(['upgradable' => $s['upgradable'], 'security' => $s['security'], 'reboot_required' => $s['reboot_required'],
            'last_update' => $s['last_update'], 'update_error' => $s['update_error']]) . "\n";
        if (!$s['ok']) $errors[] = 'apt list --upgradable failed';
        break;
    case 'off':
        $r = setup_rules(false);
        echo json_encode($r) . "\n";
        break;
    case 'on':
        @unlink(ETC . '/firewall-off');
        setup_sets();
        echo json_encode(setup_rules(true)) . "\n";
        break;
    default:
        logmsg("usage: pspm-agent.php setup|sync|off|on|apt");
        exit(64);
}
foreach ($errors as $e) logmsg($e);
exit($errors ? 2 : 0);
