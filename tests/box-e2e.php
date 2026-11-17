<?php
// Inside the systemd test box, as pspm: create a CA, a cert-only site, a sign-in provider
// and a site that requires sign-in; commit a revision. tests/box-e2e.sh drives it.
declare(strict_types=1);
require '/srv/pspm/app/current/lib/bootstrap.php';
putenv('PSPM_ACTOR=box-e2e');
$step = $argv[1] ?? 'setup';
if ($step === 'setup') {
    if (DB::val("SELECT 1 FROM site_hosts WHERE host = 'cert.pspm.test'")) { echo "already set up\n"; exit(0); }
    [$bid] = Model::saveBackend(null, Validate::backend(['name' => 'app', 'protocol' => 'http', 'servers' => [['addr' => '10.99.0.5:8080']]])[0], null);
    $caId = PKI::createCA('E2E Clients', 10, 'e2e passphrase long enough');
    [$pid, $err] = Signin::save(null, Signin::validate(['name' => 'E2E staff', 'tenant_id' => '72f988bf-86f1-41af-91ab-2d7cd011db47',
        'client_id' => '66666666-7777-8888-9999-000000000000', 'signin_host' => 'auth.pspm.test', 'email_domains' => ['pspm.test']])[0], 'fake-client-secret');
    if ($err) throw new RuntimeException($err);
    $mk = function (string $host, array $access) use ($bid) {
        $in = Validate::defaultSite();
        $in['hosts'] = [$host]; $in['proxy']['backend'] = $bid; $in['access'] = $access + $in['access'];
        [$s, $e] = Validate::site($in, [$bid]);
        if ($e) throw new RuntimeException(json_encode($e));
        [, $err] = Model::saveSite(null, $s, null);
        if ($err) throw new RuntimeException($err);
    };
    $mk('cert.pspm.test', ['conditions' => ['cert'], 'denied' => '403']);
    $si = Validate::defaultSite()['access']['signin'];
    $mk('sso.pspm.test', ['conditions' => ['public'], 'denied' => '403', 'signin' => ['mode' => 'required', 'provider' => $pid] + $si]);
    [$rid, $errs] = Revisions::commit('e2e');
    if ($errs) throw new RuntimeException(implode('; ', $errs));
    echo "revision $rid committed\n";
} elseif ($step === 'issue') {
    $uid = (int)DB::val('SELECT id FROM users LIMIT 1');
    $r = PKI::issue((string)DB::val("SELECT id FROM cas WHERE name = 'E2E Clients'"), 'e2e passphrase long enough', 'anna@pspm.test', 30, 'e2e', [], false, $uid);
    file_put_contents('/var/lib/pspm/tmp/e2e.p12', $r['p12']);
    file_put_contents('/var/lib/pspm/tmp/e2e.pass', $r['password']);
    echo "issued {$r['cert']['fingerprint_sha1']}\n";
} elseif ($step === 'revoke') {
    PKI::revoke((string)DB::val("SELECT id FROM client_certs WHERE subject_cn = 'anna@pspm.test' AND revoked_at IS NULL ORDER BY issued_at DESC LIMIT 1"), 'e2e');
    echo "revoked\n";
} elseif ($step === 'bigheader') {
    // backend "big" (tests/box-backend.php) with the given response header buffer, and a plain-HTTP site for it
    $kb = (int)($argv[2] ?? 16);
    $cur = DB::one("SELECT id, updated_at FROM backends WHERE name = 'big'");
    [$b, $e] = Validate::backend(['name' => 'big', 'protocol' => 'http', 'header_buffer' => (string)$kb, 'servers' => [['addr' => '127.0.0.1:8099']]]);
    if ($e) throw new RuntimeException(json_encode($e));
    [$bid, $err] = Model::saveBackend($cur['id'] ?? null, $b, $cur['updated_at'] ?? null);
    if ($err) throw new RuntimeException($err);
    if (!DB::val("SELECT 1 FROM site_hosts WHERE host = 'big.pspm.test'")) {
        $in = Validate::defaultSite();
        $in['hosts'] = ['big.pspm.test']; $in['proxy']['backend'] = $bid; $in['access']['conditions'] = ['public'];
        $in['tls']['mode'] = 'none';
        [$s, $e] = Validate::site($in, [$bid]);
        if ($e) throw new RuntimeException(json_encode($e));
        [, $err] = Model::saveSite(null, $s, null);
        if ($err) throw new RuntimeException($err);
    }
    [$rid, $errs] = Revisions::commit("big headers: {$kb}k");
    if ($errs) throw new RuntimeException(implode('; ', $errs));
    echo "revision $rid committed\n";
} elseif ($step === 'owncallback') {
    // an application with its own Microsoft sign-in behind sso.pspm.test (sign-in required): its
    // callbacks pass without PSPM's sign-in, to backend "big" (tests/box-backend.php echoes the headers); "off" removes the route
    $sid = (string)DB::val("SELECT site_id FROM site_hosts WHERE host = 'sso.pspm.test'");
    $big = (string)DB::val("SELECT id FROM backends WHERE name = 'big'");
    $cur = Model::site($sid);
    $in = $cur; unset($in['id'], $in['updated_at']);
    $in['routes'] = array_values(array_filter($in['routes'], fn($r) => $r['id'] !== 'rcb'));
    if (($argv[2] ?? '') !== 'off') $in['routes'][] = ['id' => 'rcb', 'match' => 'exact', 'paths' => ['/signin-oidc', '/signout-callback-oidc'], 'listeners' => ['all'],
        'action' => 'proxy', 'overrides' => ['access' => ['signin' => 'none'], 'backend' => $big]];
    [$s, $e] = Validate::site($in, array_column(Model::backends(), 'id'));
    if ($e) throw new RuntimeException(json_encode($e));
    [, $err] = Model::saveSite($sid, $s, $cur['updated_at']);
    if ($err) throw new RuntimeException($err);
    [$rid, $errs] = Revisions::commit('own sign-in callbacks ' . ($argv[2] ?? 'on'));
    if ($errs) throw new RuntimeException(implode('; ', $errs));
    echo "revision $rid committed\n";
} elseif ($step === 'adminhost') {
    // the admin host name, e.g. the sign-in host (one server for both); '' = none; optional admin access list
    $g = Settings::global();
    $g['admin_host'] = (string)($argv[2] ?? '');
    $g['admin_access'] = explode(',', (string)($argv[3] ?? 'lan,cert'));
    Settings::saveGlobal($g);
    [$rid, $errs] = Revisions::commit('admin host name: ' . ($g['admin_host'] ?: 'none'));
    if ($errs) throw new RuntimeException(implode('; ', $errs));
    echo "revision $rid committed\n";
} elseif ($step === 'servercerts') {
    // the overview of the Certificates page: name, kind, what uses it, state
    foreach (Live::serverCertificates() as $c) echo $c['name'], "\t", $c['kind'], "\t", implode('; ', $c['used_by']), "\t", $c['state'][0], "\n";
} elseif ($step === 'adminlink') {
    // an access link to the admin UI; prints the token
    [, $token] = Access::createLink(null, 'box-e2e admin', 3600, null, null, '/');
    echo "$token\n";
} elseif ($step === 'adminrevoke') {
    // revoke every link to the admin UI (ends their clearances)
    $n = 0;
    foreach (DB::all("SELECT id FROM access_links WHERE target = 'admin' AND revoked_at IS NULL") as $l) { Access::revokeLink($l['id']); $n++; }
    echo "$n revoked\n";
} elseif ($step === 'oldclear') {
    // a clearance as it existed before migration 3 (site link, site_id only)
    $sid = (string)DB::val("SELECT site_id FROM site_hosts WHERE host = 'cert.pspm.test'");
    DB::q("INSERT INTO cleared_ips (site_id, ip, expires_at) VALUES (?, '198.51.100.99/32', now() + interval '1 day') ON CONFLICT DO NOTHING", [$sid]);
    echo "$sid\n";
} elseif ($step === 'longterm') {
    // 30 days is longer than the kernel's ipset limit (24.8 days): an authorised address
    // (allow-web set) and an escalated firewall block (block set)
    DB::q("INSERT INTO trusted_ips (ip, kind, source, last_seen, expires_at) VALUES ('203.0.113.7/32', 'authorised', 'e2e', now(), now() + interval '30 days')
           ON CONFLICT (ip) DO UPDATE SET expires_at = excluded.expires_at");
    Blocks::add('192.0.2.77', 'manual', 'e2e: 30-day block', 30 * 86400, true, 'box-e2e');
    State::publish('trusted', 'blocked');
    echo "30-day entries published\n";
} elseif ($step === 'blocklist') {
    $id = Crypto::uuid();
    DB::q("INSERT INTO blocklists (id, name, url, format, mode, enabled, last_ok_at) VALUES (?, 'e2e', 'https://example.test/list', 'plain', 'block', true, now())", [$id]);
    @mkdir(Blocklists::dir(), 0750, true);
    file_put_contents(Blocklists::dir() . "/$id.list", "198.51.100.0/24\n45.155.205.0/24\n10.0.0.0/8\n");
    Blocklists::writeFile($id);
    echo file_get_contents(Blocklists::dir() . "/$id.tsv");
}
