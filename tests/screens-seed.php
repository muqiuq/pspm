<?php
// Data for tests/screenshots.sh: a backend, sites, a CA, links, a committed revision, and a
// signed-in session for admin (printed as TOKEN=…). Throwaway database only.
declare(strict_types=1);
require '/src/app/lib/bootstrap.php';
putenv('PSPM_ACTOR=screens');

DB::q("UPDATE users SET must_change_password = false, totp_secret_enc = ?, totp_confirmed = true, email = 'admin@pspm.test' WHERE username = 'admin'",
    [Crypto::seal(random_bytes(20))]);
$uid = (int)DB::val("SELECT id FROM users WHERE username = 'admin'");

[$bid] = Model::saveBackend(null, Validate::backend(['name' => 'app', 'protocol' => 'https', 'header_buffer' => '64',
    'servers' => [['addr' => '10.0.0.5:8443'], ['addr' => '10.0.0.6:8443', 'backup' => true]]])[0], null);
$mk = function (string $host, array $conds) use ($bid) {
    $in = Validate::defaultSite();
    $in['hosts'] = [$host]; $in['proxy']['backend'] = $bid; $in['access']['conditions'] = $conds;
    [$s, $e] = Validate::site($in, [$bid]);
    if ($e) throw new RuntimeException(json_encode($e));
    return Model::saveSite(null, $s, null)[0];
};
$sid = $mk('app.pspm.test', ['lan', 'cleared', 'cert']);
$mk('wiki.pspm.test', ['public']);
$g = Settings::global();
$g['admin_host'] = 'proxy.pspm.test';
$g['admin_access'] = ['lan', 'cleared', 'cert'];
Settings::saveGlobal($g);
PKI::createCA('Screens Clients', 10, 'screens passphrase long enough');
$ca = (string)DB::val("SELECT id FROM cas LIMIT 1");
PKI::issue($ca, 'screens passphrase long enough', 'anna@pspm.test', 365, 'Anna, laptop', [], false, $uid);
Access::createLink($sid, 'Visitor', 7 * 86400, null, null, '/');
Access::createLink(null, 'Admin from home', 86400, null, 5, '/');
Revisions::commit('screens');
Blocks::add('203.0.113.66', 'manual', 'screens', 86400, true, 'screens');

$token = Crypto::token(32);
DB::q("INSERT INTO sessions (id_hash, user_id, stage, csrf, reauth_at) VALUES (?, ?, 'full', ?, now())", [hash('sha256', $token), $uid, Crypto::token(24)]);
echo "TOKEN=$token\n";
