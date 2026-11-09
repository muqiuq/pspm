<?php
// Access links for a site and for the admin UI, against the smoke-test database (run by
// tests/smoke.sh before the export round trip, so the export carries both kinds).
declare(strict_types=1);
require '/src/app/lib/bootstrap.php';
putenv('PSPM_ACTOR=access-check');
function check(bool $c, string $what): void { echo ($c ? 'ok   ' : 'FAIL ') . $what . "\n"; if (!$c) exit(1); }

$site = DB::one("SELECT s.id, h.host FROM sites s JOIN site_hosts h ON h.site_id = s.id WHERE h.host = 'app.example.ch'");
check((bool)$site, 'the smoke site exists');
$g = Settings::global();
$g['admin_host'] = 'proxy.pspm.test';
$g['admin_access'] = ['lan', 'cleared', 'cert'];
Settings::saveGlobal($g);

[$adminLink, $adminToken] = Access::createLink(null, 'admin from home', 7 * 86400, null, null, '/');
[$siteLink, $siteToken] = Access::createLink($site['id'], 'site visitor', 86400, null, null, '/');
check(DB::val('SELECT target FROM access_links WHERE id = ?', [$adminLink]) === 'admin', 'a link for the admin UI has the target "admin" and no site');

check(Access::useLink('app.example.ch', $adminToken, '203.0.113.50')[0] === false, 'an admin link does not work on a site host');
check(Access::useLink('proxy.pspm.test', $siteToken, '203.0.113.50')[0] === false, 'a site link does not work on the admin host');
[$ok, , $after] = Access::useLink('proxy.pspm.test', $adminToken, '203.0.113.50');
check($ok && $after === '/', 'the admin link works on the admin host name');
check(DB::val("SELECT scope FROM cleared_ips WHERE ip = '203.0.113.50/32' AND site_id IS NULL") === 'admin', 'the address is cleared for the scope "admin"');
check(Access::useLink('app.example.ch', $siteToken, '203.0.113.50')[0] === true, 'the same address can also be cleared for a site');
check((int)DB::val("SELECT count(*) FROM cleared_ips WHERE ip = '203.0.113.50/32'") === 2, 'two clearances for one address (admin and site) side by side');
check(Access::useLink('proxy.pspm.test', $adminToken, '203.0.113.50')[0] === true
    && (int)DB::val("SELECT count(*) FROM cleared_ips WHERE ip = '203.0.113.50/32'") === 2, 'using the admin link again renews, no duplicate');

State::publish('cleared');
$snap = (string)file_get_contents(PSPM_VAR . '/state/cleared.tsv');
check(str_contains($snap, "admin|203.0.113.50\t"), 'nginx snapshot: "admin|<address>" (the admin server checks $pspm_site "admin")');
check(str_contains($snap, $site['id'] . "|203.0.113.50\t"), 'nginx snapshot: the site clearance keeps its site id');

Access::revokeLink($adminLink);
check(!DB::val("SELECT 1 FROM cleared_ips WHERE scope = 'admin'"), 'revoking the admin link ends its clearance');
check(DB::val("SELECT 1 FROM cleared_ips WHERE scope = ?", [$site['id']]) == 1, 'the site clearance stays');

// leave one admin link with a clearance for the export round trip
[, $t2] = Access::createLink(null, 'export round trip', null, null, 5, '/');
Access::useLink('proxy.pspm.test', $t2, '203.0.113.51');
echo "access checks passed\n";
