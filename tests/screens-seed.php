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

// a few AI calls for the AI log
$ai = AI::settings(); $ai['model'] = 'google/gemini-2.5-flash'; $ai['key_enc'] = Crypto::seal('screens'); Settings::set('ai', $ai);
$req = ['system' => 'You assess traffic seen by a reverse proxy in the last 24 hours. …', 'user' => ['subjects' => [
    ['subject' => 'ip-1', 'requests' => 25, 'denied' => 25, 'not_found' => 25, 'exploit_tags' => ['git'], 'paths' => [['/.git/config', 25]], 'user_agents' => ['curl/8.5']],
    ['subject' => 'ip-2', 'requests' => 14, 'denied' => 12, 'not_found' => 3, 'exploit_tags' => [], 'paths' => [['/admin', 12]], 'user_agents' => ['Mozilla/5.0']]]]];
$cid = (int)DB::val("INSERT INTO ai_calls (role, purpose, model, model_answer, request, response, result, status, duration_ms, tokens_in, tokens_out, cost, pseudonyms)
    VALUES ('main', 'scan', 'google/gemini-2.5-flash', 'google/gemini-2.5-flash-001', CAST(? AS jsonb), ?, CAST(? AS jsonb), 200, 1840, 912, 118, 0.000146, CAST(? AS jsonb)) RETURNING id",
    [json_enc($req), '{"verdicts":[{"subject":"ip-1","verdict":"block","confidence":0.96,"reason":"Probing for repository secrets."},{"subject":"ip-2","verdict":"watch","confidence":0.55,"reason":"Repeated admin access, unclear."}]}',
     '{"verdicts":[]}', json_enc(['ip-1' => '203.0.113.66/32', 'ip-2' => '198.51.100.23/32'])]);
DB::q("INSERT INTO ai_verdicts (kind, subject, verdict, confidence, reason, model, outcome, call_id) VALUES
    ('verdict', '203.0.113.66/32', 'block', 0.96, 'Probing for repository secrets.', 'google/gemini-2.5-flash', 'blocked', ?),
    ('verdict', '198.51.100.23/32', 'watch', 0.55, 'Repeated admin access, unclear.', 'google/gemini-2.5-flash', 'watch', ?)", [$cid, $cid]);
DB::q("INSERT INTO ai_calls (role, purpose, model, request, response, status, duration_ms, error) VALUES
    ('main', 'behaviour', 'google/gemini-2.5-flash', '{}', '{\"error\":\"rate limited\"}', 429, 210, 'AI API: HTTP 429 {\"error\":\"rate limited\"}')");
DB::q("INSERT INTO ai_calls (role, purpose, model, model_answer, request, response, result, status, duration_ms, tokens_in, tokens_out, cost) VALUES
    ('main', 'test', 'google/gemini-2.5-flash', 'google/gemini-2.5-flash-001', '{}', '{\"ok\": true}', '{\"ok\": true}', 200, 640, 40, 6, 0.000008)");

$token = Crypto::token(32);
DB::q("INSERT INTO sessions (id_hash, user_id, stage, csrf, reauth_at) VALUES (?, ?, 'full', ?, now())", [hash('sha256', $token), $uid, Crypto::token(24)]);
echo "TOKEN=$token\n";
