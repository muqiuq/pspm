<?php
// PKI checks against the smoke-test database (run by tests/smoke.sh).
declare(strict_types=1);
require '/src/app/lib/bootstrap.php';
putenv('PSPM_ACTOR=pki-check');
function check(bool $c, string $what): void { echo ($c ? 'ok   ' : 'FAIL ') . $what . "\n"; if (!$c) exit(1); }

$pass = 'correct horse battery staple';
$t = microtime(true);
$caId = PKI::createCA('Test Clients', 10, $pass);
check(true, sprintf('CA created (%.1f s)', microtime(true) - $t));
$ca = DB::one('SELECT * FROM cas WHERE id = ?', [$caId]);
check(PKI::info($ca['cert_pem'])['is_ca'], 'CA certificate has CA:TRUE');
check(PKI::unwrap($ca['key_wrapped'], 'wrong passphrase!!', $caId, $ca['fingerprint_sha256']) === null, 'wrong passphrase does not unwrap');
check(PKI::unwrap($ca['key_wrapped'], $pass, 'other-id', $ca['fingerprint_sha256']) === null, 'the wrapped key is bound to its CA id');
$uid = (int)DB::val('SELECT id FROM users LIMIT 1');
try { PKI::issue($caId, 'wrong passphrase!!', 'anna@example.test', 365, 'x', [], true, $uid); check(false, 'wrong passphrase refused'); }
catch (InvalidArgumentException $e) { check(str_contains($e->getMessage(), 'not correct'), 'wrong passphrase refused at issuance'); }
foreach ([true, false] as $compat) {
    $r = PKI::issue($caId, $pass, 'anna@example.test', 365, 'Anna laptop', [], $compat, $uid);
    $f = tempnam('/tmp', 'p12'); file_put_contents($f, $r['p12']);
    exec('openssl pkcs12 ' . ($compat ? '-legacy ' : '') . "-in $f -passin pass:" . escapeshellarg($r['password']) . ' -nokeys -clcerts 2>&1', $out, $rc);
    check($rc === 0 && str_contains(implode("\n", $out), 'BEGIN CERTIFICATE'), '.p12 ' . ($compat ? 'compatible (3DES)' : 'modern (AES)') . ' opens with its password');
    $out = [];
    exec('openssl pkcs12 ' . ($compat ? '-legacy ' : '') . "-in $f -passin pass:" . escapeshellarg($r['password']) . ' -info -noout 2>&1', $info);
    if ($compat) check(str_contains(implode(' ', $info), '3DES') || str_contains(implode(' ', $info), 'pbeWithSHA1And3-KeyTripleDES'), 'compatible .p12 uses 3DES');
    $info = [];
    $cf = tempnam('/tmp', 'ca'); file_put_contents($cf, $ca['cert_pem']);
    $xf = tempnam('/tmp', 'c'); file_put_contents($xf, $r['cert']['cert_pem']);
    exec("openssl verify -no-CApath -CAfile $cf -purpose sslclient $xf 2>&1", $v, $rc2);
    check($rc2 === 0, 'client certificate verifies against the CA for clientAuth');
    $v = [];
}
check(strlen(DB::val('SELECT fingerprint_sha1 FROM client_certs LIMIT 1')) === 40, 'SHA-1 fingerprint stored like nginx shows it');
$id = DB::val('SELECT id FROM client_certs LIMIT 1');
PKI::revoke($id, 'test');
[$lines, $meta] = State::build('certs');
check(str_contains(implode('', $lines), "\trevoked"), 'revocation is in the certs snapshot');
check(($meta['managed'] ?? '') === 'Test Clients' && $meta['strict'] === '1', 'strict mode lists the managed CA');
for ($i = 0; $i < 6; $i++) { try { PKI::issue($caId, 'nope nope nope nope', 'x@example.test', 7, '', [], true, $uid); } catch (InvalidArgumentException) {} }
try { PKI::issue($caId, $pass, 'x@example.test', 7, '', [], true, $uid); check(false, 'cool-down'); }
catch (InvalidArgumentException $e) { check(str_contains($e->getMessage(), 'Too many'), 'cool-down after 5 wrong passphrases'); }
DB::q('DELETE FROM pki_failures');
// the CA bundle renders and nginx accepts it
$doc = Model::document();
check(count($doc['cas']) === 1 && Model::checkDocument($doc) === [], 'the document carries the trusted CA and validates');
$facts = json_dec((string)file_get_contents('/src/tests/fixtures/facts.json'));
$r = (new Renderer(['id' => 9, 'document' => $doc], $facts))->render();
check(isset($r['files']['ca/clients.pem']) && str_contains(implode('', $r['files']), 'ssl_verify_client optional;'), 'the renderer writes the CA bundle and asks for client certificates');
@mkdir('/tmp/pki-release', 0755, true);
foreach ($r['files'] as $p => $c) { @mkdir(dirname("/tmp/pki-release/$p"), 0755, true); file_put_contents("/tmp/pki-release/$p", $c); }
echo "pki checks passed\n";
