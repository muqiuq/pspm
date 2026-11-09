<?php
declare(strict_types=1);

/**
 * Client-certificate PKI with the CA key on the server (plan §13). The CA key is wrapped
 * with a key derived from the CA passphrase (Argon2id) and XChaCha20-Poly1305; the CA's
 * id and fingerprint are the associated data. The passphrase is never stored.
 */
final class PKI
{
    public const DURATIONS = ['7' => '1 week', '30' => '1 month', '91' => '3 months', '182' => '6 months',
        '365' => '1 year', '730' => '2 years', '1095' => '3 years', '2190' => '6 years'];
    private const WORDS = ['anchor', 'basil', 'canyon', 'dolphin', 'ember', 'falcon', 'garnet', 'harbor', 'indigo', 'jasmine',
        'kepler', 'lantern', 'meadow', 'nectar', 'obsidian', 'pebble', 'quartz', 'riddle', 'sapphire', 'thistle', 'umbra',
        'velvet', 'walnut', 'xenon', 'yonder', 'zinnia', 'aurora', 'bramble', 'cinder', 'drift', 'eclipse', 'fennel',
        'glimmer', 'hollow', 'ivory', 'juniper', 'kindle', 'lilac', 'marble', 'nimbus', 'orchard', 'prism', 'quiver',
        'rustle', 'saffron', 'tundra', 'upland', 'vortex', 'willow', 'yarrow'];

    // ---------------------------------------------------------------- passphrases and key wrapping

    public static function passphraseProblem(string $p): ?string
    {
        if (mb_strlen($p) < 16) return 'The passphrase needs at least 16 characters.';
        if (strlen($p) > 1024) return 'The passphrase is too long.';
        return null;
    }

    public static function generatePassphrase(): string
    {
        $w = [];
        for ($i = 0; $i < 5; $i++) $w[] = self::WORDS[random_int(0, count(self::WORDS) - 1)];
        return implode('-', $w);
    }

    public static function p12Password(): string
    {
        return self::WORDS[random_int(0, count(self::WORDS) - 1)] . str_pad((string)random_int(0, 9999), 4, '0', STR_PAD_LEFT);
    }

    public static function wrap(string $keyPem, string $passphrase, string $caId, string $fp): string
    {
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $ops = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
        $mem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
        $k = sodium_crypto_pwhash(32, $passphrase, $salt, $ops, $mem, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($keyPem, "$caId|$fp", $nonce, $k);
        sodium_memzero($k);
        return json_enc(['v' => 1, 'kdf' => 'argon2id', 'ops' => $ops, 'mem' => $mem, 'salt' => base64_encode($salt),
            'aead' => 'xchacha20poly1305', 'nonce' => base64_encode($nonce), 'ct' => base64_encode($ct)]);
    }

    public static function unwrap(string $wrapped, string $passphrase, string $caId, string $fp): ?string
    {
        $w = json_dec($wrapped);
        $k = sodium_crypto_pwhash(32, $passphrase, base64_decode($w['salt']), (int)$w['ops'], (int)$w['mem'], SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $pem = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(base64_decode($w['ct']), "$caId|$fp", base64_decode($w['nonce']), $k);
        sodium_memzero($k);
        return $pem === false ? null : $pem;
    }

    /** Seconds until this user may try a CA passphrase again (5 failures in 10 minutes). */
    public static function cooldown(int $userId): int
    {
        $r = DB::one("SELECT count(*) AS n, max(at) AS last FROM pki_failures WHERE user_id = ? AND at > now() - interval '10 minutes'", [$userId]);
        if ((int)$r['n'] < 5) return 0;
        return max(0, 600 - (time() - (new DateTimeImmutable($r['last']))->getTimestamp()));
    }

    private static function failed(int $userId): void
    {
        DB::q('INSERT INTO pki_failures (user_id) VALUES (?)', [$userId]);
        DB::q("DELETE FROM pki_failures WHERE at < now() - interval '1 day'");
    }

    // ---------------------------------------------------------------- certificates

    public static function fingerprint(string $pem, string $algo = 'sha256'): string
    {
        return strtolower((string)openssl_x509_fingerprint($pem, $algo));
    }

    public static function info(string $pem): ?array
    {
        $x = @openssl_x509_parse($pem);
        if (!$x) return null;
        $bc = $x['extensions']['basicConstraints'] ?? '';
        return ['cn' => (string)($x['subject']['CN'] ?? ''), 'issuer_cn' => (string)($x['issuer']['CN'] ?? ''),
            'not_before' => gmdate('c', (int)$x['validFrom_time_t']), 'not_after' => gmdate('c', (int)$x['validTo_time_t']),
            'is_ca' => str_contains($bc, 'CA:TRUE'), 'self_signed' => ($x['subject'] ?? null) == ($x['issuer'] ?? null),
            'serial' => (string)($x['serialNumberHex'] ?? $x['serialNumber'] ?? '')];
    }

    private static function config(): string
    {
        $dir = is_writable(PSPM_VAR . '/tmp') ? PSPM_VAR . '/tmp' : sys_get_temp_dir();
        $f = "$dir/pspm-openssl.cnf";
        $cfg = "[ req ]\ndistinguished_name = dn\n[ dn ]\n"
            . "[ v3_ca ]\nbasicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n"
            . "[ v3_client ]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\n"
            . "extendedKeyUsage = clientAuth\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n";
        if (!is_file($f) || file_get_contents($f) !== $cfg) file_put_contents($f, $cfg);
        return $f;
    }

    public static function validName(string $n): bool
    {
        return (bool)preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._-]{2,63}$/', $n);
    }

    /** Create a self-signed root CA (RSA 4096, pathlen 0). Returns the CA id. */
    public static function createCA(string $name, int $years, string $passphrase): string
    {
        $cfg = self::config();
        $key = openssl_pkey_new(['private_key_bits' => 4096, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'config' => $cfg]);
        $csr = openssl_csr_new(['commonName' => $name, 'organizationName' => 'PSPM'], $key, ['config' => $cfg, 'digest_alg' => 'sha256']);
        $cert = openssl_csr_sign($csr, null, $key, $years * 365 + intdiv($years, 4), ['config' => $cfg, 'x509_extensions' => 'v3_ca', 'digest_alg' => 'sha256'],
            random_int(1, PHP_INT_MAX));
        if (!$cert) throw new RuntimeException('creating the CA failed: ' . openssl_error_string());
        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($key, $keyPem, null, ['config' => $cfg]);
        $id = Crypto::uuid();
        $fp = self::fingerprint($certPem);
        $info = self::info($certPem);
        DB::q('INSERT INTO cas (id, name, cert_pem, fingerprint_sha256, subject_cn, not_after, key_wrapped, trusted, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, true, ?)',
            [$id, $name, $certPem, $fp, $info['cn'], $info['not_after'], self::wrap($keyPem, $passphrase, $id, $fp), Audit::actor()]);
        sodium_memzero($keyPem);
        Audit::log('ca.create', "ca:$name", ['years' => $years, 'fingerprint' => $fp]);
        State::publish('certs');
        return $id;
    }

    /** Import a CA certificate, optionally with its key (then PSPM can issue with it). */
    public static function importCA(string $name, string $certPem, ?string $keyPem, ?string $keyPass, ?string $passphrase): string
    {
        $info = self::info($certPem);
        if (!$info || !$info['is_ca'] || !$info['self_signed']) throw new InvalidArgumentException('This is not a self-signed CA certificate (CA:TRUE).');
        if (strtotime($info['not_after']) < time()) throw new InvalidArgumentException('This CA certificate has expired.');
        $id = Crypto::uuid();
        $fp = self::fingerprint($certPem);
        $wrapped = null;
        if ($keyPem !== null && trim($keyPem) !== '') {
            $key = openssl_pkey_get_private($keyPem, (string)$keyPass);
            if (!$key) throw new InvalidArgumentException('The key cannot be read (wrong password?).');
            if (!openssl_x509_check_private_key($certPem, $key)) throw new InvalidArgumentException('The key does not belong to this certificate.');
            openssl_pkey_export($key, $plain, null, ['config' => self::config()]);
            $wrapped = self::wrap($plain, (string)$passphrase, $id, $fp);
            sodium_memzero($plain);
        }
        openssl_x509_export($certPem, $normPem);
        DB::q('INSERT INTO cas (id, name, cert_pem, fingerprint_sha256, subject_cn, not_after, key_wrapped, trusted, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, true, ?)',
            [$id, $name, $normPem, $fp, $info['cn'], $info['not_after'], $wrapped, Audit::actor()]);
        Audit::log('ca.import', "ca:$name", ['fingerprint' => $fp, 'with_key' => $wrapped !== null]);
        State::publish('certs');
        return $id;
    }

    private static function caKey(array $ca, string $passphrase, int $userId): mixed
    {
        if (!$ca['key_wrapped']) throw new InvalidArgumentException('This CA has no key in PSPM (trust only).');
        if (($wait = self::cooldown($userId)) > 0) throw new InvalidArgumentException("Too many wrong passphrases. Try again in $wait seconds.");
        $pem = self::unwrap($ca['key_wrapped'], $passphrase, $ca['id'], $ca['fingerprint_sha256']);
        if ($pem === null) { self::failed($userId); throw new InvalidArgumentException('The CA passphrase is not correct.'); }
        $key = openssl_pkey_get_private($pem);
        sodium_memzero($pem);
        if (!$key) throw new RuntimeException('The CA key cannot be loaded.');
        return $key;
    }

    /**
     * Issue a client certificate. Returns ['cert' => row, 'p12' => binary, 'password' => …].
     * The client key exists only in memory and inside the .p12; it is never stored.
     */
    public static function issue(string $caId, string $passphrase, string $cn, int $days, string $label, array $scope, bool $compat, int $userId): array
    {
        $ca = DB::one('SELECT * FROM cas WHERE id = ?', [$caId]);
        if (!$ca) throw new InvalidArgumentException('Unknown CA.');
        if (!preg_match('/^[A-Za-z0-9._@+-]{1,64}$/', $cn)) throw new InvalidArgumentException('Subject: user@domain or a domain (letters, digits, . _ @ + -).');
        $caKey = self::caKey($ca, $passphrase, $userId);
        $left = (int)floor((strtotime($ca['not_after']) - time()) / 86400) - 1;
        $days = max(1, min($days, $left));
        $cfg = self::config();
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'config' => $cfg]);
        $csr = openssl_csr_new(['commonName' => $cn], $key, ['config' => $cfg, 'digest_alg' => 'sha256']);
        $serial = random_int(1, PHP_INT_MAX);
        $cert = openssl_csr_sign($csr, $ca['cert_pem'], $caKey, $days, ['config' => $cfg, 'x509_extensions' => 'v3_client', 'digest_alg' => 'sha256'], $serial);
        if (!$cert) throw new RuntimeException('signing failed: ' . openssl_error_string());
        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($key, $keyPem, null, ['config' => $cfg]);
        $password = self::p12Password();
        $p12 = self::pkcs12($keyPem . $certPem . $ca['cert_pem'], $label !== '' ? $label : $cn, $password, $compat);
        sodium_memzero($keyPem);
        $info = self::info($certPem);
        $id = Crypto::uuid();
        $scopeStr = $scope ? implode(',', $scope) : 'all';
        DB::q('INSERT INTO client_certs (id, ca_id, serial, subject_cn, label, fingerprint_sha1, fingerprint_sha256, scope, cert_pem, not_before, not_after, issued_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$id, $caId, dechex($serial), $cn, $label, self::fingerprint($certPem, 'sha1'), self::fingerprint($certPem), $scopeStr, $certPem,
             $info['not_before'], $info['not_after'], Audit::actor()]);
        Audit::log('cert.issue', "cert:$cn", ['ca' => $ca['name'], 'days' => $days, 'scope' => $scopeStr, 'label' => $label]);
        State::publish('certs');
        return ['cert' => DB::one('SELECT * FROM client_certs WHERE id = ?', [$id]), 'p12' => $p12, 'password' => $password];
    }

    /** PKCS#12 through the openssl CLI: key and certificates on stdin, the password in the environment. */
    private static function pkcs12(string $pems, string $name, string $password, bool $compat): string
    {
        $args = ['openssl', 'pkcs12', '-export', '-name', $name, '-passout', 'env:PSPM_P12_PASS'];
        // Compatibility: 3DES/SHA-1 for old macOS, iOS, Android and Windows keychains.
        if ($compat) $args = [...$args, '-legacy', '-certpbe', 'PBE-SHA1-3DES', '-keypbe', 'PBE-SHA1-3DES', '-macalg', 'sha1'];
        $p = proc_open($args, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null,
            ['PSPM_P12_PASS' => $password, 'PATH' => '/usr/bin:/bin']);
        if (!is_resource($p)) throw new RuntimeException('cannot run openssl');
        fwrite($pipes[0], $pems);
        fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        if (proc_close($p) !== 0 || $out === '' || $out === false) throw new RuntimeException('openssl pkcs12 failed: ' . trim((string)$err));
        return $out;
    }

    public static function revoke(string $certId, string $reason): void
    {
        $c = DB::one('SELECT * FROM client_certs WHERE id = ?', [$certId]);
        if (!$c || $c['revoked_at']) return;
        DB::tx(function () use ($c, $reason) {
            DB::q('UPDATE client_certs SET revoked_at = now(), revoked_by = ?, revoke_reason = ? WHERE id = ?', [Audit::actor(), $reason, $c['id']]);
            // Revoking also removes the trust the certificate gave its addresses (plan §13.3).
            DB::q('DELETE FROM trusted_ips WHERE source = ?', ['cert:' . $c['fingerprint_sha1']]);
        });
        Audit::log('cert.revoke', 'cert:' . $c['subject_cn'], ['reason' => $reason, 'fingerprint' => $c['fingerprint_sha256']]);
        State::publish('certs', 'trusted');
    }

    public static function setScope(string $certId, array $scope): void
    {
        $s = $scope ? implode(',', $scope) : 'all';
        DB::q('UPDATE client_certs SET scope = ? WHERE id = ?', [$s, $certId]);
        Audit::log('cert.scope', "cert:$certId", ['scope' => $s]);
        State::publish('certs');
    }

    public static function changePassphrase(string $caId, string $old, string $new, int $userId): void
    {
        $ca = DB::one('SELECT * FROM cas WHERE id = ?', [$caId]);
        if (!$ca || !$ca['key_wrapped']) throw new InvalidArgumentException('This CA has no key in PSPM.');
        if (($wait = self::cooldown($userId)) > 0) throw new InvalidArgumentException("Too many wrong passphrases. Try again in $wait seconds.");
        $pem = self::unwrap($ca['key_wrapped'], $old, $ca['id'], $ca['fingerprint_sha256']);
        if ($pem === null) { self::failed($userId); throw new InvalidArgumentException('The current passphrase is not correct.'); }
        DB::q('UPDATE cas SET key_wrapped = ?, updated_at = now() WHERE id = ?', [self::wrap($pem, $new, $ca['id'], $ca['fingerprint_sha256']), $caId]);
        sodium_memzero($pem);
        Audit::log('ca.passphrase', 'ca:' . $ca['name']);
    }

    /** The CA key as encrypted PKCS#8 PEM, for offline safekeeping. */
    public static function exportKey(string $caId, string $passphrase, string $exportPass, int $userId): string
    {
        $ca = DB::one('SELECT * FROM cas WHERE id = ?', [$caId]);
        $key = self::caKey($ca ?: throw new InvalidArgumentException('Unknown CA.'), $passphrase, $userId);
        openssl_pkey_export($key, $out, $exportPass, ['config' => self::config(), 'encrypt_key_cipher' => OPENSSL_CIPHER_AES_256_CBC]);
        Audit::log('ca.export_key', 'ca:' . $ca['name']);
        return $out;
    }

    /** CAs that nginx trusts, for the revision (public parts only). */
    public static function trustedForRevision(): array
    {
        return array_map(fn($r) => ['id' => $r['id'], 'name' => $r['name'], 'cert_pem' => $r['cert_pem'], 'fingerprint_sha256' => $r['fingerprint_sha256']],
            DB::all('SELECT id, name, cert_pem, fingerprint_sha256 FROM cas WHERE trusted ORDER BY id'));
    }
}
