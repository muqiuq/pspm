<?php
declare(strict_types=1);

/**
 * The whole configuration as one JSON file (plan §16). Secrets go into an encrypted
 * section (Argon2id + XChaCha20-Poly1305; the associated data is the SHA-256 of the
 * canonical plain part, so changing any byte makes the import fail).
 */
final class Export
{
    public const FORMAT_VERSION = 1;

    /** section => label => [table, primary key, secret columns (column => 'raw'|'seal')] */
    public const SECTIONS = [
        'users'      => ['users' => ['users', 'id', ['password_hash' => 'raw', 'totp_secret_enc' => 'seal']]],
        'settings'   => ['settings' => ['settings', 'key', []]],
        'backends'   => ['backends' => ['backends', 'id', []]],
        'sites'      => ['sites' => ['sites', 'id', []], 'hosts' => ['site_hosts', 'host', []]],
        'revisions'  => ['revisions' => ['config_revisions', 'id', []], 'applies' => ['applies', 'id', []]],
        'access'     => ['links' => ['access_links', 'id', ['token_hash' => 'raw']], 'cleared' => ['cleared_ips', 'scope, ip', []], 'bans' => ['banned_ips', 'ip', []]],
        'signin'     => ['providers' => ['oauth_providers', 'id', ['client_secret_enc' => 'seal', 'cookie_secret_enc' => 'seal']]],
        'pki'        => ['cas' => ['cas', 'id', ['key_wrapped' => 'raw']], 'client_certs' => ['client_certs', 'id', []]],
        'security'   => ['trusted' => ['trusted_ips', 'ip', []], 'blocks' => ['blocks', 'ip', []], 'block_history' => ['block_history', 'id', []],
                         'traps' => ['traps', 'id', []], 'trap_votes' => ['trap_votes', 'trap_id, window_start', []],
                         'expected' => ['expected_patterns', 'actor_type, actor, pattern', []]],
        'blocklists' => ['blocklists' => ['blocklists', 'id', ['auth_header_enc' => 'seal']]],
    ];
    public const HISTORY = ['audit' => ['audit_log', 'id'], 'verdicts' => ['ai_verdicts', 'id'], 'findings' => ['risk_findings', 'id'],
        'baselines' => ['behaviour_baselines', 'actor_type, actor'], 'scan_runs' => ['scan_runs', 'id'], 'activity' => ['ip_activity', 'ip, hour'],
        'behaviour' => ['behaviour_hours', 'actor_type, actor, hour'], 'attack_paths' => ['attack_paths', 'host, path, day'],
        'blocklist_fetches' => ['blocklist_fetches', 'id']];

    private static function jsonbColumns(string $table): array
    {
        return array_column(DB::all("SELECT column_name FROM information_schema.columns WHERE table_name = ? AND data_type = 'jsonb'", [$table]), 'column_name');
    }

    private static function rows(string $table, string $pk): array
    {
        $js = self::jsonbColumns($table);
        $gen = array_flip(self::generatedColumns($table));
        $out = [];
        foreach (DB::all("SELECT * FROM $table ORDER BY $pk") as $r) {
            foreach ($js as $c) if (isset($r[$c])) $r[$c] = json_dec($r[$c]);
            $out[] = array_diff_key($r, $gen);   // derived by the database (e.g. cleared_ips.scope)
        }
        return $out;
    }

    /** Columns the database computes itself; they are neither exported nor inserted. */
    private static function generatedColumns(string $table): array
    {
        return array_column(DB::all("SELECT column_name FROM information_schema.columns WHERE table_name = ? AND is_generated = 'ALWAYS'", [$table]), 'column_name');
    }

    /** @param array|null $tls ['letsencrypt' => base64 tar.gz, 'never_block' => text] (CLI only) */
    public static function build(string $passphrase, bool $history, ?array $tls = null): array
    {
        if ($e = PKI::passphraseProblem($passphrase)) throw new InvalidArgumentException("Export passphrase: $e");
        $doc = ['format' => 'pspm-export', 'format_version' => self::FORMAT_VERSION, 'exported_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'pspm_version' => pspm_version() . ' ' . Status::codeCommit(), 'schema_version' => DB::schemaVersion(),
            'options' => ['history' => $history, 'tls' => $tls !== null]];
        $secrets = [];
        foreach (self::SECTIONS as $section => $tables) {
            foreach ($tables as $label => [$table, $pk, $secretCols]) {
                $rows = self::rows($table, $pk);
                foreach ($rows as &$r) {
                    $rid = implode('|', array_map(fn($c) => (string)$r[trim($c)], explode(',', $pk)));
                    foreach ($secretCols as $col => $how) {
                        if (($r[$col] ?? null) === null) continue;
                        $secrets["$table|$rid|$col"] = $how === 'seal' ? Crypto::open($r[$col]) : $r[$col];
                        $r[$col] = null;
                    }
                    if ($table === 'settings') $r['value'] = self::extractSettingSecrets($r['key'], $r['value'], $secrets);
                }
                unset($r);
                $doc[$section][$label] = $rows;
            }
        }
        if ($history) foreach (self::HISTORY as $label => [$table, $pk]) $doc['history'][$label] = self::rows($table, $pk);
        if ($tls) $secrets['tls'] = $tls;
        $doc = ksort_deep($doc);
        $plain = json_canonical($doc, false);
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $ops = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE; $mem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
        $k = sodium_crypto_pwhash(32, $passphrase, $salt, $ops, $mem, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(json_canonical($secrets, false), hash('sha256', $plain, true), $nonce, $k);
        sodium_memzero($k);
        $doc['secrets'] = ['kdf' => 'argon2id', 'opslimit' => $ops, 'memlimit' => $mem, 'salt' => base64_encode($salt),
            'aead' => 'xchacha20poly1305', 'nonce' => base64_encode($nonce), 'ciphertext' => base64_encode($ct)];
        Audit::log('export', null, ['history' => $history, 'tls' => $tls !== null]);
        return $doc;
    }

    /** Settings values may hold sealed fields (…_enc): their plain value goes into the secrets. */
    private static function extractSettingSecrets(string $key, mixed $value, array &$secrets): mixed
    {
        if (!is_array($value)) return $value;
        foreach ($value as $k => $v) {
            if (is_string($k) && str_ends_with($k, '_enc') && is_string($v) && $v !== '') {
                $secrets["settings|$key|$k"] = Crypto::open($v);
                $value[$k] = '';
            }
        }
        return $value;
    }

    public static function encode(array $doc): string
    {
        return json_canonical($doc, true) . "\n";
    }

    // ---------------------------------------------------------------- import

    /** Check and decrypt a file. Returns [plain document, secrets]. */
    public static function open(string $json, string $passphrase): array
    {
        $doc = json_decode($json, true);
        if (!is_array($doc) || ($doc['format'] ?? '') !== 'pspm-export') throw new InvalidArgumentException('This is not a PSPM export file.');
        if ((int)($doc['format_version'] ?? 0) > self::FORMAT_VERSION) throw new InvalidArgumentException('This file comes from a newer PSPM; update this box first.');
        if ((int)($doc['schema_version'] ?? 0) > DB::schemaVersion()) throw new InvalidArgumentException('The file needs a newer database schema; update this box first.');
        $s = $doc['secrets'] ?? null;
        unset($doc['secrets']);
        if (!is_array($s) || ($s['kdf'] ?? '') !== 'argon2id' || ($s['aead'] ?? '') !== 'xchacha20poly1305') throw new InvalidArgumentException('The encrypted part is missing or unknown.');
        $plain = json_canonical($doc, false);
        $k = sodium_crypto_pwhash(32, $passphrase, base64_decode($s['salt']), (int)$s['opslimit'], (int)$s['memlimit'], SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $sec = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(base64_decode($s['ciphertext']), hash('sha256', $plain, true), base64_decode($s['nonce']), $k);
        sodium_memzero($k);
        if ($sec === false) throw new InvalidArgumentException('Wrong passphrase, or the file was changed after the export.');
        return [$doc, json_decode($sec, true) ?: []];
    }

    /** What an import would change. */
    public static function preview(array $doc, array $secrets, string $importer): array
    {
        $p = ['counts' => [], 'users' => [], 'conflicts' => [], 'tls' => isset($secrets['tls']), 'exported_at' => $doc['exported_at'] ?? '?'];
        foreach (self::SECTIONS as $section => $tables) foreach ($tables as $label => [$table]) $p['counts']["$section.$label"] = count($doc[$section][$label] ?? []);
        foreach ($doc['history'] ?? [] as $label => $rows) $p['counts']["history.$label"] = count($rows);
        $cur = array_column(DB::all('SELECT username, role FROM users'), 'role', 'username');
        foreach ($doc['users']['users'] ?? [] as $u) {
            $p['users'][] = $u['username'] . ' (' . $u['role'] . ')' . (isset($cur[$u['username']]) ? ($u['username'] === $importer ? ' — you: kept as is' : ' — replaced') : ' — added');
        }
        foreach (array_diff(array_keys($cur), array_column($doc['users']['users'] ?? [], 'username')) as $gone) {
            if ($gone !== $importer) $p['users'][] = "$gone — removed (not in the file)";
        }
        $siteHosts = array_column($doc['sites']['hosts'] ?? [], 'host');
        $admin = '';
        foreach ($doc['settings']['settings'] ?? [] as $s) if ($s['key'] === 'global') $admin = $s['value']['admin_host'] ?? '';
        if ($admin !== '' && in_array($admin, $siteHosts, true)) $p['conflicts'][] = "The admin host name $admin is also a site.";
        $working = Model::document();
        $p['diff'] = [
            'sites' => [count($working['sites']), count($doc['sites']['sites'] ?? [])],
            'backends' => [count($working['backends']), count($doc['backends']['backends'] ?? [])],
        ];
        return $p;
    }

    /**
     * Replace everything with the file, in one transaction. The importing admin's account is
     * never deleted or demoted. Static configuration lands in the working copy; runtime
     * state takes effect at once.
     */
    public static function apply(array $doc, array $secrets, string $importer): array
    {
        $order = [];
        foreach (self::SECTIONS as $section => $tables) foreach ($tables as $label => $t) $order[] = [$section, $label, ...$t];
        $hist = [];
        foreach (self::HISTORY as $label => [$table, $pk]) if (isset($doc['history'][$label])) $hist[] = ['history', $label, $table, $pk, []];
        $stats = [];
        DB::tx(function () use ($order, $hist, $doc, $secrets, $importer, &$stats) {
            $all = array_merge($order, $hist);
            foreach (array_reverse($all) as [$section, $label, $table]) {
                if ($table === 'users') DB::q('DELETE FROM users WHERE username <> ?', [$importer]);
                elseif ($table === 'settings') DB::q('DELETE FROM settings');
                else DB::q("DELETE FROM $table");
            }
            foreach ($all as [$section, $label, $table, $pk, $secretCols]) {
                $js = self::jsonbColumns($table);
                $gen = self::generatedColumns($table);
                $n = 0;
                foreach ($doc[$section][$label] ?? [] as $r) {
                    if ($table === 'users' && $r['username'] === $importer) continue;
                    $rid = implode('|', array_map(fn($c) => (string)$r[trim($c)], explode(',', $pk)));
                    foreach ($secretCols as $col => $how) {
                        $v = $secrets["$table|$rid|$col"] ?? null;
                        $r[$col] = $v === null ? null : ($how === 'seal' ? Crypto::seal((string)$v) : $v);
                    }
                    if ($table === 'settings' && is_array($r['value'])) {
                        foreach ($r['value'] as $k => $v) if (is_string($k) && str_ends_with($k, '_enc') && isset($secrets["settings|{$r['key']}|$k"])) {
                            $r['value'][$k] = Crypto::seal((string)$secrets["settings|{$r['key']}|$k"]);
                        }
                    }
                    // keep ids (round trip); only a user whose id is the importer's gets a new one
                    if ($table === 'users' && (string)$r['id'] === (string)DB::val('SELECT id FROM users WHERE username = ?', [$importer])) unset($r['id']);
                    foreach ($js as $c) if (array_key_exists($c, $r)) $r[$c] = $r[$c] === null ? null : json_enc($r[$c]);
                    foreach ($gen as $c) unset($r[$c]);   // older files never had them; newer ones leave them out
                    $cols = array_keys($r);
                    DB::q("INSERT INTO $table (" . implode(', ', $cols) . ') VALUES (' . implode(', ', array_map(fn($c) => ":$c", $cols)) . ')', $r);
                    $n++;
                }
                $stats["$section.$label"] = $n;
                foreach (DB::all("SELECT column_name FROM information_schema.columns WHERE table_name = ? AND column_default LIKE 'nextval%'", [$table]) as $c) {
                    DB::val("SELECT setval(pg_get_serial_sequence(?, ?), greatest(coalesce((SELECT max({$c['column_name']}) FROM $table), 0), 1))", [$table, $c['column_name']]);
                }
            }
            // the importing admin stays an admin
            DB::q("UPDATE users SET role = 'admin', disabled = false WHERE username = ?", [$importer]);
        });
        Audit::log('import', null, ['exported_at' => $doc['exported_at'] ?? null, 'counts' => $stats]);
        try { State::publish(); } catch (Throwable) {}
        foreach (Blocklists::all() as $b) DB::q('UPDATE blocklists SET last_fetch_at = NULL WHERE id = ?', [$b['id']]);
        return $stats;
    }
}
