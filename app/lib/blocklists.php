<?php
declare(strict_types=1);

/**
 * External blocklists (plan §14.5): runtime state, fetched by the unprivileged user,
 * validated here and again by the agent. A broken or poisoned download never replaces
 * the last good list.
 */
final class Blocklists
{
    public const MAX_BYTES = 32 * 1024 * 1024;
    public const MAX_ENTRIES = 250000;
    public const MAX_AGE = 7 * 86400;
    public const RESERVED = ['0.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24',
        '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '::/128', '::ffff:0:0/96', '64:ff9b::/96', '100::/64', '2001:db8::/32', 'ff00::/8'];

    public static function dir(): string { return PSPM_STATE . '/blocklists'; }

    public static function all(): array { return DB::all('SELECT * FROM blocklists ORDER BY name'); }

    /** @return array{0: array, 1: array<string,string>} */
    public static function validate(array $in): array
    {
        $e = [];
        $b = ['name' => trim((string)($in['name'] ?? ''))];
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._()-]{1,63}$/', $b['name'])) $e['name'] = '2–64 letters, digits, space . _ ( ) -';
        $b['url'] = trim((string)($in['url'] ?? ''));
        if (!str_starts_with($b['url'], 'https://') || !Validate::url($b['url'])) $e['url'] = 'An https:// URL.';
        $b['format'] = Validate::enum($in['format'] ?? 'plain', ['plain', 'jsonl']) ?? 'plain';
        $b['field'] = preg_match('/^[A-Za-z0-9_.-]{1,40}$/', (string)($in['field'] ?? 'cidr')) ? (string)$in['field'] : 'cidr';
        $b['refresh_hours'] = Validate::int($in['refresh_hours'] ?? 24, 1, 168) ?? 24;
        $b['mode'] = Validate::enum($in['mode'] ?? 'observe', ['block', 'observe']) ?? 'observe';
        $b['enabled'] = (bool)($in['enabled'] ?? true);
        return [$b, $e];
    }

    public static function save(?string $id, array $b, ?string $authHeader): string
    {
        if ($id) {
            DB::q('UPDATE blocklists SET name = ?, url = ?, format = ?, field = ?, refresh_hours = ?, mode = ?, enabled = ?, updated_at = now() WHERE id = ?',
                [$b['name'], $b['url'], $b['format'], $b['field'], $b['refresh_hours'], $b['mode'], $b['enabled'], $id]);
        } else {
            $id = Crypto::uuid();
            DB::q('INSERT INTO blocklists (id, name, url, format, field, refresh_hours, mode, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [$id, $b['name'], $b['url'], $b['format'], $b['field'], $b['refresh_hours'], $b['mode'], $b['enabled']]);
        }
        if ($authHeader !== null) DB::q('UPDATE blocklists SET auth_header_enc = ? WHERE id = ?', [$authHeader === '' ? null : Crypto::seal($authHeader), $id]);
        Audit::log('blocklist.save', 'blocklist:' . $b['name'], ['mode' => $b['mode'], 'enabled' => $b['enabled']]);
        self::writeFile($id);
        return $id;
    }

    public static function delete(string $id): void
    {
        DB::q('DELETE FROM blocklists WHERE id = ?', [$id]);
        @unlink(self::dir() . "/$id.tsv");
        @unlink(self::dir() . "/$id.list");
        @unlink(self::dir() . "/$id.held");
        Audit::log('blocklist.delete', "blocklist:$id");
    }

    /** Parse a downloaded list. Returns [entries (cidr => true), refused count]. */
    public static function parse(string $body, string $format, string $field): array
    {
        $out = []; $refused = 0;
        foreach (preg_split('/\r?\n/', $body) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || $line[0] === ';' || str_starts_with($line, '//')) continue;
            if ($format === 'jsonl') {
                $d = json_decode($line, true);
                $cand = is_array($d) ? (string)($d[$field] ?? '') : '';
            } else {
                $cand = preg_split('/[\s;,]+/', $line)[0] ?? '';
            }
            $n = self::accept($cand);
            if ($n === null) { $refused++; continue; }
            $out[$n] = true;
            if (count($out) > self::MAX_ENTRIES) break;
        }
        return [$out, $refused];
    }

    /** Normalise one entry, or null when it is not acceptable (plan §14.5 step 3). */
    public static function accept(string $c): ?string
    {
        $n = IP::normCidr($c);
        if (!$n) return null;
        [, $len] = explode('/', $n);
        $fam = IP::family($n);
        if (($fam === 4 && (int)$len < 8) || ($fam === 6 && (int)$len < 16)) return null;
        if (IP::neverBlocked($n)) return null;
        foreach (self::RESERVED as $r) if (IP::overlaps($r, $n)) return null;
        return $n;
    }

    /** Fetch every list that is due (or one, forced). */
    public static function run(?string $only = null): array
    {
        $res = [];
        foreach (self::all() as $b) {
            if ($only && $b['id'] !== $only) continue;
            if (!$b['enabled']) { @unlink(self::dir() . "/{$b['id']}.tsv"); continue; }
            $due = !$b['last_fetch_at'] || time() - strtotime($b['last_fetch_at']) >= 3600 * (int)$b['refresh_hours'];
            if (!$due && !$only) { self::writeFile($b['id']); continue; }
            $res[$b['name']] = self::fetch($b);
        }
        return $res;
    }

    private static function fetch(array $b): array
    {
        $headers = ['User-Agent: PSPM-blocklist-fetcher'];
        if ($b['etag']) $headers[] = 'If-None-Match: ' . $b['etag'];
        if ($b['last_modified']) $headers[] = 'If-Modified-Since: ' . $b['last_modified'];
        if ($b['auth_header_enc']) $headers[] = Crypto::open($b['auth_header_enc']);
        $respHeaders = [];
        $ch = curl_init($b['url']);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_ENCODING => '', CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => fn($c, $dlTotal, $dl) => $dl > self::MAX_BYTES ? 1 : 0,
            CURLOPT_HEADERFUNCTION => function ($c, $h) use (&$respHeaders) {
                if (str_contains($h, ':')) { [$k, $v] = explode(':', $h, 2); $respHeaders[strtolower(trim($k))] = trim($v); }
                return strlen($h);
            }]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        $now = gmdate('c');
        $prevCount = (int)(json_dec($b['last_status'])['entries'] ?? 0);
        $status = ['at' => $now, 'http' => $code];
        if ($body === false || ($code !== 200 && $code !== 304)) {
            $status += ['level' => $b['last_ok_at'] && time() - strtotime($b['last_ok_at']) > 2 * 86400 ? 'red' : 'amber',
                'message' => 'download failed: ' . ($err ?: "HTTP $code") . '; the last good list stays (until it is 7 days old)', 'entries' => $prevCount];
            self::record($b, $status, null, false);
            return $status;
        }
        if ($code === 304) {
            $status += ['level' => 'green', 'message' => 'not modified', 'entries' => $prevCount];
            DB::q('UPDATE blocklists SET last_ok_at = now() WHERE id = ?', [$b['id']]);
            self::touchFile($b['id']);
            self::record($b, $status, null, true);
            return $status;
        }
        [$entries, $refused] = self::parse((string)$body, $b['format'], $b['field']);
        $n = count($entries);
        $status += ['entries' => $n, 'refused' => $refused];
        $list = implode("\n", array_keys($entries)) . "\n";
        // sanity: an empty list, or one that shrank by more than half, does not replace the last good one
        if ($n === 0 || ($prevCount > 0 && $n < $prevCount / 2)) {
            write_atomic(self::dir() . "/{$b['id']}.held", $list, 0640);
            $status += ['level' => 'amber', 'message' => "the new list has $n entries (before: $prevCount); kept the last good list. Accept it on the Security page if this is right.", 'held' => $n, 'entries' => $prevCount];
            DB::q("UPDATE blocklists SET held = ?::jsonb WHERE id = ?", [json_enc(['entries' => $n, 'at' => $now]), $b['id']]);
            self::record($b, $status, $n, false);
            return $status;
        }
        @mkdir(self::dir(), 0750, true);
        write_atomic(self::dir() . "/{$b['id']}.list", $list, 0640);
        DB::q('UPDATE blocklists SET etag = ?, last_modified = ?, last_ok_at = now(), held = NULL WHERE id = ?',
            [$respHeaders['etag'] ?? null, $respHeaders['last-modified'] ?? null, $b['id']]);
        $status += ['level' => 'green', 'message' => "$n entries" . ($refused ? ", $refused refused" : '')];
        self::record($b, $status, $n, true);
        self::writeFile($b['id']);
        return $status;
    }

    private static function record(array $b, array $status, ?int $entries, bool $accepted): void
    {
        DB::q('UPDATE blocklists SET last_fetch_at = now(), last_status = ?::jsonb WHERE id = ?', [json_enc($status), $b['id']]);
        DB::q('INSERT INTO blocklist_fetches (blocklist_id, http_status, entries, refused, changed, accepted, error) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [$b['id'], $status['http'] ?? null, $entries ?? ($status['entries'] ?? null), $status['refused'] ?? null, $entries !== null, $accepted,
             ($status['level'] ?? '') === 'green' ? null : ($status['message'] ?? null)]);
        DB::q("DELETE FROM blocklist_fetches WHERE at < now() - interval '30 days'");
    }

    /** "Accept anyway": the held list replaces the current one. */
    public static function acceptHeld(string $id): void
    {
        $held = self::dir() . "/$id.held";
        if (!is_file($held)) throw new InvalidArgumentException('Nothing is held for this list.');
        rename($held, self::dir() . "/$id.list");
        $n = count(file(self::dir() . "/$id.list", FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES) ?: []);
        DB::q("UPDATE blocklists SET held = NULL, last_ok_at = now(), last_status = ?::jsonb WHERE id = ?",
            [json_enc(['at' => gmdate('c'), 'level' => 'green', 'message' => "$n entries (accepted by hand)", 'entries' => $n]), $id]);
        Audit::log('blocklist.accept', "blocklist:$id", ['entries' => $n]);
        self::writeFile($id);
    }

    private static function touchFile(string $id): void
    {
        $f = self::dir() . "/$id.list";
        if (is_file($f)) touch($f);
        self::writeFile($id);
    }

    /** The snapshot the agent reads: header with mode, entries with their expiry (plan §14.5). */
    public static function writeFile(string $id): void
    {
        $b = DB::one('SELECT * FROM blocklists WHERE id = ?', [$id]);
        $list = self::dir() . "/$id.list";
        $tsv = self::dir() . "/$id.tsv";
        if (!$b || !$b['enabled'] || !is_file($list)) { @unlink($tsv); return; }
        $fetched = strtotime($b['last_ok_at'] ?? '') ?: filemtime($list);
        $exp = $fetched + self::MAX_AGE;
        if ($exp <= time()) { @unlink($tsv); return; }
        $out = "# pspm blocklist {$b['name']}\n# mode {$b['mode']}\n# fetched $fetched\n";
        foreach (file($list, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $c) $out .= "$c\t$exp\t-\n";
        write_atomic($tsv, $out, 0640);
    }

    /** Overlap of a list with addresses that pass anyway (trusted, cleared, never-block). */
    public static function overlap(string $id): int
    {
        $list = self::dir() . "/$id.list";
        if (!is_file($list)) return 0;
        $allowed = array_merge(array_column(DB::all('SELECT ip::text AS ip FROM trusted_ips'), 'ip'), array_column(DB::all('SELECT ip::text AS ip FROM cleared_ips'), 'ip'));
        if (!$allowed) return 0;
        $n = 0;
        foreach (file($list, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $c) {
            foreach ($allowed as $a) if (IP::overlaps($a, $c)) { $n++; break; }
            if ($n > 1000) break;
        }
        return $n;
    }
}
