<?php
declare(strict_types=1);

/**
 * What is really live on this box, read without privileges (plan §5.3), and drift
 * detection (plan §6.8). Nothing here writes; nothing here is used for rendering.
 */
final class Live
{
    public static function releasesDir(): string { return PSPM_NGINX . '/releases'; }

    public static function currentRelease(): ?string
    {
        $t = @readlink(PSPM_NGINX . '/current');
        return $t ? basename($t) : null;
    }

    public static function previousRelease(): ?string
    {
        $j = self::journal();
        return $j['previous'] ?? null;
    }

    public static function journal(): array
    {
        $f = PSPM_VAR . '/apply.journal';
        $out = [];
        if (is_readable($f)) foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
            if (str_contains($l, '=')) { [$k, $v] = explode('=', $l, 2); $out[$k] = $v; }
        }
        return $out;
    }

    public static function dir(?string $rel = null): ?string
    {
        $rel ??= self::currentRelease();
        if (!$rel || !preg_match('/^[A-Za-z0-9._-]+$/', $rel)) return null;
        $d = self::releasesDir() . '/' . $rel;
        return is_dir($d) ? $d : null;
    }

    /** The revision a release was rendered from (its revision.json). */
    public static function revision(?string $rel = null): ?array
    {
        $d = self::dir($rel);
        if (!$d || !is_readable("$d/revision.json")) return null;
        try { return json_dec((string)file_get_contents("$d/revision.json")); } catch (Throwable) { return null; }
    }

    public static function summary(?string $rel = null): ?array
    {
        $d = self::dir($rel);
        if (!$d || !is_readable("$d/summary.json")) return null;
        try { return json_dec((string)file_get_contents("$d/summary.json")); } catch (Throwable) { return null; }
    }

    /** All files of a release, path => content (rendered and static). */
    public static function files(?string $rel = null, bool $renderedOnly = false): array
    {
        $d = self::dir($rel);
        if (!$d) return [];
        $out = [];
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $p = substr($f->getPathname(), strlen($d) + 1);
            if (in_array($p, ['MANIFEST.sha256', 'revision.json', 'summary.json', 'facts.json'], true)) continue;
            if ($renderedOnly && (str_starts_with($p, 'static/') || str_starts_with($p, 'lua/'))) continue;
            $out[$p] = (string)@file_get_contents($f->getPathname());
        }
        ksort($out);
        return $out;
    }

    public static function manifest(?string $rel = null): array
    {
        $d = self::dir($rel);
        $out = [];
        if ($d && is_readable("$d/MANIFEST.sha256")) {
            foreach (file("$d/MANIFEST.sha256", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
                if (preg_match('/^([0-9a-f]{64})\s+\*?(?:\.\/)?(.+)$/', $l, $m)) $out[$m[2]] = $m[1];
            }
        }
        return $out;
    }

    /** nginx master: pid, command line, start time of the newest worker (= last reload). */
    public static function nginxMaster(): ?array
    {
        $pid = (int)trim((string)@file_get_contents('/run/nginx.pid'));
        if ($pid <= 0 || !is_readable("/proc/$pid/cmdline")) return null;
        $cmd = array_values(array_filter(explode("\0", (string)file_get_contents("/proc/$pid/cmdline")), 'strlen'));
        $btime = 0;
        foreach (@file('/proc/stat') ?: [] as $l) if (str_starts_with($l, 'btime ')) $btime = (int)substr($l, 6);
        $newest = 0;
        foreach (glob('/proc/[0-9]*/stat') ?: [] as $f) {
            $st = @file_get_contents($f);
            if (!$st) continue;
            $rest = explode(' ', substr($st, strrpos($st, ')') + 2));
            if ((int)($rest[1] ?? 0) === $pid) $newest = max($newest, $btime + intdiv((int)($rest[19] ?? 0), 100));
        }
        return ['pid' => $pid, 'cmdline' => $cmd, 'workers_started' => $newest ?: null];
    }

    public static function runsPspmConfig(?array $m): bool
    {
        if (!$m) return false;
        $c = implode(' ', $m['cmdline']);
        return str_contains($c, '-p ' . PSPM_NGINX . '/current/') || str_contains($c, '-p ' . PSPM_NGINX . '/current ');
    }

    /** What nginx says it has loaded (loopback endpoint). */
    public static function loadedRelease(): ?string
    {
        [$code, $body] = http_get_local('http://127.0.0.1:9080/pspm-release', 1.5);
        return $code === 200 ? trim($body) : null;
    }

    /**
     * Drift findings. Each: ['level' => 'red'|'amber'|'info', 'check' => …, 'message' => …, 'files' => [...]].
     */
    public static function drift(): array
    {
        $out = [];
        $rel = self::currentRelease();
        if (!$rel) return [['level' => 'info', 'check' => 'release', 'message' => 'No configuration has been applied yet.']];
        $d = self::dir($rel);
        $manifest = self::manifest($rel);
        if (!$manifest) {
            $out[] = ['level' => 'amber', 'check' => 'manifest', 'message' => 'The live release has no manifest; changes cannot be checked.'];
        } else {
            $changed = $added = $missing = [];
            $latest = 0;
            foreach ($manifest as $p => $sha) {
                $f = "$d/$p";
                if (!is_file($f)) { $missing[] = $p; continue; }
                if (hash_file('sha256', $f) !== $sha) { $changed[] = $p; $latest = max($latest, (int)filemtime($f)); }
            }
            foreach (array_keys(self::files($rel)) as $p) if (!isset($manifest[$p])) { $added[] = $p; $latest = max($latest, (int)@filemtime("$d/$p")); }
            if ($changed || $added || $missing) {
                $m = self::nginxMaster();
                $loaded = $m && $m['workers_started'] && $m['workers_started'] >= $latest;
                $out[] = ['level' => 'amber', 'check' => 'files',
                    'message' => 'Files of the live release were changed outside PSPM' . ($loaded ? ' and nginx has loaded them.' : ', not loaded by nginx yet.'),
                    'files' => ['changed' => $changed, 'added' => $added, 'missing' => $missing]];
            }
        }
        $m = self::nginxMaster();
        if (!$m) $out[] = ['level' => 'red', 'check' => 'nginx', 'message' => 'nginx is not running (no master process found).'];
        elseif (!self::runsPspmConfig($m)) $out[] = ['level' => 'red', 'check' => 'nginx', 'message' => 'nginx runs a configuration that is not PSPM\'s: ' . implode(' ', $m['cmdline'])];
        if (!is_readable('/etc/systemd/system/nginx.service.d/pspm.conf')) {
            $out[] = ['level' => 'red', 'check' => 'drop-in', 'message' => 'The systemd drop-in /etc/systemd/system/nginx.service.d/pspm.conf is missing; a restart would start Debian\'s default configuration.'];
        }
        $loaded = self::loadedRelease();
        if ($m && $loaded !== null && $loaded !== $rel) {
            $out[] = ['level' => 'red', 'check' => 'loaded', 'message' => "nginx has release $loaded loaded, but $rel is current on disk."];
        }
        foreach (['/etc/nginx/sites-enabled', '/etc/nginx/conf.d'] as $dd) {
            $extra = array_values(array_filter(glob("$dd/*") ?: [], 'is_file'));
            if ($extra) $out[] = ['level' => 'info', 'check' => 'debian', 'message' => "Files in $dd are not loaded by PSPM: " . implode(', ', array_map('basename', $extra))];
        }
        return $out;
    }

    /** Let's Encrypt certificates, public parts only (plan §5.3). Same shape as the facts. */
    public static function certs(): array
    {
        $out = [];
        foreach (glob('/etc/letsencrypt/live/*/cert.pem') ?: [] as $f) {
            $x = @openssl_x509_parse((string)@file_get_contents($f));
            if (!$x) continue;
            $sans = [];
            foreach (explode(',', $x['extensions']['subjectAltName'] ?? '') as $san) {
                $san = trim($san);
                if (str_starts_with($san, 'DNS:')) $sans[] = strtolower(substr($san, 4));
            }
            $dir = dirname($f);
            $out[] = ['name' => basename($dir), 'fullchain' => "$dir/fullchain.pem", 'key' => "$dir/privkey.pem",
                'sans' => $sans, 'not_after' => gmdate('Y-m-d\TH:i:s\Z', (int)$x['validTo_time_t'])];
        }
        return $out;
    }

    /** Subject, names, issuer, validity, key and SHA-256 fingerprint of one PEM certificate; null if it does not parse. */
    public static function x509Info(string $pem): ?array
    {
        $x = @openssl_x509_parse($pem);
        if (!$x) return null;
        $sans = [];
        foreach (explode(',', $x['extensions']['subjectAltName'] ?? '') as $san) {
            $san = trim($san);
            if (str_starts_with($san, 'DNS:')) $sans[] = strtolower(substr($san, 4));
            elseif (str_starts_with($san, 'IP Address:')) $sans[] = substr($san, 11);
        }
        $key = '';
        if (($pub = @openssl_pkey_get_public($pem)) && ($d = openssl_pkey_get_details($pub))) {
            $key = match ($d['type']) { OPENSSL_KEYTYPE_RSA => 'RSA', OPENSSL_KEYTYPE_EC => 'EC', default => 'other' } . ' ' . $d['bits'];
        }
        $fp = (string)@openssl_x509_fingerprint($pem, 'sha256');
        return ['subject' => (string)($x['subject']['CN'] ?? ''), 'sans' => $sans,
            'issuer' => (string)($x['issuer']['CN'] ?? ($x['issuer']['O'] ?? '')), 'self_signed' => $x['subject'] == $x['issuer'],
            'not_before' => gmdate('Y-m-d\TH:i:s\Z', (int)$x['validFrom_time_t']), 'not_after' => gmdate('Y-m-d\TH:i:s\Z', (int)$x['validTo_time_t']),
            'key' => $key, 'fingerprint' => implode(':', str_split(strtoupper($fp), 2))];
    }

    /**
     * Every certificate the box presents or trusts, for the overview on the Certificates page:
     * Let's Encrypt certificates (with what uses them), the IP certificate, the client CAs
     * nginx trusts and the custom CAs of backends. Each row has a state [level, text].
     */
    public static function serverCertificates(): array
    {
        $now = time();
        $state = function (string $notAfter, int $amberDays, int $redDays = 0) use ($now): array {
            $days = (int)floor((strtotime($notAfter) - $now) / 86400);
            if ($days < 0) return ['red', 'expired'];
            if ($days < $redDays) return ['red', "expires in $days days"];
            if ($days < $amberDays) return ['amber', "expires in $days days"];
            return ['green', 'valid'];
        };
        $sum = self::summary() ?? [];
        $doc = self::revision()['document'] ?? [];
        $rows = [];

        // Let's Encrypt: what nginx uses each one for (the live release's summary)
        foreach (glob('/etc/letsencrypt/live/*/cert.pem') ?: [] as $f) {
            $name = basename(dirname($f));
            $i = self::x509Info((string)@file_get_contents($f));
            if (!$i) continue;
            $used = [];
            foreach ($sum['sites'] ?? [] as $s) if (($s['cert'] ?? null) === $name) $used[] = 'site ' . $s['host'];
            if (($sum['admin']['cert'] ?? null) === $name) $used[] = 'admin UI ' . $sum['admin']['host'];
            foreach ($sum['providers'] ?? [] as $p) {
                $c = $p['cert'] ?? null;   // releases before this field: by the names the certificate covers
                if ($c === $name || ($c === null && Renderer::sanCovers($i['sans'], $p['signin_host']))) $used[] = 'sign-in host ' . $p['signin_host'];
            }
            [$lvl, $txt] = $state($i['not_after'], 25, 7);   // certbot renews 30 days before the end
            if ($lvl === 'amber') $txt .= ' (renewal is overdue)';
            if (!$used && $lvl === 'green') { $lvl = 'grey'; $txt = 'valid, not used'; }
            $rows[] = ['kind' => "Let's Encrypt", 'name' => $name, 'used_by' => array_values(array_unique($used)), 'state' => [$lvl, $txt]] + $i;
        }
        usort($rows, fn($a, $b) => strcmp($a['not_after'], $b['not_after']));

        // the self-signed certificate for the UI by IP address and through the SSH tunnel
        // install.sh copies the public certificate into the status directory ($ETC/tls holds the key and is root-only)
        $ip = is_readable(PSPM_STATUS . '/ip.crt') ? PSPM_STATUS . '/ip.crt' : PSPM_ETC . '/tls/ip.crt';
        if (is_readable($ip) && ($i = self::x509Info((string)file_get_contents($ip)))) {
            $rows[] = ['kind' => 'IP certificate (self-signed)', 'name' => 'ip.crt', 'used_by' => ['admin UI by IP address', 'SSH tunnel (127.0.0.1:9443)'],
                'state' => $state($i['not_after'], 60, 7)] + $i;
        }

        // client CAs nginx trusts, and the custom CAs backends are checked against
        foreach ($doc['cas'] ?? [] as $ca) {
            if (!($i = self::x509Info((string)($ca['cert_pem'] ?? '')))) continue;
            $rows[] = ['kind' => 'Client CA (trusted by nginx)', 'name' => (string)$ca['name'], 'used_by' => ['client certificates of every site'],
                'state' => $state($i['not_after'], 365, 30)] + $i;
        }
        foreach ($doc['backends'] ?? [] as $b) {
            if (($b['tls_verify'] ?? '') !== 'custom') continue;
            preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', (string)($b['custom_ca'] ?? ''), $m);
            foreach ($m[0] as $pem) {
                if (!($i = self::x509Info($pem))) continue;
                $rows[] = ['kind' => 'Backend CA (custom)', 'name' => (string)$b['name'], 'used_by' => ['TLS check of backend ' . $b['name']],
                    'state' => $state($i['not_after'], 30, 7)] + $i;
            }
        }
        return $rows;
    }

    /** Certificates the live release waits for (requested by the next install.sh run), with Let's Encrypt refusals. */
    public static function pendingCertificates(): array
    {
        $fails = Status::read('cert-failures') ?? [];
        $out = [];
        foreach ((self::summary() ?? [])['pending_certs'] ?? [] as $p) {
            $at = isset($fails[$p['name']]) && is_int($fails[$p['name']]) ? $fails[$p['name']] : null;
            $out[] = $p + ['failed_at' => $at ? gmdate('Y-m-d\TH:i:s\Z', $at) : null];
        }
        return $out;
    }

    /**
     * Facts for a preview render: those the live release was rendered with (IPv6, resolved
     * backends, modules …), with fresh certificates. Without them the renderer's defaults
     * would show differences that are not there (e.g. IPv6 listeners on a box without IPv6).
     */
    public static function previewFacts(): array
    {
        $rel = self::currentRelease();
        $f = [];
        if ($rel !== null && is_readable($file = self::releasesDir() . "/$rel/facts.json")) {
            try { $f = (array)(json_dec((string)file_get_contents($file)) ?? []); } catch (Throwable) { $f = []; }
        }
        $certs = self::certs();
        if ($certs || !isset($f['certs'])) $f['certs'] = $certs;
        $f['release'] = 'preview';
        $f['now'] = gmdate('Y-m-d\TH:i:s\Z');
        return $f;
    }
}
