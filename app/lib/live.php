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
