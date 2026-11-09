<?php
declare(strict_types=1);

function h(mixed $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function json_enc(mixed $v, bool $pretty = false): string
{
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;
    return json_encode($v, $pretty ? $flags | JSON_PRETTY_PRINT : $flags);
}

function json_dec(?string $s): mixed
{
    if ($s === null || $s === '') return null;
    return json_decode($s, true, 512, JSON_THROW_ON_ERROR);
}

/** JSON with sorted keys, so equal data gives equal bytes (revisions, exports, hashes). */
function json_canonical(mixed $v, bool $pretty = true): string
{
    return json_enc(ksort_deep($v), $pretty);
}

function ksort_deep(mixed $v): mixed
{
    if (!is_array($v)) return $v;
    if (!array_is_list($v)) ksort($v, SORT_STRING);
    foreach ($v as $k => $x) $v[$k] = ksort_deep($x);
    return $v;
}

/** Write a file atomically: temp file in the same directory, then rename. */
function write_atomic(string $path, string $data, int $mode = 0640): void
{
    $tmp = $path . '.tmp.' . bin2hex(random_bytes(4));
    if (file_put_contents($tmp, $data) === false) throw new RuntimeException("cannot write $tmp");
    chmod($tmp, $mode);
    if (!rename($tmp, $path)) { @unlink($tmp); throw new RuntimeException("cannot rename to $path"); }
}

function now_utc(): DateTimeImmutable
{
    return new DateTimeImmutable('now', new DateTimeZone('UTC'));
}

function fmt_time(?string $ts, string $fmt = 'Y-m-d H:i'): string
{
    if (!$ts) return '—';
    try { return (new DateTimeImmutable($ts))->setTimezone(new DateTimeZone(date_default_timezone_get()))->format($fmt); }
    catch (Throwable) { return h($ts); }
}

function ago(?string $ts): string
{
    if (!$ts) return 'never';
    $d = time() - (new DateTimeImmutable($ts))->getTimestamp();
    if ($d < 0) return 'in ' . human_secs(-$d);
    return human_secs($d) . ' ago';
}

function human_secs(int $s): string
{
    if ($s < 90) return "$s s";
    if ($s < 5400) return round($s / 60) . ' min';
    if ($s < 129600) return round($s / 3600) . ' h';
    return round($s / 86400) . ' d';
}

function human_bytes(int|float $b): string
{
    foreach (['B', 'kB', 'MB', 'GB', 'TB'] as $u) {
        if ($b < 1024 || $u === 'TB') return ($u === 'B' ? (string)(int)$b : sprintf('%.1f', $b)) . " $u";
        $b /= 1024;
    }
    return (string)$b;
}

/** Run a command without a shell. Returns [exit code, stdout, stderr]. */
function run_cmd(array $argv, ?string $stdin = null, int $timeout = 30): array
{
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $p = proc_open($argv, $spec, $pipes);
    if (!is_resource($p)) return [127, '', 'cannot start ' . $argv[0]];
    if ($stdin !== null) fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = $err = '';
    $deadline = microtime(true) + $timeout;
    while (true) {
        $r = [$pipes[1], $pipes[2]]; $w = $e = null;
        if (stream_select($r, $w, $e, 0, 200000) === false) break;
        foreach ($r as $s) {
            $chunk = fread($s, 65536);
            if ($s === $pipes[1]) $out .= $chunk; else $err .= $chunk;
        }
        if (feof($pipes[1]) && feof($pipes[2])) break;
        if (microtime(true) > $deadline) { proc_terminate($p, 9); $err .= "\n(timeout after {$timeout}s)"; break; }
    }
    fclose($pipes[1]); fclose($pipes[2]);
    $code = proc_close($p);
    return [$code, $out, $err];
}

/** Small HTTP GET over loopback (status endpoints of nginx and oauth2-proxy). */
function http_get_local(string $url, float $timeout = 2.0): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => (int)($timeout * 1000),
        CURLOPT_CONNECTTIMEOUT_MS => (int)($timeout * 1000), CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_FOLLOWLOCATION => false]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    return [$code, $body === false ? '' : (string)$body, $err];
}

function slugify(string $s, int $max = 40): string
{
    $s = strtolower(preg_replace('/[^A-Za-z0-9]+/', '-', $s) ?? '');
    return substr(trim($s, '-'), 0, $max) ?: 'x';
}
