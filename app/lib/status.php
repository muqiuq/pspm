<?php
declare(strict_types=1);

/** Status JSON written by root (install.sh, agent) into /var/lib/pspm/status/. */
final class Status
{
    public static function read(string $name): ?array
    {
        $f = PSPM_STATUS . '/' . basename($name) . '.json';
        if (!is_readable($f)) return null;
        try {
            $d = json_dec((string)file_get_contents($f));
            if (is_array($d)) $d['_age'] = time() - (int)filemtime($f);
            return is_array($d) ? $d : null;
        } catch (Throwable) { return null; }
    }

    /** Age in seconds, or null when missing. */
    public static function age(string $name): ?int
    {
        $f = PSPM_STATUS . '/' . basename($name) . '.json';
        return is_file($f) ? time() - (int)filemtime($f) : null;
    }

    /** What the agent's last firewall report says is wrong, in one sentence; null when nothing is. */
    public static function firewallProblem(?array $fw): ?string
    {
        if (!$fw) return null;
        $errors = array_values(array_filter((array)($fw['errors'] ?? []), 'is_string'));
        $failed = array_keys(array_filter((array)($fw['sets'] ?? []), fn($n) => $n === -1));
        $broken = array_keys(array_filter((array)($fw['rules'] ?? []), fn($s) => $s === 'error'));
        if (!$errors && !$failed && !$broken) return null;
        $first = $errors ? mb_substr($errors[0], 0, 300) . (count($errors) > 1 ? ' (and ' . (count($errors) - 1) . ' more)' : '') : '';
        if ($broken) return 'The firewall chain could not be set up (' . implode(', ', $broken) . '): ' . $first . ' nginx still blocks.';
        if ($failed) return 'The firewall works, but ' . (count($failed) === 1 ? 'set ' : 'sets ') . implode(', ', $failed)
            . ' could not be loaded: ' . $first . ' (sudo journalctl -u pspm-agent)';
        return "The firewall agent reports: $first";
    }

    public static function unitActive(string $unit): ?bool
    {
        if (!is_executable('/usr/bin/systemctl')) return null;
        [$code, $out] = run_cmd(['/usr/bin/systemctl', 'is-active', $unit], null, 3);
        return trim($out) === 'active';
    }

    public static function diskFree(string $path = '/'): ?array
    {
        $free = @disk_free_space($path); $total = @disk_total_space($path);
        return $free && $total ? ['free' => $free, 'total' => $total, 'pct_used' => round(100 - 100 * $free / $total)] : null;
    }

    public static function codeCommit(): string
    {
        $f = PSPM_APP . '/COMMIT';
        return is_readable($f) ? trim((string)file_get_contents($f)) : 'unknown';
    }
}
