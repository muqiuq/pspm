<?php
declare(strict_types=1);

/**
 * Settings. The key 'global' holds the static global configuration that becomes part of
 * every revision (plan §7.1). All other keys are runtime settings and take effect at once.
 */
final class Settings
{
    public const GLOBAL_DEFAULTS = [
        'admin_host'       => '',
        'admin_access'     => ['lan', 'cert'],
        'acme_email'       => '',
        'lan_ranges'       => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'],
        'tls_profile'      => 'intermediate',
        'security_headers' => true,
        'hsts'             => ['enabled' => true, 'max_age' => 31536000, 'include_subdomains' => true],
        'rate_standard'    => ['rate' => 100, 'burst' => 200],
        'rate_strict'      => ['rate' => 10, 'burst' => 20],
        'error_pages'      => true,
    ];

    public const RUNTIME_DEFAULTS = [
        'login' => ['max_failures' => 30, 'window_secs' => 3600, 'ban_secs' => 86400],
        'firewall_enforcement' => true,
    ];

    private static array $cache = [];

    public static function global(): array
    {
        $g = self::get('global', []);
        return array_replace(self::GLOBAL_DEFAULTS, is_array($g) ? $g : []);
    }

    public static function saveGlobal(array $g): void
    {
        self::set('global', array_intersect_key($g, self::GLOBAL_DEFAULTS));
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        if (!array_key_exists($key, self::$cache)) {
            $v = DB::val('SELECT value FROM settings WHERE key = ?', [$key]);
            self::$cache[$key] = $v === null ? null : json_dec($v);
        }
        $v = self::$cache[$key];
        if ($v === null) return $default ?? (self::RUNTIME_DEFAULTS[$key] ?? null);
        if (is_array($v) && is_array(self::RUNTIME_DEFAULTS[$key] ?? null)) {
            return array_replace(self::RUNTIME_DEFAULTS[$key], $v);
        }
        return $v;
    }

    public static function set(string $key, mixed $value): void
    {
        DB::q('INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?::jsonb, now(), ?)
               ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now(), updated_by = excluded.updated_by',
            [$key, json_enc($value), Audit::actor()]);
        self::$cache[$key] = $value;
    }
}
