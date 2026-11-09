<?php
declare(strict_types=1);

/**
 * Microsoft sign-in through oauth2-proxy (plan §12). Providers are static configuration
 * (part of every revision, without secrets); install.sh renders their containers.
 */
final class Signin
{
    public const IMAGE = 'quay.io/oauth2-proxy/oauth2-proxy:v7.15.2';
    public const REDIS_IMAGE = 'redis:8.2';
    public const FIRST_PORT = 4181;
    public const HEADERS = ['X-Forwarded-User' => 'user', 'X-Forwarded-Email' => 'email', 'X-Forwarded-Groups' => 'groups',
        'X-Forwarded-Preferred-Username' => 'preferred user name', 'X-Remote-User' => 'e-mail as remote user',
        'X-Forwarded-Access-Token' => 'access token'];

    public static function slug(string $id): string { return 'p' . substr(str_replace('-', '', $id), 0, 8); }

    public static function providers(): array
    {
        $out = [];
        foreach (DB::all('SELECT * FROM oauth_providers ORDER BY name') as $r) {
            $out[$r['id']] = ['id' => $r['id'], 'name' => $r['name'], 'has_secret' => (bool)$r['client_secret_enc'], 'updated_at' => $r['updated_at']] + json_dec($r['config']);
        }
        return $out;
    }

    public static function provider(string $id): ?array { return self::providers()[$id] ?? null; }

    /** For the revision: everything but the secrets. */
    public static function forRevision(): array
    {
        $out = [];
        foreach (self::providers() as $p) { unset($p['has_secret'], $p['updated_at']); $out[] = $p; }
        usort($out, fn($a, $b) => strcmp($a['id'], $b['id']));
        return $out;
    }

    /** @return array{0: array, 1: array<string,string>} */
    public static function validate(array $in): array
    {
        $e = [];
        $guid = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/';
        $p = ['name' => trim((string)($in['name'] ?? ''))];
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._-]{1,47}$/', $p['name'])) $e['name'] = '2–48 letters, digits, space . _ -';
        $p['type'] = 'entra';
        foreach (['tenant_id' => 'Tenant ID', 'client_id' => 'Client (application) ID'] as $k => $l) {
            $p[$k] = strtolower(trim((string)($in[$k] ?? '')));
            if (!preg_match($guid, $p[$k])) $e[$k] = "$l: a GUID like 0000aaaa-11bb-22cc-33dd-444444eeeeee";
        }
        $p['signin_host'] = Validate::host((string)($in['signin_host'] ?? '')) ?? '';
        if ($p['signin_host'] === '') $e['signin_host'] = 'A host name, e.g. auth.example.ch';
        $cd = trim((string)($in['cookie_domain'] ?? ''), " .");
        if ($cd === '' && $p['signin_host'] !== '') $cd = substr($p['signin_host'], strpos($p['signin_host'], '.') + 1);
        $p['cookie_domain'] = Validate::host($cd) ?? '';
        if ($p['cookie_domain'] === '' || ($p['signin_host'] !== '' && !self::under($p['signin_host'], $p['cookie_domain']))) {
            $e['cookie_domain'] = 'The parent domain of the sign-in host and of every site that uses it, e.g. example.ch';
        }
        $doms = [];
        foreach ((array)($in['email_domains'] ?? []) as $d) {
            $d = strtolower(trim((string)$d));
            if ($d === '') continue;
            if ($d === '*') { $doms = ['*']; break; }
            if ($n = Validate::host($d)) $doms[] = $n; else $e['email_domains'] = "Not a domain: $d";
        }
        if (!$doms) $e['email_domains'] ??= 'At least one e-mail domain (or * for any account of the tenant).';
        $p['email_domains'] = array_values(array_unique($doms));
        $p['groups_claim'] = Validate::enum($in['groups_claim'] ?? 'groups', ['groups', 'roles']) ?? 'groups';
        $p['email_claim'] = Validate::enum($in['email_claim'] ?? 'email', ['email', 'preferred_username', 'upn']) ?? 'email';
        $p['session_hours'] = Validate::int($in['session_hours'] ?? 24, 1, 168) ?? 24;
        $p['recheck_minutes'] = Validate::int($in['recheck_minutes'] ?? 60, 5, 1440) ?? 60;
        $p['start_url'] = '';
        if (trim((string)($in['start_url'] ?? '')) !== '') {
            $p['start_url'] = Validate::url((string)$in['start_url']) ?? '';
            if ($p['start_url'] === '') $e['start_url'] = 'A full http(s) URL, or empty for 404.';
        }
        $p['port'] = Validate::int($in['port'] ?? 0, 1024, 65535) ?? 0;
        return [$p, $e];
    }

    public static function under(string $host, string $domain): bool
    {
        return $host === $domain || str_ends_with($host, '.' . $domain);
    }

    public static function save(?string $id, array $p, ?string $clientSecret): array
    {
        if (DB::val('SELECT 1 FROM oauth_providers WHERE name = ?' . ($id ? ' AND id <> ?' : ''), $id ? [$p['name'], $id] : [$p['name']])) {
            return [null, 'A provider with this name exists.'];
        }
        if (Model::hostConflicts([$p['signin_host']], null) || $p['signin_host'] === Settings::global()['admin_host']) {
            return [null, 'The sign-in host name is used by a site or the admin UI.'];
        }
        return DB::tx(function () use ($id, $p, $clientSecret) {
            if ($id) {
                $cur = DB::one('SELECT config FROM oauth_providers WHERE id = ? FOR UPDATE', [$id]);
                if (!$cur) return [null, 'The provider no longer exists.'];
                $p['port'] = (int)(json_dec($cur['config'])['port'] ?? 0);
                $name = $p['name']; unset($p['name']);
                DB::q('UPDATE oauth_providers SET name = ?, config = ?::jsonb, updated_at = now(), updated_by = ? WHERE id = ?', [$name, json_enc($p), Audit::actor(), $id]);
                if ($clientSecret !== null && $clientSecret !== '') DB::q('UPDATE oauth_providers SET client_secret_enc = ? WHERE id = ?', [Crypto::seal($clientSecret), $id]);
                Audit::log('signin.update', "provider:$name", ['secret_changed' => $clientSecret !== null && $clientSecret !== '']);
            } else {
                $id = Crypto::uuid();
                $used = array_map(fn($r) => (int)(json_dec($r['config'])['port'] ?? 0), DB::all('SELECT config FROM oauth_providers'));
                $port = self::FIRST_PORT;
                while (in_array($port, $used, true)) $port++;
                $p['port'] = $port;
                $name = $p['name']; unset($p['name']);
                DB::q('INSERT INTO oauth_providers (id, name, config, client_secret_enc, cookie_secret_enc, updated_by) VALUES (?, ?, ?::jsonb, ?, ?, ?)',
                    [$id, $name, json_enc($p), $clientSecret ? Crypto::seal($clientSecret) : null, Crypto::seal(bin2hex(random_bytes(16))), Audit::actor()]);
                Audit::log('signin.create', "provider:$name");
            }
            return [$id, null];
        });
    }

    /** A new cookie secret ends every session of this provider (after the next apply). */
    public static function rotateCookieSecret(string $id): void
    {
        DB::q('UPDATE oauth_providers SET cookie_secret_enc = ?, updated_at = now() WHERE id = ?', [Crypto::seal(bin2hex(random_bytes(16))), $id]);
        Audit::log('signin.rotate_cookie_secret', "provider:$id");
    }

    public static function users(string $id): array
    {
        $out = [];
        foreach (Model::sites() as $s) if (($s['access']['signin']['provider'] ?? '') === $id) $out[] = $s['hosts'][0];
        return $out;
    }

    /** Environment for the container (install.sh writes it root-only). */
    public static function env(string $id): string
    {
        $r = DB::one('SELECT * FROM oauth_providers WHERE id = ?', [$id]);
        if (!$r) throw new RuntimeException("no provider $id");
        $client = $r['client_secret_enc'] ? Crypto::open($r['client_secret_enc']) : '';
        $cookie = Crypto::open($r['cookie_secret_enc']);
        foreach ([$client, $cookie] as $v) if (preg_match('/[\r\n]/', $v)) throw new RuntimeException('a secret contains a line break');
        return "OAUTH2_PROXY_CLIENT_SECRET=$client\nOAUTH2_PROXY_COOKIE_SECRET=$cookie\n";
    }

    /** Is the provider's container answering? */
    public static function ready(int $port): ?bool
    {
        if ($port <= 0) return null;
        [$code] = http_get_local("http://127.0.0.1:$port/ready", 1.0);
        return $code === 200;
    }

    // ---------------------------------------------------------------- rendering helpers (pure)

    /** oauth2-proxy configuration (TOML) without secrets. */
    public static function config(array $p, array $hosts, bool $passToken): string
    {
        $q = fn(string $s) => '"' . addcslashes($s, "\"\\") . '"';
        $list = fn(array $l) => '[' . implode(', ', array_map($q, $l)) . ']';
        $slug = self::slug($p['id']);
        $hosts = array_values(array_unique(array_merge([$p['signin_host']], $hosts)));
        sort($hosts);
        $lines = [
            '# oauth2-proxy for "' . $p['name'] . '" — rendered by PSPM (plan §12.2). Secrets come from the environment.',
            'http_address = "127.0.0.1:' . $p['port'] . '"',
            'reverse_proxy = true',
            'trusted_proxy_ips = ["127.0.0.1/32"]',
            'upstreams = ["static://202"]',
            'provider = "oidc"',
            'provider_display_name = "Microsoft"',
            'oidc_issuer_url = ' . $q('https://login.microsoftonline.com/' . $p['tenant_id'] . '/v2.0'),
            'client_id = ' . $q($p['client_id']),
            'scope = "openid email profile offline_access"',
            'code_challenge_method = "S256"',
            'redirect_url = ' . $q('https://' . $p['signin_host'] . '/oauth2/callback'),
            'email_domains = ' . $list($p['email_domains']),
            'whitelist_domains = ' . $list($hosts),
            'oidc_groups_claim = ' . $q($p['groups_claim']),
            'oidc_email_claim = ' . $q($p['email_claim']),
            'insecure_oidc_allow_unverified_email = false',
            'cookie_name = ' . $q('_pspm_' . $slug),
            'cookie_domains = ' . $list(['.' . $p['cookie_domain']]),
            'cookie_secure = true',
            'cookie_httponly = true',
            'cookie_samesite = "lax"',
            'cookie_expire = "' . $p['session_hours'] . 'h"',
            'cookie_refresh = "' . $p['recheck_minutes'] . 'm"',
            'cookie_csrf_per_request = true',
            'cookie_csrf_expire = "15m"',
            'session_store_type = "redis"',
            'redis_connection_url = "redis://127.0.0.1:6379"',
            'set_xauthrequest = true',
            'pass_access_token = ' . ($passToken ? 'true' : 'false'),
            'skip_provider_button = true',
            'footer = "-"',
            'request_logging = false',
            'auth_logging = true',
            'standard_logging = true',
        ];
        return implode("\n", $lines) . "\n";
    }

    public static function compose(array $providers): string
    {
        $o = "# Sign-in containers — rendered by PSPM (plan §12.2). install.sh installs this as\n"
           . "# /etc/pspm/oauth2-proxy/compose.yml; the secrets are in the .env files next to it.\n"
           . "name: pspm-signin\nservices:\n"
           . "  redis:\n    image: " . self::REDIS_IMAGE . "\n    container_name: pspm-redis\n    network_mode: host\n    restart: unless-stopped\n"
           . "    env_file: /etc/pspm/oauth2-proxy/redis.env\n    command: [\"redis-server\", \"/usr/local/etc/redis/redis.conf\"]\n"
           . "    volumes:\n      - /etc/pspm/oauth2-proxy/redis.conf:/usr/local/etc/redis/redis.conf:ro\n      - /var/lib/pspm/redis:/data\n"
           . "    healthcheck:\n      test: [\"CMD\", \"redis-cli\", \"-h\", \"127.0.0.1\", \"ping\"]\n      interval: 10s\n      timeout: 3s\n      retries: 5\n";
        foreach ($providers as $p) {
            $s = self::slug($p['id']);
            $o .= "  oauth-$s:\n    # {$p['name']}\n    image: " . self::IMAGE . "\n    container_name: pspm-oauth-$s\n    network_mode: host\n"
                . "    user: \"65532:65532\"\n    read_only: true\n    restart: unless-stopped\n    env_file: /etc/pspm/oauth2-proxy/$s.env\n"
                . "    command: [\"--config=/etc/oauth2-proxy/oauth2-proxy.cfg\"]\n    volumes:\n      - /etc/pspm/oauth2-proxy/$s:/etc/oauth2-proxy:ro\n"
                . "    depends_on:\n      - redis\n";
        }
        return $o;
    }
}
