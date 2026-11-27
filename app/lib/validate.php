<?php
declare(strict_types=1);

/**
 * Validation and normalisation of the configuration model (plan §7.6). The DB is written
 * by the web user, so the renderer runs these checks again on every revision. No field
 * ever carries raw nginx syntax, and '$' is never accepted.
 */
final class Validate
{
    public const CONDITIONS = ['lan', 'cleared', 'cert', 'public'];
    public const RESERVED_PORTS = [80, 443, 9443, 9080];
    public const HEADER_VALUE_TYPES = ['text', 'client_addr', 'scheme', 'host', 'request_id', 'client_cert_fp'];
    public const PRESETS = [
        'cert'           => ['Certificate', ['cert']],
        'cleared_cert'   => ['Cleared or certificate', ['cleared', 'cert']],
        'lan_cleared_cert' => ['LAN, cleared or certificate', ['lan', 'cleared', 'cert']],
        'lan_cleared'    => ['LAN or cleared', ['lan', 'cleared']],
        'cleared'        => ['Cleared only', ['cleared']],
        'lan'            => ['LAN only', ['lan']],
        'public'         => ['Public', ['public']],
    ];

    // ---------------------------------------------------------------- primitives

    public static function host(string $h): ?string
    {
        $h = strtolower(trim($h));
        if ($h === '' || IP::valid($h)) return null;
        if (function_exists('idn_to_ascii') && preg_match('/[^\x20-\x7e]/', $h)) {
            $h = idn_to_ascii($h, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46) ?: '';
        }
        if (strlen($h) > 253 || !str_contains($h, '.')) return null;
        foreach (explode('.', $h) as $label) {
            if (!preg_match('/^(?!-)[a-z0-9-]{1,63}(?<!-)$/', $label)) return null;
        }
        if (preg_match('/^\d+$/', substr($h, strrpos($h, '.') + 1))) return null; // TLD must not be numeric
        return $h;
    }

    public static function path(string $p): ?string
    {
        $p = trim($p);
        if ($p === '' || $p[0] !== '/' || strlen($p) > 512) return null;
        if (!preg_match('#^/[A-Za-z0-9._~!*\'()@:+,=&%/-]*$#', $p)) return null;   // no space, quotes, braces, ; $ ? #
        if (str_starts_with($p, '/.pspm/') || $p === '/.pspm') return null;         // reserved for access links
        return $p;
    }

    public static function headerName(string $n): ?string
    {
        $n = trim($n);
        return preg_match('/^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/', $n) ? $n : null;
    }

    public static function headerValue(string $v): ?string
    {
        return strlen($v) <= 1024 && preg_match('/^[\x20-\x7e]*$/', $v) && !preg_match('/["\\\\$]/', $v) ? $v : null;
    }

    public static function url(string $u): ?string
    {
        $u = trim($u);
        if (strlen($u) > 1024 || preg_match('/[\s"\\\\$<>{}]/', $u)) return null;
        $p = parse_url($u);
        if (!$p || !in_array($p['scheme'] ?? '', ['http', 'https'], true) || empty($p['host'])) return null;
        if (!self::host($p['host']) && !IP::valid(trim($p['host'], '[]'))) return null;
        return $u;
    }

    public static function email(string $e): ?string
    {
        $e = trim($e);
        return $e !== '' && strlen($e) <= 254 && filter_var($e, FILTER_VALIDATE_EMAIL) && !preg_match('/["\\\\$\s]/', $e) ? $e : null;
    }

    /** "0" (unlimited), "512k", "10m", "2g"; at most 100g. Returns the normalised string. */
    public static function size(string $s): ?string
    {
        $s = strtolower(trim($s));
        if (!preg_match('/^(\d{1,6})([kmg]?)$/', $s, $m)) return null;
        $bytes = (int)$m[1] * ['' => 1, 'k' => 1024, 'm' => 1 << 20, 'g' => 1 << 30][$m[2]];
        return $bytes <= 100 * (1 << 30) ? $m[1] . $m[2] : null;
    }

    public static function int(mixed $v, int $min, int $max): ?int
    {
        if (is_string($v)) $v = trim($v);
        if (!is_int($v) && !(is_string($v) && preg_match('/^-?\d+$/', $v))) return null;
        $v = (int)$v;
        return $v >= $min && $v <= $max ? $v : null;
    }

    public static function enum(mixed $v, array $allowed): ?string
    {
        return is_string($v) && in_array($v, $allowed, true) ? $v : null;
    }

    public static function uuid(mixed $v): ?string
    {
        return is_string($v) && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $v) ? $v : null;
    }

    /** host:port for a backend server: IPv4, [IPv6] or a host name. */
    public static function serverAddr(string $s): ?string
    {
        $s = trim($s);
        if (preg_match('/^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/', $s, $m)) {
            return IP::valid($m[1]) && self::int($m[2], 1, 65535) ? '[' . strtolower($m[1]) . ']:' . (int)$m[2] : null;
        }
        if (!preg_match('/^([A-Za-z0-9.-]+):(\d{1,5})$/', $s, $m) || !self::int($m[2], 1, 65535)) return null;
        $h = IP::valid($m[1]) ? $m[1] : (self::host($m[1]) ?? (preg_match('/^[a-z0-9-]{1,63}$/i', $m[1]) ? strtolower($m[1]) : null));
        return $h ? "$h:" . (int)$m[2] : null;
    }

    public static function cidr(string $c): ?string
    {
        return IP::normCidr($c);
    }

    // ---------------------------------------------------------------- global settings

    /** @return array{0: array, 1: array<string,string>} */
    public static function global(array $in): array
    {
        $e = [];
        $g = Settings::GLOBAL_DEFAULTS;
        $ah = trim((string)($in['admin_host'] ?? ''));
        if ($ah !== '') { $g['admin_host'] = self::host($ah) ?? ''; if ($g['admin_host'] === '') $e['admin_host'] = 'Not a valid host name.'; }
        $aa = array_values(array_intersect(['lan', 'cleared', 'cert', 'public'], (array)($in['admin_access'] ?? [])));
        if (!$aa) $e['admin_access'] = 'Choose at least one condition.';
        $g['admin_access'] = $aa ?: ['lan'];
        $em = trim((string)($in['acme_email'] ?? ''));
        if ($em !== '') { $g['acme_email'] = self::email($em) ?? ''; if ($g['acme_email'] === '') $e['acme_email'] = 'Not a valid e-mail address.'; }
        $lan = [];
        foreach ((array)($in['lan_ranges'] ?? []) as $r) {
            if (trim((string)$r) === '') continue;
            $n = self::cidr((string)$r);
            if (!$n) { $e['lan_ranges'] = "Not a network: $r"; continue; }
            $lan[] = $n;
        }
        $g['lan_ranges'] = array_values(array_unique($lan));
        $g['tls_profile'] = self::enum($in['tls_profile'] ?? '', ['intermediate', 'modern']) ?? 'intermediate';
        $g['security_headers'] = (bool)($in['security_headers'] ?? true);
        $g['error_pages'] = (bool)($in['error_pages'] ?? true);
        $h = (array)($in['hsts'] ?? []);
        $g['hsts'] = ['enabled' => (bool)($h['enabled'] ?? true),
            'max_age' => self::int($h['max_age'] ?? 31536000, 0, 63072000) ?? 31536000,
            'include_subdomains' => (bool)($h['include_subdomains'] ?? true)];
        foreach (['rate_standard' => [100, 200], 'rate_strict' => [10, 20]] as $k => [$dr, $db]) {
            $r = (array)($in[$k] ?? []);
            $g[$k] = ['rate' => self::int($r['rate'] ?? $dr, 1, 100000) ?? $dr, 'burst' => self::int($r['burst'] ?? $db, 0, 100000) ?? $db];
        }
        return [$g, $e];
    }

    // ---------------------------------------------------------------- backends

    /** @return array{0: array, 1: array<string,string>} */
    /** Response header buffer sizes a backend can choose (KB); the default is also set in http.conf. */
    public const HEADER_BUFFERS = [16, 32, 64, 128];
    public const HEADER_BUFFER_DEFAULT = 16;

    public static function backend(array $in): array
    {
        $e = [];
        $b = ['name' => trim((string)($in['name'] ?? ''))];
        if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,47}$/', $b['name'])) $e['name'] = 'Lower-case letters, digits, - and _ (max. 48).';
        $b['protocol'] = self::enum($in['protocol'] ?? 'http', ['http', 'https']) ?? 'http';
        $b['tls_verify'] = self::enum($in['tls_verify'] ?? 'off', ['off', 'system', 'custom']) ?? 'off';
        $b['tls_name'] = '';
        if (($tn = trim((string)($in['tls_name'] ?? ''))) !== '') {
            $b['tls_name'] = self::host($tn) ?? '';
            if ($b['tls_name'] === '') $e['tls_name'] = 'Not a valid host name.';
        }
        $b['custom_ca'] = '';
        if ($b['tls_verify'] === 'custom') {
            $pem = trim((string)($in['custom_ca'] ?? ''));
            if (!preg_match('/^-----BEGIN CERTIFICATE-----[A-Za-z0-9+\/=\s-]+-----END CERTIFICATE-----$/', $pem)
                || openssl_x509_read($pem) === false) {
                $e['custom_ca'] = 'Paste one or more PEM certificates.';
            } else {
                $b['custom_ca'] = $pem;
            }
        }
        $b['keepalive'] = self::int($in['keepalive'] ?? 16, 0, 1024) ?? 16;
        // Room for the response headers of this application (proxy_buffer_size, in KB); larger
        // headers make nginx answer 502 "upstream sent too big header". Older backends: default.
        $hb = trim((string)($in['header_buffer'] ?? ''));
        if ($hb === '') $hb = (string)self::HEADER_BUFFER_DEFAULT;   // not sent (older form): the default
        $b['header_buffer'] = in_array($hb, array_map('strval', self::HEADER_BUFFERS), true) ? (int)$hb : self::HEADER_BUFFER_DEFAULT;
        if ($b['header_buffer'] !== (int)$hb) $e['header_buffer'] = 'One of ' . implode(', ', array_map(fn($k) => "{$k}k", self::HEADER_BUFFERS)) . '.';
        $b['servers'] = [];
        foreach ((array)($in['servers'] ?? []) as $i => $s) {
            if (!is_array($s) || trim((string)($s['addr'] ?? '')) === '') continue;
            $addr = self::serverAddr((string)$s['addr']);
            if (!$addr) { $e["servers.$i"] = 'host:port, e.g. 10.0.0.5:8080 or [2001:db8::5]:443'; continue; }
            $b['servers'][] = ['addr' => $addr,
                'weight' => self::int($s['weight'] ?? 1, 1, 100) ?? 1,
                'backup' => (bool)($s['backup'] ?? false),
                'max_fails' => self::int($s['max_fails'] ?? 1, 0, 100) ?? 1,
                'fail_timeout' => self::int($s['fail_timeout'] ?? 10, 1, 3600) ?? 10];
        }
        if (!$b['servers']) $e['servers'] = 'At least one server.';
        return [$b, $e];
    }

    // ---------------------------------------------------------------- sites

    public static function defaultSite(): array
    {
        return [
            'enabled' => true, 'description' => '', 'hosts' => [],
            'tls' => ['mode' => 'letsencrypt', 'profile' => 'default', 'http2' => true,
                'hsts' => ['mode' => 'default', 'max_age' => 31536000, 'include_subdomains' => true, 'preload' => false]],
            'port80' => 'redirect',
            'client_certs' => 'optional',
            'access' => ['conditions' => ['lan', 'cleared', 'cert'], 'denied' => '403', 'denied_url' => '',
                'signin' => ['mode' => 'none', 'provider' => '', 'groups' => [], 'emails' => [], 'domains' => [],
                    'headers' => ['X-Forwarded-User', 'X-Forwarded-Email', 'X-Remote-User'], 'pass_token' => false, 'nonbrowser_401' => true]],
            'limits' => ['max_body' => '10m', 'rate' => 'standard', 'limit_conn' => 0],
            'proxy' => ['backend' => '', 'host_header' => 'client', 'host_fixed' => '', 'connect_timeout' => 10,
                'read_timeout' => 60, 'send_timeout' => 60, 'websocket' => true,
                'request_buffering' => true, 'response_buffering' => true],
            'headers' => ['request' => [], 'response' => [], 'hide' => [], 'security' => 'default'],
            'listeners' => [],
            'routes' => [['id' => 'r1', 'match' => 'prefix', 'paths' => ['/'], 'listeners' => ['all'],
                'action' => 'proxy', 'status' => 404, 'redirect_url' => '', 'redirect_code' => 302, 'overrides' => []]],
        ];
    }

    /**
     * @param array $backendIds ids of existing backends
     * @return array{0: array, 1: array<string,string>}
     */
    public static function site(array $in, array $backendIds): array
    {
        $e = [];
        $d = self::defaultSite();
        $s = ['enabled' => (bool)($in['enabled'] ?? false), 'description' => mb_substr(trim((string)($in['description'] ?? '')), 0, 200)];
        if (preg_match('/[\x00-\x1f]/', $s['description'])) $s['description'] = '';

        $hosts = [];
        foreach ((array)($in['hosts'] ?? []) as $i => $h) {
            if (trim((string)$h) === '') continue;
            $n = self::host((string)$h);
            if (!$n) { $e['hosts'] = 'Not a valid host name: ' . $h; continue; }
            $hosts[] = $n;
        }
        $s['hosts'] = array_values(array_unique($hosts));
        if (!$s['hosts']) $e['hosts'] ??= 'At least one host name.';
        if (count($s['hosts']) > 50) $e['hosts'] = 'At most 50 host names per site.';

        $t = (array)($in['tls'] ?? []);
        $hs = (array)($t['hsts'] ?? []);
        $s['tls'] = [
            'mode' => self::enum($t['mode'] ?? '', ['letsencrypt', 'none']) ?? 'letsencrypt',
            'profile' => self::enum($t['profile'] ?? '', ['default', 'intermediate', 'modern']) ?? 'default',
            'http2' => (bool)($t['http2'] ?? true),
            'hsts' => ['mode' => self::enum($hs['mode'] ?? '', ['default', 'off', 'on']) ?? 'default',
                'max_age' => self::int($hs['max_age'] ?? 31536000, 0, 63072000) ?? 31536000,
                'include_subdomains' => (bool)($hs['include_subdomains'] ?? true), 'preload' => (bool)($hs['preload'] ?? false)],
        ];
        $s['port80'] = self::enum($in['port80'] ?? '', ['redirect', 'serve', 'acme_only']) ?? 'redirect';
        if ($s['tls']['mode'] === 'none') $s['port80'] = 'serve';
        $s['client_certs'] = self::enum($in['client_certs'] ?? '', ['optional', 'off']) ?? 'optional';

        [$s['access'], $ae] = self::access((array)($in['access'] ?? []), true);
        foreach ($ae as $k => $v) $e["access.$k"] = $v;
        if (in_array('cert', $s['access']['conditions'], true) && $s['client_certs'] === 'off') {
            $e['client_certs'] = 'The policy uses certificates, so they must be requested.';
        }

        $l = (array)($in['limits'] ?? []);
        $s['limits'] = ['max_body' => self::size((string)($l['max_body'] ?? '10m')) ?? '',
            'rate' => self::enum($l['rate'] ?? '', ['off', 'standard', 'strict']) ?? 'standard',
            'limit_conn' => self::int($l['limit_conn'] ?? 0, 0, 100000) ?? 0];
        if ($s['limits']['max_body'] === '') { $e['limits.max_body'] = 'e.g. 10m, 512k, 2g or 0 (unlimited); at most 100g.'; $s['limits']['max_body'] = '10m'; }

        [$s['proxy'], $pe] = self::proxy((array)($in['proxy'] ?? []), $backendIds, true);
        foreach ($pe as $k => $v) $e["proxy.$k"] = $v;

        $hd = (array)($in['headers'] ?? []);
        $s['headers'] = ['request' => [], 'response' => [], 'hide' => [],
            'security' => self::enum($hd['security'] ?? '', ['default', 'off']) ?? 'default'];
        foreach ((array)($hd['request'] ?? []) as $i => $r) {
            if (!is_array($r) || trim((string)($r['name'] ?? '')) === '') continue;
            $n = self::headerName((string)$r['name']);
            $type = self::enum($r['type'] ?? 'text', self::HEADER_VALUE_TYPES) ?? 'text';
            $v = $type === 'text' ? self::headerValue((string)($r['value'] ?? '')) : '';
            if (!$n || $v === null) { $e["headers.request.$i"] = 'Header name: letters, digits, -. Value: printable ASCII without " \\ $.'; continue; }
            if (in_array(strtolower($n), ['host', 'x-forwarded-user', 'x-forwarded-email', 'x-forwarded-groups',
                'x-forwarded-preferred-username', 'x-remote-user', 'x-forwarded-access-token', 'connection', 'upgrade'], true)) {
                $e["headers.request.$i"] = "$n is set by PSPM."; continue;
            }
            $s['headers']['request'][] = ['name' => $n, 'type' => $type, 'value' => $v];
        }
        foreach ((array)($hd['response'] ?? []) as $i => $r) {
            if (!is_array($r) || trim((string)($r['name'] ?? '')) === '') continue;
            $n = self::headerName((string)$r['name']);
            $v = self::headerValue((string)($r['value'] ?? ''));
            if (!$n || $v === null || $v === '') { $e["headers.response.$i"] = 'Header name and a value (printable ASCII without " \\ $).'; continue; }
            $s['headers']['response'][] = ['name' => $n, 'value' => $v];
        }
        foreach ((array)($hd['hide'] ?? []) as $n) {
            if (trim((string)$n) === '') continue;
            $n = self::headerName((string)$n);
            if ($n) $s['headers']['hide'][] = $n; else $e['headers.hide'] = 'Not a header name.';
        }
        $s['headers']['hide'] = array_values(array_unique($s['headers']['hide']));

        $s['listeners'] = [];
        foreach ((array)($in['listeners'] ?? []) as $i => $li) {
            if (!is_array($li) || trim((string)($li['port'] ?? '')) === '') continue;
            $p = self::int($li['port'], 1, 65535);
            if (!$p || in_array($p, self::RESERVED_PORTS, true)) { $e["listeners.$i"] = 'A port 1–65535 other than 80, 443, 9080, 9443.'; continue; }
            $s['listeners'][] = ['port' => $p, 'tls' => (bool)($li['tls'] ?? false)];
        }
        $ports = array_column($s['listeners'], 'port');
        if (count($ports) !== count(array_unique($ports))) $e['listeners'] = 'Each port only once.';
        if ($s['tls']['mode'] === 'none') foreach ($s['listeners'] as $li) if ($li['tls']) $e['listeners'] = 'A site without TLS cannot have a TLS listener.';

        $s['routes'] = [];
        $seen = [];
        $validListeners = array_merge(['all', 'https', 'http'], array_map(fn($li) => 'port:' . $li['port'], $s['listeners']));
        foreach (array_values((array)($in['routes'] ?? [])) as $i => $r) {
            if (!is_array($r)) continue;
            $paths = [];
            foreach ((array)($r['paths'] ?? []) as $p) {
                if (trim((string)$p) === '') continue;
                $np = self::path((string)$p);
                if (!$np) { $e["routes.$i.paths"] = "Not an allowed path: $p (must start with /; no spaces, quotes, braces, ; \$ ? #; /.pspm/ is reserved)"; continue; }
                $paths[] = $np;
            }
            if (!$paths) { $e["routes.$i.paths"] ??= 'At least one path.'; continue; }
            $match = self::enum($r['match'] ?? 'prefix', ['prefix', 'exact']) ?? 'prefix';
            // without the prefix to the backend: the path ends in / (so /site1 does not take /site1abc; /site1 redirects to /site1/)
            $strip = !empty($r['strip_prefix']);
            if ($strip && $match === 'prefix') $paths = array_values(array_unique(array_map(fn($p) => rtrim($p, '/') . '/', $paths)));
            foreach ($paths as $p) {
                $key = "$match $p";
                if (isset($seen[$key])) $e["routes.$i.paths"] = "Path $p appears twice.";
                $seen[$key] = true;
            }
            $ls = array_values(array_intersect($validListeners, (array)($r['listeners'] ?? ['all'])));
            $route = [
                'id' => preg_match('/^[a-z0-9]{1,16}$/', (string)($r['id'] ?? '')) ? $r['id'] : 'r' . ($i + 1),
                'match' => $match, 'paths' => array_values(array_unique($paths)), 'listeners' => $ls ?: ['all'],
                'action' => self::enum($r['action'] ?? 'proxy', ['proxy', 'status', 'redirect', 'acme_proxy']) ?? 'proxy',
                'status' => self::int($r['status'] ?? 404, 200, 599) ?? 404,
                'redirect_url' => '', 'redirect_code' => self::int($r['redirect_code'] ?? 302, 301, 308) ?? 302,
                'overrides' => [],
            ];
            if (!in_array($route['redirect_code'], [301, 302, 303, 307, 308], true)) $route['redirect_code'] = 302;
            if ($route['action'] === 'acme_proxy') {
                $route['match'] = 'prefix';
                $route['paths'] = ['/.well-known/acme-challenge/'];
            } else {
                foreach ($route['paths'] as $p) {
                    if (str_starts_with($p, '/.well-known/acme-challenge')) $e["routes.$i.paths"] = 'The ACME path is handled by PSPM; use the action "proxy the ACME challenge" to hand it to the backend.';
                }
            }
            if ($strip) {
                // stored only when set: routes of existing installations stay exactly as they are
                if ($route['match'] !== 'prefix' || $route['action'] !== 'proxy') $e["routes.$i.strip_prefix"] = 'Only a prefix route that proxies to a backend can pass the path without its prefix.';
                elseif (in_array('/', $route['paths'], true)) $e["routes.$i.strip_prefix"] = 'There is no prefix to remove from /: use a path such as /site1/.';
                else $route['strip_prefix'] = true;
            }
            if ($route['action'] === 'redirect') {
                $route['redirect_url'] = self::url((string)($r['redirect_url'] ?? '')) ?? '';
                if ($route['redirect_url'] === '') $e["routes.$i.redirect_url"] = 'A full http(s) URL.';
            }
            $o = (array)($r['overrides'] ?? []);
            if (!empty($o['access']['conditions'])) {
                [$oa, $oe] = self::access((array)$o['access'], false);
                foreach ($oe as $k => $v) $e["routes.$i.access.$k"] = $v;
                $route['overrides']['access'] = $oa;
            } elseif (isset($o['access']['signin']) && $o['access']['signin'] !== '') {
                // the sign-in alone (e.g. "none" for an application's own sign-in callback); the site's conditions stay
                $route['overrides']['access'] = ['signin' => self::enum($o['access']['signin'], ['none', 'alternative', 'required']) ?? 'none'];
            }
            // the route signs in at the site's provider (also when the site itself does not sign in)
            if (($route['overrides']['access']['signin'] ?? 'none') !== 'none' && $s['access']['signin']['provider'] === '') {
                $e["routes.$i.signin"] = 'This route signs in: choose the provider under "Sign-in with Microsoft" (the site\'s own sign-in can stay none).';
            }
            if (isset($o['max_body']) && trim((string)$o['max_body']) !== '') {
                $route['overrides']['max_body'] = self::size((string)$o['max_body']) ?? '';
                if ($route['overrides']['max_body'] === '') $e["routes.$i.max_body"] = 'e.g. 10m or 0.';
            }
            if (isset($o['read_timeout']) && trim((string)$o['read_timeout']) !== '') {
                $route['overrides']['read_timeout'] = self::int($o['read_timeout'], 1, 86400) ?? 60;
            }
            if (!empty($o['backend'])) {
                if (in_array($o['backend'], $backendIds, true)) $route['overrides']['backend'] = $o['backend'];
                else $e["routes.$i.backend"] = 'Unknown backend.';
            }
            if (in_array($route['action'], ['proxy', 'acme_proxy'], true) && empty($route['overrides']['backend']) && $s['proxy']['backend'] === '') {
                $e["routes.$i.backend"] = 'This route proxies, so the site (or the route) needs a backend.';
            }
            $s['routes'][] = $route;
        }
        if ($s['enabled'] && !$s['routes']) $e['routes'] = 'An enabled site needs at least one route.';
        if (count(array_filter($s['routes'], fn($r) => $r['action'] === 'acme_proxy')) > 1) $e['routes'] = 'Only one route can proxy the ACME challenge.';
        return [$s, $e];
    }

    /** @return array{0: array, 1: array<string,string>} */
    public static function access(array $in, bool $site): array
    {
        $e = [];
        $conds = array_values(array_intersect(self::CONDITIONS, (array)($in['conditions'] ?? [])));
        if (!$conds) { $e['conditions'] = 'Choose at least one condition.'; $conds = ['lan']; }
        if (in_array('public', $conds, true)) $conds = ['public'];
        $a = ['conditions' => $conds];
        if (!$site && isset($in['signin']) && $in['signin'] !== '') {
            $a['signin'] = self::enum($in['signin'], ['none', 'alternative', 'required']) ?? 'none';
        }
        if ($site) {
            $si = (array)($in['signin'] ?? []);
            $sg = ['mode' => self::enum($si['mode'] ?? 'none', ['none', 'alternative', 'required']) ?? 'none',
                'provider' => self::uuid($si['provider'] ?? '') ?? '', 'groups' => [], 'emails' => [], 'domains' => [],
                'headers' => array_values(array_intersect(array_keys(Signin::HEADERS), (array)($si['headers'] ?? []))),
                'pass_token' => (bool)($si['pass_token'] ?? false), 'nonbrowser_401' => (bool)($si['nonbrowser_401'] ?? true)];
            foreach ((array)($si['groups'] ?? []) as $g) {
                $g = trim((string)$g);
                if ($g === '') continue;
                if (preg_match('/^[A-Za-z0-9._@-][A-Za-z0-9 ._@-]{0,127}$/', $g)) $sg['groups'][] = $g; else $e['signin.groups'] = "Not a group id or role: $g";
            }
            foreach ((array)($si['emails'] ?? []) as $m) {
                if (trim((string)$m) === '') continue;
                if ($v = self::email((string)$m)) $sg['emails'][] = strtolower($v); else $e['signin.emails'] = "Not an e-mail address: $m";
            }
            foreach ((array)($si['domains'] ?? []) as $d) {
                if (trim((string)$d) === '') continue;
                if ($v = self::host((string)$d)) $sg['domains'][] = $v; else $e['signin.domains'] = "Not a domain: $d";
            }
            foreach (['groups', 'emails', 'domains'] as $k) $sg[$k] = array_values(array_unique($sg[$k]));
            if (!$sg['pass_token']) $sg['headers'] = array_values(array_diff($sg['headers'], ['X-Forwarded-Access-Token']));
            if ($sg['mode'] !== 'none' && $sg['provider'] === '') $e['signin.provider'] = 'Choose the sign-in provider.';
            $a['signin'] = $sg;
            $a['denied'] = self::enum($in['denied'] ?? '403', ['403', '404', 'redirect', 'close']) ?? '403';
            $a['denied_url'] = '';
            if ($a['denied'] === 'redirect') {
                $a['denied_url'] = self::url((string)($in['denied_url'] ?? '')) ?? '';
                if ($a['denied_url'] === '') $e['denied_url'] = 'A full http(s) URL.';
            }
        }
        return [$a, $e];
    }

    /** @return array{0: array, 1: array<string,string>} */
    public static function proxy(array $in, array $backendIds, bool $site): array
    {
        $e = [];
        $p = ['backend' => (string)($in['backend'] ?? '')];
        if ($p['backend'] !== '' && !in_array($p['backend'], $backendIds, true)) { $e['backend'] = 'Unknown backend.'; $p['backend'] = ''; }
        $p['host_header'] = self::enum($in['host_header'] ?? 'client', ['client', 'fixed']) ?? 'client';
        $p['host_fixed'] = '';
        if ($p['host_header'] === 'fixed') {
            $p['host_fixed'] = self::host((string)($in['host_fixed'] ?? '')) ?? '';
            if ($p['host_fixed'] === '') $e['host_fixed'] = 'A host name to send upstream.';
        }
        foreach (['connect_timeout' => [1, 300, 10], 'read_timeout' => [1, 86400, 60], 'send_timeout' => [1, 86400, 60]] as $k => [$mi, $ma, $df]) {
            $v = self::int($in[$k] ?? $df, $mi, $ma);
            if ($v === null) { $e[$k] = "$mi–$ma seconds."; $v = $df; }
            $p[$k] = $v;
        }
        foreach (['websocket' => true, 'request_buffering' => true, 'response_buffering' => true] as $k => $df) {
            $p[$k] = (bool)($in[$k] ?? $df);
        }
        return [$p, $e];
    }
}
