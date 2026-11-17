<?php
declare(strict_types=1);

/**
 * The renderer: revision + facts → nginx files (plan §6.3 step 2). A pure function: no DB,
 * no secrets, no clock. bin/render.php runs it as the unprivileged user pspm-render.
 *
 * nginx runs with "-p <release>/ -c nginx.conf", so every path inside a release is
 * relative. "nginx -t -p releases/<rel>/" therefore tests exactly the new tree, and a diff
 * between two releases shows only real changes.
 */
final class Renderer
{
    private array $doc;
    private array $facts;
    private array $backends = [];
    private array $files = [];
    private array $warnings = [];
    private array $pendingCerts = [];
    private array $webports = [80, 443];
    private array $summary = [];
    private array $providers = [];
    private array $providerHosts = [];
    private array $signinCerts = [];   // provider id → name of the certificate its sign-in host uses (null: pending)
    private array $providerToken = [];

    public const IDENTITY_HEADERS = ['X-Forwarded-User', 'X-Forwarded-Email', 'X-Forwarded-Groups',
        'X-Forwarded-Preferred-Username', 'X-Remote-User', 'X-Forwarded-Access-Token'];

    /**
     * proxy_buffer_size for response headers up to $kb KB, with proxy_buffers and
     * proxy_busy_buffers_size that nginx -t accepts: busy >= max(header buffer, one buffer)
     * and busy <= all buffers minus one. proxyBuffers(16) is the default in http.conf.
     */
    public static function proxyBuffers(int $kb): array
    {
        return ['proxy_buffer_size' => "{$kb}k", 'proxy_buffers' => max(8, intdiv(2 * $kb, 16)) . ' 16k',
            'proxy_busy_buffers_size' => max(32, $kb) . 'k'];
    }

    private static function bufferLines(string $indent, int $kb): string
    {
        $o = '';
        foreach (self::proxyBuffers($kb) as $k => $v) $o .= "$indent$k $v;\n";
        return $o;
    }

    public function __construct(array $revision, array $facts)
    {
        $this->doc = $revision['document'] ?? [];
        $this->facts = $facts + ['release' => 'unknown', 'certs' => [], 'resolved' => [], 'ipv6' => true,
            'ca_bundle' => false, 'paths' => [],
            'modules' => ['/usr/share/nginx/modules/ndk_http_module.so', '/usr/share/nginx/modules/ngx_http_lua_module.so']];
        $this->facts['paths'] += ['app_public' => '/srv/pspm/app/current/public', 'app_assets' => '/srv/pspm/app/current/assets',
            'php_socket' => '/run/php/pspm-fpm.sock', 'acme_root' => '/var/www/acme', 'state_dir' => '/var/lib/pspm/state',
            'ip_cert' => '/etc/pspm/tls/ip.crt', 'ip_key' => '/etc/pspm/tls/ip.key'];
        $this->summary['revision'] = $revision['id'] ?? null;
    }

    /** @return array{files: array<string,string>, summary: array, warnings: array, errors: array} */
    public function render(): array
    {
        $errors = Model::checkDocument($this->doc);
        if ($errors) return ['files' => [], 'summary' => [], 'warnings' => [], 'errors' => $errors];
        foreach ($this->doc['backends'] as $b) $this->backends[$b['id']] = $b;
        $g = $this->doc['global'];
        // Client-certificate CAs nginx trusts (static configuration, plan §13.1).
        $cas = $this->doc['cas'] ?? [];
        usort($cas, fn($a, $b) => strcmp($a['id'], $b['id']));
        $this->facts['ca_bundle'] = (bool)$cas;
        if ($cas) {
            $this->files['ca/clients.pem'] = implode('', array_map(fn($c) => rtrim($c['cert_pem']) . "\n", $cas));
            foreach ($cas as $c) $this->files['ca/client-' . $c['id'] . '.pem'] = rtrim($c['cert_pem']) . "\n";
        }

        $sites = array_values(array_filter($this->doc['sites'], fn($s) => !empty($s['enabled'])));
        usort($sites, fn($a, $b) => strcmp($a['hosts'][0], $b['hosts'][0]));
        $provs = $this->doc['providers'] ?? [];
        usort($provs, fn($a, $b) => strcmp($a['id'], $b['id']));
        foreach ($provs as $p) $this->providers[$p['id']] = $p;
        foreach ($sites as $s) {
            if (!$this->signinProvider($s)) continue;
            $pid = $s['access']['signin']['provider'];
            $this->providerHosts[$pid] = array_merge($this->providerHosts[$pid] ?? [], $s['hosts']);
            $this->providerToken[$pid] = ($this->providerToken[$pid] ?? false) || !empty($s['access']['signin']['pass_token']);
        }

        $this->files['conf/http-generated.conf'] = $this->httpGenerated($g);
        $siteSummaries = [];
        foreach ($sites as $s) {
            $this->files['sites/' . $s['hosts'][0] . '.conf'] = $this->site($s, $g, $st);
            $siteSummaries[] = $st;
        }
        $this->files['conf/upstreams.conf'] = $this->upstreams($sites);
        $this->files['conf/signin.conf'] = $this->signinHosts($g);
        if ($this->providers) {
            foreach ($this->providers as $p) {
                $this->files['oauth2-proxy/' . Signin::slug($p['id']) . '.cfg'] = Signin::config($p, $this->providerHosts[$p['id']] ?? [], $this->providerToken[$p['id']] ?? false);
            }
            $this->files['oauth2-proxy/compose.yml'] = Signin::compose(array_values($this->providers));
        }
        [$system, $admin] = $this->system($g);
        $this->files['conf/system.conf'] = $system;
        $this->files['conf/ui.conf'] = $this->ui();
        $this->files['conf/release.conf'] = "# PSPM release marker\nlocation = /pspm-release {\n    default_type text/plain;\n    return 200 \""
            . $this->facts['release'] . "\\n\";\n}\n";
        $this->files['nginx.conf'] = $this->main();
        foreach ($this->backends as $b) {
            if ($b['tls_verify'] === 'custom' && $b['custom_ca'] !== '') $this->files['ca/backend-' . $b['id'] . '.pem'] = $b['custom_ca'] . "\n";
        }
        ksort($this->files);
        sort($this->webports);
        $this->summary['providers'] = array_map(fn($p) => ['id' => $p['id'], 'slug' => Signin::slug($p['id']), 'name' => $p['name'],
            'port' => $p['port'], 'signin_host' => $p['signin_host'], 'tenant_id' => $p['tenant_id'],
            'cert' => ($admin['signin'] ?? null) === $p['id'] ? $admin['cert'] : ($this->signinCerts[$p['id']] ?? null),
            'sites' => array_values(array_unique($this->providerHosts[$p['id']] ?? []))], array_values($this->providers));
        $this->summary += ['sites' => $siteSummaries, 'admin' => $admin, 'webports' => array_values(array_unique($this->webports)),
            'pending_certs' => array_values($this->pendingCerts), 'acme_email' => $g['acme_email']];
        return ['files' => $this->files, 'summary' => $this->summary, 'warnings' => $this->warnings, 'errors' => []];
    }

    // ---------------------------------------------------------------- top level

    private function main(): string
    {
        // Debian's modules-enabled snippets use paths relative to nginx's prefix, which
        // is the release directory here; so the modules are loaded by absolute path.
        $modules = '';
        foreach ($this->facts['modules'] as $m) {
            if (preg_match('#^/[A-Za-z0-9/._-]+\.so$#', $m)) $modules .= "load_module $m;\n";
        }
        return <<<NGX
        # PSPM — generated by the renderer. Do not edit: changes made here are reported as
        # drift and replaced by the next apply.
        user www-data;
        worker_processes auto;
        worker_rlimit_nofile 65535;
        pid /run/nginx.pid;
        error_log /var/log/nginx/error.log warn;
        {$modules}

        events {
            worker_connections 8192;
        }

        http {
            include /etc/nginx/mime.types;
            default_type application/octet-stream;
            include static/http.conf;
            include conf/http-generated.conf;
            include conf/upstreams.conf;
            include conf/system.conf;
            include conf/signin.conf;
            include sites/*.conf;
        }

        NGX;
    }

    private function httpGenerated(array $g): string
    {
        $o = "# Generated from the global settings.\n";
        $o .= "lua_package_path \"\${prefix}lua/?.lua;;\";\n";
        $o .= "init_by_lua_block {\n    require(\"pspm\").init(" . $this->luaStr($this->facts['paths']['state_dir']) . ")\n}\n\n";
        $o .= "geo \$pspm_lan {\n    default 0;\n";
        foreach ($g['lan_ranges'] as $r) $o .= "    $r 1;\n";
        $o .= "}\n\n";
        $o .= sprintf("limit_req_zone \$binary_remote_addr zone=pspm_std:20m rate=%dr/s;\n", $g['rate_standard']['rate']);
        $o .= sprintf("limit_req_zone \$binary_remote_addr zone=pspm_strict:20m rate=%dr/s;\n", $g['rate_strict']['rate']);
        return $o;
    }

    // ---------------------------------------------------------------- management, catch-all, loopback

    /** @return array{0: string, 1: array} */
    private function system(array $g): array
    {
        $admin = ['host' => $g['admin_host'], 'in_effect' => false, 'pending' => false, 'cert' => null, 'signin' => null];
        // any valid certificate that covers the name will do (pspm-admin, a wildcard, the sign-in host's)
        $adminCert = $g['admin_host'] !== '' ? $this->certFor([$g['admin_host']], 'pspm-admin') : null;
        $shared = $this->sharedSignin($g);
        if ($shared) $admin['signin'] = $shared['id'];
        if ($g['admin_host'] !== '') {
            if ($adminCert && $adminCert['covers']) { $admin['in_effect'] = true; $admin['cert'] = $adminCert['name']; }
            else { $admin['pending'] = true; $this->pendingCerts['pspm-admin'] = ['name' => 'pspm-admin', 'hosts' => [$g['admin_host']], 'site' => 'admin'];
                if ($shared) $this->warnings[] = "Sign-in host {$g['admin_host']} (also the admin host name) waits for its certificate; sites that require sign-in answer 503 until then.";
            }
        }
        $ipUi = !$admin['in_effect'];
        $v6 = $this->facts['ipv6'];
        $p = $this->facts['paths'];
        $vars = $this->vars('', 'public', '444');

        $o = "# Catch-all, management UI and loopback listeners.\n\n";
        // Port 80 catch-all
        // unknown.lua answers the UI by IP to private addresses while no admin host name is in
        // effect (plan §8.2); everything else is closed and counted by the unknown-host rule.
        $byIp = '    set $pspm_ui_by_ip ' . ($ipUi ? '1' : '0') . ";\n    rewrite_by_lua_file lua/unknown.lua;\n";
        $o .= "server {\n    listen 80 default_server;\n" . ($v6 ? "    listen [::]:80 default_server;\n" : '') . "    server_name _;\n$vars$byIp";
        $o .= "    location / {\n        return 301 https://\$host\$request_uri;\n    }\n}\n\n";
        // Port 443 catch-all
        $o .= "server {\n    listen 443 ssl default_server;\n" . ($v6 ? "    listen [::]:443 ssl default_server;\n" : '') . "    server_name _;\n";
        $o .= "    ssl_certificate {$p['ip_cert']};\n    ssl_certificate_key {$p['ip_key']};\n    include static/tls-intermediate.conf;\n$vars$byIp";
        $o .= "    set \$pspm_listener ip;\n    include conf/ui.conf;\n}\n\n";
        // Admin host name
        if ($g['admin_host'] !== '') {
            $h = $g['admin_host'];
            $o .= "# Admin host name\nserver {\n    listen 80;\n" . ($v6 ? "    listen [::]:80;\n" : '') . "    server_name $h;\n" . $this->vars('', 'public', '403');
            $o .= "    rewrite_by_lua_file lua/block.lua;\n" . $this->acmeLocation();
            $o .= $admin['in_effect'] ? "    location / {\n        return 301 https://\$host\$request_uri;\n    }\n"
                                      : "    location / {\n        return 503;\n    }\n" . $this->errorPages(true);
            $o .= "}\n\n";
            if ($admin['in_effect']) {
                $o .= "server {\n    listen 443 ssl;\n" . ($v6 ? "    listen [::]:443 ssl;\n" : '') . "    http2 on;\n    server_name $h;\n";
                $o .= "    ssl_certificate {$adminCert['fullchain']};\n    ssl_certificate_key {$adminCert['key']};\n";
                $o .= "    include static/tls-" . $g['tls_profile'] . ".conf;\n";
                if ($this->facts['ca_bundle'] && in_array('cert', $g['admin_access'], true)) {
                    $o .= "    ssl_verify_client optional;\n    ssl_client_certificate ca/clients.pem;\n    ssl_verify_depth 1;\n";
                }
                $o .= $this->vars('admin', implode(',', $g['admin_access']), '403');
                $o .= "    rewrite_by_lua_file lua/block.lua;\n    access_by_lua_file lua/gate.lua;\n    set \$pspm_listener admin;\n";
                // also the sign-in host of a provider: its /oauth2/ is public, the UI keeps the admin access
                if ($shared) $o .= $this->oauth2Location($shared);
                // access links to the admin UI (plan §11.1): they clear the address for $pspm_site "admin"
                if (in_array('cleared', $g['admin_access'], true)) $o .= $this->accessLinkLocation();
                if ($g['hsts']['enabled']) $o .= '    add_header Strict-Transport-Security "max-age=' . $g['hsts']['max_age'] . ($g['hsts']['include_subdomains'] ? '; includeSubDomains' : '') . "\" always;\n";
                $o .= "    include conf/ui.conf;\n}\n\n";
            }
        }
        // Loopback: the UI through an SSH tunnel; always on (plan §8.2)
        $o .= "# Loopback UI for SSH tunnels: ssh -L 9443:127.0.0.1:9443 <box>\n";
        $o .= "server {\n    listen 127.0.0.1:9443 ssl;\n    server_name _;\n    ssl_certificate {$p['ip_cert']};\n    ssl_certificate_key {$p['ip_key']};\n";
        $o .= "    include static/tls-intermediate.conf;\n" . $vars . "    set \$pspm_listener loopback;\n    include conf/ui.conf;\n}\n\n";
        // Loopback control endpoints
        $o .= "# Loopback control: release marker, state sync, health\n";
        $o .= "server {\n    listen 127.0.0.1:9080;\n    server_name _;\n    access_log off;\n" . $vars;
        $o .= "    include conf/release.conf;\n";
        $o .= "    location = /pspm-sync {\n        default_type application/json;\n        content_by_lua_file lua/sync.lua;\n    }\n";
        $o .= "    location = /healthz {\n" . $this->fastcgi('loopback') . "    }\n";
        $o .= "    # Declares the variables Lua sets per request (never executed).\n";
        $o .= "    location = /.pspm/declare {\n        internal;\n        set \$pspm_outcome \"\";\n        set \$pspm_user \"\";\n        set \$pspm_email \"\";\n"
            . "        set \$pspm_groups \"\";\n        set \$pspm_puser \"\";\n        set \$pspm_token \"\";\n        return 404;\n    }\n";
        $o .= "    location / {\n        return 404;\n    }\n}\n";
        return [$o, $admin];
    }

    private function ui(): string
    {
        $p = $this->facts['paths'];
        $fcgi = $this->fastcgi(null, '    ');
        return <<<NGX
        # The PSPM web UI (included by the IP, admin host and loopback servers).
        root {$p['app_public']};
        client_max_body_size 64m;
        client_body_buffer_size 64m;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Referrer-Policy no-referrer always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'" always;
        location ^~ /assets/ {
            alias {$p['app_assets']}/;
            expires 1h;
            access_log off;
        }
        location = /login {
            limit_req zone=pspm_login burst=3 nodelay;
        $fcgi}
        location / {
            limit_req zone=pspm_ui burst=20 nodelay;
        $fcgi}

        NGX;
    }

    private function fastcgi(?string $listener, string $ind = '        '): string
    {
        $o = "{$ind}fastcgi_pass unix:{$this->facts['paths']['php_socket']};\n";
        $o .= "{$ind}include /etc/nginx/fastcgi_params;\n";
        $o .= "{$ind}root {$this->facts['paths']['app_public']};\n";
        $o .= "{$ind}fastcgi_param SCRIPT_FILENAME \$realpath_root/index.php;\n";
        $o .= "{$ind}fastcgi_param SCRIPT_NAME /index.php;\n";
        $o .= "{$ind}fastcgi_param HTTPS \$https if_not_empty;\n";
        $o .= "{$ind}fastcgi_param HTTP_PROXY \"\";\n";
        $o .= "{$ind}fastcgi_param PSPM_LISTENER " . ($listener ?? '$pspm_listener') . ";\n";
        $o .= "{$ind}fastcgi_read_timeout 300s;\n";
        return $o;
    }

    // ---------------------------------------------------------------- sites

    private function site(array $s, array $g, ?array &$st): string
    {
        $host = $s['hosts'][0];
        $names = implode(' ', $s['hosts']);
        $v6 = $this->facts['ipv6'];
        $st = ['id' => $s['id'], 'host' => $host, 'tls' => $s['tls']['mode'], 'cert' => null, 'pending' => false];
        $cert = null;
        if ($s['tls']['mode'] === 'letsencrypt') {
            $name = 'pspm-' . slugify($host, 60);
            $cert = $this->certFor($s['hosts'], $name);
            if (!$cert || !$cert['covers']) {
                $this->pendingCerts[$name] = ['name' => $name, 'hosts' => $s['hosts'], 'site' => $host];
            }
            if (!$cert) $st['pending'] = true;
            else $st['cert'] = $cert['name'];
        }
        // signinVars sets $pspm_signin itself when the site or a route signs in
        $siteVars = $this->vars($s['id'], implode(',', $s['access']['conditions']), $s['access']['denied'], $s['access']['denied_url'], !$this->signinProvider($s))
            . $this->signinVars($s);
        $o = "# Site $host (" . $s['id'] . ")\n";

        // Port 80
        $acmeProxied = (bool)array_filter($s['routes'], fn($r) => $r['action'] === 'acme_proxy');
        $o .= "server {\n    listen 80;\n" . ($v6 ? "    listen [::]:80;\n" : '') . "    server_name $names;\n$siteVars";
        $o .= "    rewrite_by_lua_file lua/block.lua;\n    access_by_lua_file lua/gate.lua;\n";
        if (!$acmeProxied) $o .= $this->acmeLocation();
        $o .= $this->signinAuthLocation($s);
        if ($s['tls']['mode'] === 'none' || $s['port80'] === 'serve') {
            if ($s['tls']['mode'] === 'none') $o .= $this->linkLocation($s);
            $o .= $this->routes($s, $g, 'http', $acmeProxied);
        } elseif ($st['pending']) {
            $o .= "    # Waiting for its certificate: ACME only (plan §6.4)\n    location / {\n        return 503;\n    }\n";
            $o .= $this->routes($s, $g, 'http', $acmeProxied, true);
        } elseif ($s['port80'] === 'redirect') {
            $o .= "    location / {\n        return 301 https://\$host\$request_uri;\n    }\n";
            $o .= $this->routes($s, $g, 'http', $acmeProxied, true);
        } else {
            $o .= "    location / {\n        return 404;\n    }\n";
            $o .= $this->routes($s, $g, 'http', $acmeProxied, true);
        }
        $o .= $this->errorPages($g['error_pages']) . "}\n";

        // Port 443
        if ($cert) {
            $o .= "\nserver {\n    listen 443 ssl;\n" . ($v6 ? "    listen [::]:443 ssl;\n" : '');
            if ($s['tls']['http2']) $o .= "    http2 on;\n";
            $o .= "    server_name $names;\n" . $this->tlsBlock($s, $g, $cert) . $siteVars;
            $o .= "    rewrite_by_lua_file lua/block.lua;\n    access_by_lua_file lua/gate.lua;\n";
            $o .= $this->linkLocation($s) . $this->signinAuthLocation($s) . $this->routes($s, $g, 'https', $acmeProxied) . $this->errorPages($g['error_pages']) . "}\n";
        }

        // Extra listeners
        foreach ($s['listeners'] as $li) {
            if ($li['tls'] && !$cert) { $this->warnings[] = "$host: listener {$li['port']} (TLS) waits for the certificate."; continue; }
            $this->webports[] = $li['port'];
            $o .= "\nserver {\n    listen {$li['port']}" . ($li['tls'] ? ' ssl' : '') . ";\n";
            if ($v6) $o .= "    listen [::]:{$li['port']}" . ($li['tls'] ? ' ssl' : '') . ";\n";
            $o .= "    server_name $names;\n" . ($li['tls'] ? $this->tlsBlock($s, $g, $cert) : '') . $siteVars;
            $o .= "    rewrite_by_lua_file lua/block.lua;\n    access_by_lua_file lua/gate.lua;\n";
            $o .= $this->signinAuthLocation($s) . $this->routes($s, $g, 'port:' . $li['port'], $acmeProxied) . $this->errorPages($g['error_pages']) . "}\n";
        }
        return $o;
    }

    private function tlsBlock(array $s, array $g, array $cert): string
    {
        $profile = $s['tls']['profile'] === 'default' ? $g['tls_profile'] : $s['tls']['profile'];
        $o = "    ssl_certificate {$cert['fullchain']};\n    ssl_certificate_key {$cert['key']};\n    include static/tls-$profile.conf;\n";
        if ($this->facts['ca_bundle'] && $s['client_certs'] === 'optional') {
            $o .= "    ssl_verify_client optional;\n    ssl_client_certificate ca/clients.pem;\n    ssl_verify_depth 1;\n";
        }
        return $o;
    }

    private function routes(array $s, array $g, string $listener, bool $acmeProxied, bool $onlyExplicit = false): string
    {
        $o = '';
        foreach ($s['routes'] as $r) {
            $ls = $r['listeners'];
            $on = in_array($listener, $ls, true) || (in_array('all', $ls, true) && !$onlyExplicit);
            if ($r['action'] === 'acme_proxy') $on = $listener === 'http';
            if (!$on) continue;
            foreach ($r['paths'] as $path) {
                if ($onlyExplicit && $path === '/' && $r['match'] === 'prefix') continue;   // "/" is already the redirect/503
                $loc = $r['match'] === 'exact' ? "= $path" : ($path === '/' ? '/' : "^~ $path");
                $o .= "    location $loc {\n" . $this->routeBody($s, $g, $r, $listener) . "    }\n";
            }
        }
        return $o;
    }

    private function routeBody(array $s, array $g, array $r, string $listener): string
    {
        $i = '        ';
        $o = '';
        $ov = $r['overrides'];
        // Let's Encrypt must always reach the challenge: public, and never sent to the sign-in
        // (a site that requires sign-in would answer 401, and its certificate could not be renewed)
        if ($r['action'] === 'acme_proxy') $o .= "{$i}set \$pspm_allow public;\n{$i}set \$pspm_signin none;\n";
        elseif (!empty($ov['access'])) {
            // without own conditions the site's stay ($pspm_allow from the server); the sign-in can be overridden alone
            if (!empty($ov['access']['conditions'])) $o .= "{$i}set \$pspm_allow " . implode(',', $ov['access']['conditions']) . ";\n";
            if (isset($ov['access']['signin']) && $this->signinProvider($s)) $o .= "{$i}set \$pspm_signin {$ov['access']['signin']};\n";
            elseif (isset($ov['access']['signin'])) $o .= "{$i}set \$pspm_signin none;\n";
        }
        if ($r['action'] === 'status') return $o . "{$i}return {$r['status']};\n";
        if ($r['action'] === 'redirect') return $o . "{$i}return {$r['redirect_code']} \"{$r['redirect_url']}\";\n";

        $bid = $ov['backend'] ?? $s['proxy']['backend'];
        $b = $this->backends[$bid] ?? null;
        if (!$b) return $o . "{$i}return 502;\n";
        $p = $s['proxy'];
        $o .= "{$i}client_max_body_size " . ($ov['max_body'] ?? $s['limits']['max_body']) . ";\n";
        if ($s['limits']['rate'] === 'standard') $o .= "{$i}limit_req zone=pspm_std burst={$g['rate_standard']['burst']} nodelay;\n";
        if ($s['limits']['rate'] === 'strict') $o .= "{$i}limit_req zone=pspm_strict burst={$g['rate_strict']['burst']} nodelay;\n";
        if ($s['limits']['limit_conn'] > 0) $o .= "{$i}limit_conn pspm_conn {$s['limits']['limit_conn']};\n";
        $o .= "{$i}proxy_pass {$b['protocol']}://" . $this->upstreamName($b['id']) . ";\n";
        $o .= "{$i}proxy_http_version 1.1;\n";
        $o .= "{$i}proxy_set_header Host " . ($p['host_header'] === 'fixed' ? $p['host_fixed'] : '$host') . ";\n";
        foreach (['X-Real-IP' => '$remote_addr', 'X-Forwarded-For' => '$remote_addr', 'X-Forwarded-Proto' => '$scheme',
                  'X-Forwarded-Host' => '$host', 'X-Forwarded-Port' => '$server_port'] as $hn => $hv) {
            $o .= "{$i}proxy_set_header $hn $hv;\n";
        }
        if ($p['websocket']) $o .= "{$i}proxy_set_header Upgrade \$http_upgrade;\n{$i}proxy_set_header Connection \$pspm_connection_upgrade;\n";
        else $o .= "{$i}proxy_set_header Connection \"\";\n";
        // Identity headers are always set: to the signed-in identity, or empty, which means
        // nginx does not send them. A client can never pass its own (plan §12.4).
        $selected = $this->signinProvider($s) ? ($s['access']['signin']['headers'] ?? []) : [];
        $vars = ['X-Forwarded-User' => '$pspm_user', 'X-Forwarded-Email' => '$pspm_email', 'X-Forwarded-Groups' => '$pspm_groups',
            'X-Forwarded-Preferred-Username' => '$pspm_puser', 'X-Remote-User' => '$pspm_email', 'X-Forwarded-Access-Token' => '$pspm_token'];
        foreach (self::IDENTITY_HEADERS as $hn) $o .= "{$i}proxy_set_header $hn " . (in_array($hn, $selected, true) ? $vars[$hn] : '""') . ";\n";
        foreach ($s['headers']['request'] as $hd) {
            $v = match ($hd['type']) { 'client_addr' => '$remote_addr', 'scheme' => '$scheme', 'host' => '$host',
                'request_id' => '$request_id', 'client_cert_fp' => '$ssl_client_fingerprint', default => '"' . $hd['value'] . '"' };
            $o .= "{$i}proxy_set_header {$hd['name']} $v;\n";
        }
        $o .= "{$i}proxy_connect_timeout {$p['connect_timeout']}s;\n";
        $o .= "{$i}proxy_read_timeout " . ($ov['read_timeout'] ?? $p['read_timeout']) . "s;\n";
        $o .= "{$i}proxy_send_timeout {$p['send_timeout']}s;\n";
        $o .= "{$i}proxy_request_buffering " . ($p['request_buffering'] ? 'on' : 'off') . ";\n";
        $o .= "{$i}proxy_buffering " . ($p['response_buffering'] ? 'on' : 'off') . ";\n";
        $hb = (int)($b['header_buffer'] ?? Validate::HEADER_BUFFER_DEFAULT);   // older revisions have no value
        if ($hb !== Validate::HEADER_BUFFER_DEFAULT) $o .= self::bufferLines($i, $hb);
        if ($b['protocol'] === 'https') {
            $first = explode(':', trim(preg_replace('/\]:\d+$/', ']', $b['servers'][0]['addr']) ?? '', '[]'))[0];
            $sni = $b['tls_name'] ?: (IP::valid($first) ? '' : preg_replace('/:\d+$/', '', $b['servers'][0]['addr']));
            if ($sni !== '') $o .= "{$i}proxy_ssl_server_name on;\n{$i}proxy_ssl_name $sni;\n";
            if ($b['tls_verify'] === 'off') $o .= "{$i}proxy_ssl_verify off;\n";
            else {
                $o .= "{$i}proxy_ssl_verify on;\n{$i}proxy_ssl_verify_depth 4;\n";
                $o .= "{$i}proxy_ssl_trusted_certificate " . ($b['tls_verify'] === 'custom' ? 'ca/backend-' . $b['id'] . '.pem' : '/etc/ssl/certs/ca-certificates.crt') . ";\n";
            }
        }
        $sec = $g['security_headers'] && $s['headers']['security'] !== 'off';
        $hide = $s['headers']['hide'];
        if ($sec) $hide[] = 'X-Powered-By';
        foreach (array_unique($hide) as $hn) $o .= "{$i}proxy_hide_header $hn;\n";
        // add_header is written into every location: a location with its own add_header loses the server's.
        if ($sec) $o .= "{$i}add_header X-Content-Type-Options nosniff always;\n{$i}add_header Referrer-Policy strict-origin-when-cross-origin always;\n";
        if ($listener !== 'http' && $s['tls']['mode'] !== 'none' && ($hsts = $this->hsts($s, $g))) $o .= "{$i}add_header Strict-Transport-Security \"$hsts\" always;\n";
        foreach ($s['headers']['response'] as $hd) $o .= "{$i}add_header {$hd['name']} \"{$hd['value']}\" always;\n";
        return $o;
    }

    private function hsts(array $s, array $g): ?string
    {
        $h = $s['tls']['hsts'];
        if ($h['mode'] === 'off' || ($h['mode'] === 'default' && !$g['hsts']['enabled'])) return null;
        if ($h['mode'] === 'default') return 'max-age=' . $g['hsts']['max_age'] . ($g['hsts']['include_subdomains'] ? '; includeSubDomains' : '');
        return 'max-age=' . $h['max_age'] . ($h['include_subdomains'] ? '; includeSubDomains' : '') . ($h['preload'] ? '; preload' : '');
    }

    /** The provider a site signs in with, or null when neither the site nor a route uses sign-in. */
    private function signinProvider(array $s): ?array
    {
        $si = $s['access']['signin'] ?? ['mode' => 'none'];
        $uses = ($si['mode'] ?? 'none') !== 'none';
        foreach ($s['routes'] as $r) $uses = $uses || ($r['overrides']['access']['signin'] ?? 'none') !== 'none';
        return $uses ? ($this->providers[$si['provider'] ?? ''] ?? null) : null;
    }

    private function signinVars(array $s): string
    {
        $p = $this->signinProvider($s);
        if (!$p) return '';
        $si = $s['access']['signin'];
        $q = [];
        if ($si['groups']) $q[] = 'allowed_groups=' . rawurlencode(implode(',', $si['groups']));
        if ($si['emails']) $q[] = 'allowed_emails=' . rawurlencode(implode(',', $si['emails']));
        if ($si['domains']) $q[] = 'allowed_email_domains=' . rawurlencode(implode(',', $si['domains']));
        return "    set \$pspm_signin {$si['mode']};\n    set \$pspm_signin_host {$p['signin_host']};\n"
             . '    set $pspm_signin_args "' . implode('&', $q) . "\";\n    set \$pspm_signin_nb401 " . ($si['nonbrowser_401'] ? '1' : '0') . ";\n";
    }

    /** Internal location for the sign-in check (the subrequest from gate.lua, plan §12.3). */
    private function signinAuthLocation(array $s): string
    {
        $p = $this->signinProvider($s);
        if (!$p) return '';
        return "    location = /.pspm/signin/auth {\n        internal;\n        proxy_pass http://127.0.0.1:{$p['port']}/oauth2/auth;\n"
             . "        proxy_pass_request_body off;\n        proxy_set_header Content-Length \"\";\n"
             . "        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header X-Forwarded-For \$remote_addr;\n"
             . "        proxy_set_header X-Forwarded-Proto https;\n        proxy_set_header X-Forwarded-Host \$host;\n"
             . "        proxy_set_header X-Forwarded-Uri \$request_uri;\n        proxy_set_header X-Forwarded-Method \$request_method;\n"
             . "        proxy_set_header X-Scheme https;\n        proxy_connect_timeout 2s;\n        proxy_read_timeout 3s;\n"
             . self::bufferLines('        ', 32)   // the user's groups come back in a header; Entra sends up to 200
             . "    }\n";
    }

    /** The sign-in host of each provider: /oauth2/* to its oauth2-proxy (plan §12.3). */
    /** The provider whose sign-in host is also the admin host name (one server serves both), or null. */
    private function sharedSignin(array $g): ?array
    {
        foreach ($this->providers as $p) if ($g['admin_host'] !== '' && $p['signin_host'] === $g['admin_host']) return $p;
        return null;
    }

    /**
     * /oauth2/* to a provider's oauth2-proxy: public, the sign-in pages and callbacks (plan §12.3).
     * The gate does not run here: it strips the _pspm_ cookies (they must never reach a backend),
     * but these are oauth2-proxy's own (CSRF at the callback, the session at sign-out). On a host
     * shared with the admin UI, the server's gate would otherwise lose the CSRF cookie (403).
     * block.lua (rewrite phase) still refuses blocked addresses.
     */
    private function oauth2Location(array $p): string
    {
        return "    location /oauth2/ {\n        set \$pspm_allow public;\n        access_by_lua_block { return }   # no gate: oauth2-proxy needs its _pspm_ cookies\n"
            . "        limit_req zone=pspm_signin burst=120 nodelay;\n        proxy_pass http://127.0.0.1:{$p['port']};\n"
            . "        proxy_set_header Host \$host;\n        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header X-Forwarded-For \$remote_addr;\n"
            . "        proxy_set_header X-Forwarded-Proto https;\n        proxy_set_header X-Forwarded-Host \$host;\n        proxy_set_header X-Scheme https;\n"
            . self::bufferLines('        ', 128) . "        proxy_connect_timeout 5s;\n        proxy_read_timeout 30s;\n    }\n";
    }

    private function signinHosts(array $g): string
    {
        $o = "# Sign-in hosts (Microsoft sign-in through oauth2-proxy)\n";
        $v6 = $this->facts['ipv6'];
        $shared = $this->sharedSignin($g);
        foreach ($this->providers as $p) {
            $h = $p['signin_host'];
            if ($shared && $shared['id'] === $p['id']) { $o .= "# $h is also the admin host name: served in conf/system.conf\n"; continue; }
            $name = 'pspm-signin-' . Signin::slug($p['id']);
            $cert = $this->certFor([$h], $name);
            if (!$cert || !$cert['covers']) $this->pendingCerts[$name] = ['name' => $name, 'hosts' => [$h], 'site' => "sign-in {$p['name']}"];
            $this->signinCerts[$p['id']] = $cert['name'] ?? null;
            $o .= "server {\n    listen 80;\n" . ($v6 ? "    listen [::]:80;\n" : '') . "    server_name $h;\n" . $this->vars('', 'public', '404');
            $o .= "    rewrite_by_lua_file lua/block.lua;\n" . $this->acmeLocation();
            $o .= $cert ? "    location / {\n        return 301 https://\$host\$request_uri;\n    }\n}\n" : "    location / {\n        return 503;\n    }\n}\n";
            if (!$cert) { $this->warnings[] = "Sign-in host $h waits for its certificate; sites that require sign-in answer 503 until then."; continue; }
            $o .= "server {\n    listen 443 ssl;\n" . ($v6 ? "    listen [::]:443 ssl;\n" : '') . "    http2 on;\n    server_name $h;\n";
            $o .= "    ssl_certificate {$cert['fullchain']};\n    ssl_certificate_key {$cert['key']};\n    include static/tls-{$g['tls_profile']}.conf;\n";
            $o .= $this->vars('', 'public', '404') . "    rewrite_by_lua_file lua/block.lua;\n";
            $o .= "    add_header Strict-Transport-Security \"max-age=31536000\" always;\n";
            $o .= $this->oauth2Location($p);
            $o .= "    location = / {\n        " . ($p['start_url'] !== '' ? "return 302 \"{$p['start_url']}\";" : 'return 404;') . "\n    }\n";
            $o .= "    location / {\n        return 404;\n    }\n}\n";
        }
        return $o;
    }

    /** Access links live on the site's own host names (plan §11.1); only when the policy accepts cleared addresses. */
    private function linkLocation(array $s): string
    {
        $uses = in_array('cleared', $s['access']['conditions'], true);
        foreach ($s['routes'] as $r) $uses = $uses || in_array('cleared', $r['overrides']['access']['conditions'] ?? [], true);
        return $uses ? $this->accessLinkLocation() : '';
    }

    /** /.pspm/access/<token>: public and rate-limited; PHP serves only the link handler there (listener "site"). */
    private function accessLinkLocation(): string
    {
        return "    location ^~ /.pspm/access/ {\n        set \$pspm_allow public;\n        limit_req zone=pspm_access burst=10 nodelay;\n"
             . $this->fastcgi('site') . "    }\n";
    }

    private function acmeLocation(): string
    {
        return "    location ^~ /.well-known/acme-challenge/ {\n        set \$pspm_allow public;\n        set \$pspm_signin none;\n        root {$this->facts['paths']['acme_root']};\n"
             . "        default_type text/plain;\n        try_files \$uri =404;\n    }\n";
    }

    private function errorPages(bool $on): string
    {
        if (!$on) return '';
        $o = '';
        foreach ([403, 404, 429, 502, 503, 504] as $c) $o .= "    error_page $c /.pspm/error/$c.html;\n";
        return $o . "    location ^~ /.pspm/error/ {\n        internal;\n        set \$pspm_allow public;\n        alias static/errors/;\n    }\n";
    }

    private function vars(string $site, string $allow, string $deny, string $denyUrl = '', bool $signinNone = true): string
    {
        // $pspm_outcome and the identity variables are not set here: a server-level "set"
        // runs again on internal redirects (error pages) and would wipe what Lua recorded.
        // They are declared once in conf/system.conf.
        return "    set \$pspm_site \"$site\";\n    set \$pspm_allow $allow;\n    set \$pspm_deny $deny;\n"
             . "    set \$pspm_deny_url \"$denyUrl\";\n    set \$pspm_listener \"\";\n" . ($signinNone ? "    set \$pspm_signin none;\n" : '');
    }

    // ---------------------------------------------------------------- upstreams and certificates

    private function upstreamName(string $id): string
    {
        return 'pspm_b_' . str_replace('-', '', substr($id, 0, 13));
    }

    private function upstreams(array $sites): string
    {
        $used = [];
        foreach ($sites as $s) {
            if ($s['proxy']['backend'] !== '') $used[$s['proxy']['backend']] = true;
            foreach ($s['routes'] as $r) if (!empty($r['overrides']['backend'])) $used[$r['overrides']['backend']] = true;
        }
        ksort($used);
        $o = "# Backends in use\n";
        foreach (array_keys($used) as $id) {
            $b = $this->backends[$id];
            $o .= "upstream " . $this->upstreamName($id) . " {\n    # {$b['name']}\n";
            $live = 0;
            foreach ($b['servers'] as $srv) {
                $h = preg_replace('/:\d+$/', '', $srv['addr']);
                if (!IP::valid(trim((string)$h, '[]')) && ($this->facts['resolved'][$h] ?? true) === false) {
                    $this->warnings[] = "Backend {$b['name']}: $h does not resolve; the server is left out.";
                    continue;
                }
                $live++;
                $o .= "    server {$srv['addr']} weight={$srv['weight']} max_fails={$srv['max_fails']} fail_timeout={$srv['fail_timeout']}s"
                    . ($srv['backup'] ? ' backup' : '') . ";\n";
            }
            if ($live === 0) $o .= "    server 127.0.0.1:9 down;   # no server resolves\n";
            if ($b['keepalive'] > 0) $o .= "    keepalive {$b['keepalive']};\n";
            $o .= "}\n";
        }
        return $o;
    }

    /**
     * Find a usable certificate for these host names: preferably the one with the expected
     * name, else any unexpired one whose SANs cover them all. 'covers' tells whether every
     * host is in it (otherwise it is used, and an expanded certificate is requested).
     */
    private function certFor(array $hosts, string $name): ?array
    {
        $now = $this->facts['now'] ?? gmdate('c');
        $best = null;
        foreach ($this->facts['certs'] as $c) {
            if (($c['not_after'] ?? '') <= $now) continue;
            $covered = array_filter($hosts, fn($h) => self::sanCovers($c['sans'] ?? [], $h));
            $covers = count($covered) === count($hosts);
            if ($c['name'] === $name && count($covered) > 0) return $c + ['covers' => $covers];
            if ($covers && !$best) $best = $c + ['covers' => true];
        }
        return $best;
    }

    public static function sanCovers(array $sans, string $host): bool
    {
        foreach ($sans as $san) {
            $san = strtolower($san);
            if ($san === $host) return true;
            if (str_starts_with($san, '*.') && substr_count($host, '.') >= 2 && substr($host, strpos($host, '.')) === substr($san, 1)) return true;
        }
        return false;
    }

    private function luaStr(string $s): string
    {
        return '"' . addcslashes($s, "\"\\\n") . '"';
    }
}
