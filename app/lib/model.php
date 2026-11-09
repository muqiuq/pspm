<?php
declare(strict_types=1);

/** The configuration working copy: global settings, sites (with routes), backends. */
final class Model
{
    public static function backends(): array
    {
        $out = [];
        foreach (DB::all('SELECT id, name, config, updated_at FROM backends ORDER BY name') as $r) {
            $out[$r['id']] = ['id' => $r['id'], 'updated_at' => $r['updated_at']] + json_dec($r['config']);
        }
        return $out;
    }

    public static function backend(string $id): ?array
    {
        $r = DB::one('SELECT id, config, updated_at FROM backends WHERE id = ?', [$id]);
        return $r ? ['id' => $r['id'], 'updated_at' => $r['updated_at']] + json_dec($r['config']) : null;
    }

    public static function sites(): array
    {
        $out = [];
        foreach (DB::all('SELECT id, config, updated_at FROM sites ORDER BY name') as $r) {
            $out[$r['id']] = ['id' => $r['id'], 'updated_at' => $r['updated_at']] + json_dec($r['config']);
        }
        return $out;
    }

    public static function site(string $id): ?array
    {
        $r = DB::one('SELECT id, config, updated_at FROM sites WHERE id = ?', [$id]);
        return $r ? ['id' => $r['id'], 'updated_at' => $r['updated_at']] + json_dec($r['config']) : null;
    }

    /**
     * Save a validated site. $expected is the updated_at the editor loaded (optimistic
     * locking between admins). Returns [id, error].
     */
    public static function saveSite(?string $id, array $site, ?string $expected): array
    {
        $taken = self::hostConflicts($site['hosts'], $id);
        if ($taken) return [null, 'Host name already used by another site: ' . implode(', ', $taken)];
        $admin = Settings::global()['admin_host'];
        if ($admin !== '' && in_array($admin, $site['hosts'], true)) return [null, "$admin is the admin host name."];
        return DB::tx(function () use ($id, $site, $expected) {
            if ($id) {
                $cur = DB::one('SELECT updated_at FROM sites WHERE id = ? FOR UPDATE', [$id]);
                if (!$cur) return [null, 'The site no longer exists.'];
                if ($expected && $cur['updated_at'] !== $expected) return [null, 'Someone else changed this site meanwhile. Reload and edit again.'];
                DB::q('UPDATE sites SET name = ?, config = ?::jsonb, updated_at = now(), updated_by = ? WHERE id = ?',
                    [$site['hosts'][0], json_enc($site), Audit::actor(), $id]);
                Audit::log('site.update', 'site:' . $site['hosts'][0]);
            } else {
                $id = Crypto::uuid();
                DB::q('INSERT INTO sites (id, name, config, updated_by) VALUES (?, ?, ?::jsonb, ?)',
                    [$id, $site['hosts'][0], json_enc($site), Audit::actor()]);
                Audit::log('site.create', 'site:' . $site['hosts'][0]);
            }
            DB::q('DELETE FROM site_hosts WHERE site_id = ?', [$id]);
            foreach ($site['hosts'] as $h) DB::q('INSERT INTO site_hosts (host, site_id) VALUES (?, ?)', [$h, $id]);
            return [$id, null];
        });
    }

    public static function hostConflicts(array $hosts, ?string $exceptSite): array
    {
        if (!$hosts) return [];
        $in = implode(',', array_fill(0, count($hosts), '?'));
        $rows = DB::all("SELECT host FROM site_hosts WHERE host IN ($in)" . ($exceptSite ? ' AND site_id <> ?' : ''),
            $exceptSite ? [...$hosts, $exceptSite] : $hosts);
        return array_column($rows, 'host');
    }

    public static function deleteSite(string $id): void
    {
        $s = self::site($id);
        DB::q('DELETE FROM sites WHERE id = ?', [$id]);
        Audit::log('site.delete', 'site:' . ($s['hosts'][0] ?? $id));
    }

    public static function saveBackend(?string $id, array $b, ?string $expected): array
    {
        $dupe = DB::val('SELECT id FROM backends WHERE name = ?' . ($id ? ' AND id <> ?' : ''), $id ? [$b['name'], $id] : [$b['name']]);
        if ($dupe) return [null, 'A backend with this name exists.'];
        return DB::tx(function () use ($id, $b, $expected) {
            if ($id) {
                $cur = DB::one('SELECT updated_at FROM backends WHERE id = ? FOR UPDATE', [$id]);
                if (!$cur) return [null, 'The backend no longer exists.'];
                if ($expected && $cur['updated_at'] !== $expected) return [null, 'Someone else changed this backend meanwhile. Reload and edit again.'];
                DB::q('UPDATE backends SET name = ?, config = ?::jsonb, updated_at = now(), updated_by = ? WHERE id = ?',
                    [$b['name'], json_enc($b), Audit::actor(), $id]);
                Audit::log('backend.update', 'backend:' . $b['name']);
            } else {
                $id = Crypto::uuid();
                DB::q('INSERT INTO backends (id, name, config, updated_by) VALUES (?, ?, ?::jsonb, ?)',
                    [$id, $b['name'], json_enc($b), Audit::actor()]);
                Audit::log('backend.create', 'backend:' . $b['name']);
            }
            return [$id, null];
        });
    }

    /** Sites that use the backend (site default or route override). */
    public static function backendUsers(string $id): array
    {
        $users = [];
        foreach (self::sites() as $s) {
            $uses = ($s['proxy']['backend'] ?? '') === $id;
            foreach ($s['routes'] as $r) $uses = $uses || (($r['overrides']['backend'] ?? '') === $id);
            if ($uses) $users[] = $s['hosts'][0];
        }
        return $users;
    }

    public static function deleteBackend(string $id): ?string
    {
        if ($u = self::backendUsers($id)) return 'Still used by: ' . implode(', ', $u);
        $b = self::backend($id);
        DB::q('DELETE FROM backends WHERE id = ?', [$id]);
        Audit::log('backend.delete', 'backend:' . ($b['name'] ?? $id));
        return null;
    }

    /** The working copy as one document: what "Ready to apply" freezes into a revision. */
    public static function document(): array
    {
        $sites = [];
        foreach (self::sites() as $id => $s) { unset($s['updated_at']); $sites[] = $s; }
        $backends = [];
        foreach (self::backends() as $id => $b) { unset($b['updated_at']); $backends[] = $b; }
        usort($sites, fn($a, $b) => strcmp($a['id'], $b['id']));
        usort($backends, fn($a, $b) => strcmp($a['id'], $b['id']));
        return ['format' => 1, 'global' => Settings::global(), 'sites' => $sites, 'backends' => $backends,
            'cas' => PKI::trustedForRevision(), 'providers' => Signin::forRevision()];
    }

    /**
     * Validate a whole document: every object again, plus the cross-object rules. Used at
     * commit, and by the renderer on what it receives. Returns a list of messages.
     */
    public static function checkDocument(array $doc): array
    {
        $errors = [];
        if (($doc['format'] ?? null) !== 1) return ['Unknown document format.'];
        [, $ge] = Validate::global((array)($doc['global'] ?? []));
        foreach ($ge as $k => $v) $errors[] = "Settings → $k: $v";
        $backendIds = [];
        foreach ((array)($doc['backends'] ?? []) as $b) {
            if (!Validate::uuid($b['id'] ?? null)) { $errors[] = 'A backend has no valid id.'; continue; }
            [, $be] = Validate::backend($b);
            foreach ($be as $k => $v) $errors[] = "Backend {$b['name']} → $k: $v";
            $backendIds[] = $b['id'];
        }
        foreach ((array)($doc['cas'] ?? []) as $ca) {
            $info = is_string($ca['cert_pem'] ?? null) ? PKI::info($ca['cert_pem']) : null;
            if (!Validate::uuid($ca['id'] ?? null) || !$info) { $errors[] = 'A trusted CA is not a valid certificate.'; continue; }
            if (!$info['is_ca'] || !$info['self_signed']) $errors[] = "CA {$ca['name']} is not a self-signed CA certificate.";
            if (PKI::fingerprint($ca['cert_pem']) !== ($ca['fingerprint_sha256'] ?? '')) $errors[] = "CA {$ca['name']}: the fingerprint does not match.";
        }
        $providers = [];
        $hostSeen = [];
        foreach ((array)($doc['providers'] ?? []) as $p) {
            [, $pe] = Signin::validate($p);
            foreach ($pe as $k => $v) $errors[] = 'Sign-in provider ' . ($p['name'] ?? '?') . " → $k: $v";
            if (!Validate::uuid($p['id'] ?? null) || empty($p['port'])) $errors[] = 'A sign-in provider has no valid id or port.';
            else $providers[$p['id']] = $p;
            // the admin host name may equal one sign-in host (rendered as one server); two providers may not share one
            if (isset($hostSeen[$p['signin_host'] ?? ''])) $errors[] = "Sign-in host {$p['signin_host']} is used by two providers.";
            $hostSeen[$p['signin_host'] ?? ''] = true;
        }
        $hostSeen = array_filter($hostSeen, fn($k) => $k !== '', ARRAY_FILTER_USE_KEY);
        $portTls = [];
        $admin = $doc['global']['admin_host'] ?? '';
        foreach ((array)($doc['sites'] ?? []) as $s) {
            $name = $s['hosts'][0] ?? '?';
            if (!Validate::uuid($s['id'] ?? null)) { $errors[] = "Site $name has no valid id."; continue; }
            [, $se] = Validate::site($s, $backendIds);
            foreach ($se as $k => $v) $errors[] = "Site $name → $k: $v";
            $si = $s['access']['signin'] ?? ['mode' => 'none'];
            $usesSignin = ($si['mode'] ?? 'none') !== 'none';
            foreach ((array)($s['routes'] ?? []) as $r) $usesSignin = $usesSignin || ($r['overrides']['access']['signin'] ?? 'none') !== 'none';
            if ($usesSignin) {
                $p = $providers[$si['provider'] ?? ''] ?? null;
                if (!$p) $errors[] = "Site $name: its sign-in provider does not exist.";
                else foreach ((array)$s['hosts'] as $h) {
                    if (!Signin::under($h, $p['cookie_domain'])) $errors[] = "Site $name: $h is outside the cookie domain {$p['cookie_domain']} of provider {$p['name']}.";
                }
            }
            foreach ((array)($s['hosts'] ?? []) as $h) {
                if (isset($hostSeen[$h])) $errors[] = "Host $h is in two sites (or is a sign-in host).";
                if ($h === $admin) $errors[] = "Host $h is the admin host name.";
                $hostSeen[$h] = true;
            }
            if (!empty($s['enabled'])) {
                foreach ((array)($s['listeners'] ?? []) as $li) {
                    $p = (int)$li['port'];
                    if (isset($portTls[$p]) && $portTls[$p] !== (bool)$li['tls']) $errors[] = "Port $p is used with and without TLS.";
                    $portTls[$p] = (bool)$li['tls'];
                }
            }
        }
        return $errors;
    }
}
