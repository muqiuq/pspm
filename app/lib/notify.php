<?php
declare(strict_types=1);

/**
 * E-mail notifications through an SMTP relay (plan §8.6). Events go to an outbox; the
 * notify timer sends them. Mails carry no secrets, tokens or action links.
 */
final class Notify
{
    public const CATEGORIES = ['findings' => 'Findings', 'health' => 'Health', 'accounts' => 'Accounts and PKI', 'changes' => 'Changes'];
    public const ROLE_DEFAULTS = ['admin' => ['findings', 'health', 'accounts'], 'operator' => ['findings'], 'viewer' => []];
    public const SMTP_DEFAULTS = ['host' => '', 'port' => 587, 'security' => 'starttls', 'user' => '', 'pass_enc' => '', 'from' => '', 'extra' => []];

    public static function smtp(): array
    {
        $s = Settings::get('smtp', []);
        return array_replace(self::SMTP_DEFAULTS, is_array($s) ? $s : []);
    }

    public static function configured(): bool { return self::smtp()['host'] !== ''; }

    /** Categories a user receives: their choice, or the defaults of their role. */
    public static function userCategories(array $u): array
    {
        $n = is_string($u['notify'] ?? null) ? (json_dec($u['notify']) ?? []) : ($u['notify'] ?? []);
        if (in_array('none', $n, true)) return [];
        return $n ?: (self::ROLE_DEFAULTS[$u['role']] ?? []);
    }

    public static function recipients(string $category): array
    {
        $to = [];
        foreach (DB::all("SELECT username, role, email, notify FROM users WHERE NOT disabled AND email IS NOT NULL AND email <> ''") as $u) {
            if (in_array($category, self::userCategories($u), true)) $to[] = $u['email'];
        }
        if (in_array($category, ['findings', 'health'], true)) foreach (self::smtp()['extra'] as $e) $to[] = $e;
        return array_values(array_unique($to));
    }

    /** Queue a notification. The same dedupe key is sent at most once per 6 hours. */
    public static function event(string $category, string $subject, string $body, ?string $dedupe = null, int $delaySecs = 0): void
    {
        try {
            if (!self::configured()) return;
            $to = self::recipients($category);
            if (!$to) return;
            if ($dedupe && DB::val("SELECT 1 FROM notification_outbox WHERE dedupe_key = ? AND created_at > now() - interval '6 hours'", [$dedupe])) return;
            $host = pspm_conf('BOX_FQDN', gethostname() ?: 'pspm');
            $ui = Settings::global()['admin_host'] !== '' ? 'https://' . Settings::global()['admin_host'] . '/' : "the PSPM UI on $host";
            $body = rtrim($body) . "\n\n-- \nPSPM on $host · open $ui to act. This mail contains no links that change anything.\n";
            DB::q('INSERT INTO notification_outbox (category, dedupe_key, subject, body, recipients, send_after) VALUES (?, ?, ?, ?, ?::jsonb, now() + make_interval(secs => ?))',
                [$category, $dedupe, '[PSPM] ' . mb_substr($subject, 0, 150), $body, json_enc($to), $delaySecs]);
        } catch (Throwable $e) {
            error_log('PSPM notify: ' . $e->getMessage());
        }
    }

    /** Audit events that also go out by e-mail. */
    public static function fromAudit(string $action, ?string $object, array $details, string $actor): void
    {
        $cat = match (true) {
            (bool)preg_match('/^(user\.(create|create_admin|role|reset_password|reset_otp|disable|delete)|ca\.|cert\.issue)/', $action) => 'accounts',
            (bool)preg_match('/^(revision\.commit|apply\.)/', $action) => 'changes',
            default => null,
        };
        if (!$cat) return;
        $txt = "$actor: $action" . ($object ? " ($object)" : '');
        foreach ($details as $k => $v) if (is_scalar($v) && !preg_match('/pass|secret|token|key/i', (string)$k)) $txt .= "\n  $k: $v";
        self::event($cat, $action . ($object ? " $object" : ''), $txt);
    }

    // ---------------------------------------------------------------- sending

    /** Send what is due. Returns [sent, failed]. */
    public static function send(): array
    {
        if (!self::configured()) return [0, 0];
        $sentHour = (int)DB::val("SELECT count(*) FROM notification_outbox WHERE status = 'sent' AND sent_at > now() - interval '1 hour'");
        $due = DB::all("SELECT * FROM notification_outbox WHERE status = 'pending' AND send_after <= now() ORDER BY id LIMIT 200");
        if (!$due) return [0, 0];
        $sent = $failed = 0;
        // more than 5 mails within 10 minutes become one digest
        $recent = (int)DB::val("SELECT count(*) FROM notification_outbox WHERE created_at > now() - interval '10 minutes'");
        if (count($due) > 5 || $recent > 5) {
            $byTo = [];
            foreach ($due as $m) $byTo[implode(',', json_dec($m['recipients']))][] = $m;
            foreach ($byTo as $to => $msgs) {
                $body = count($msgs) . " notifications:\n\n" . implode("\n\n", array_map(fn($m) => '* ' . $m['subject'] . "\n" . trim(explode("\n-- \n", $m['body'])[0]), $msgs));
                $ok = $sentHour < 50 && self::mail(explode(',', $to), '[PSPM] ' . count($msgs) . ' notifications', $body, $err);
                $ids = '{' . implode(',', array_column($msgs, 'id')) . '}';
                if ($ok) { DB::q("UPDATE notification_outbox SET status = 'digested', sent_at = now() WHERE id = ANY(?::bigint[])", [$ids]); $sent++; $sentHour++; }
                else self::retry($msgs, $err ?? 'hourly cap reached');
                if (!$ok) $failed++;
            }
            return [$sent, $failed];
        }
        foreach ($due as $m) {
            if ($sentHour >= 50) {
                DB::q("UPDATE notification_outbox SET status = 'dropped', last_error = 'hourly cap' WHERE id = ?", [$m['id']]);
                if (!DB::val("SELECT 1 FROM notification_outbox WHERE dedupe_key = 'paused' AND created_at > now() - interval '1 hour'")) {
                    self::event('health', 'Notifications paused', 'More than 50 mails within an hour: further notifications are dropped for now. See the dashboard.', 'paused');
                }
                continue;
            }
            if (self::mail(json_dec($m['recipients']), $m['subject'], $m['body'], $err)) {
                DB::q("UPDATE notification_outbox SET status = 'sent', sent_at = now(), attempts = attempts + 1 WHERE id = ?", [$m['id']]);
                $sent++; $sentHour++;
            } else {
                self::retry([$m], $err);
                $failed++;
            }
        }
        return [$sent, $failed];
    }

    private static function retry(array $msgs, string $err): void
    {
        foreach ($msgs as $m) {
            $a = (int)$m['attempts'] + 1;
            $st = strtotime($m['created_at']) < time() - 86400 ? 'failed' : 'pending';
            DB::q('UPDATE notification_outbox SET attempts = ?, last_error = ?, status = ?, send_after = now() + make_interval(secs => ?) WHERE id = ?',
                [$a, mb_substr($err, 0, 500), $st, min(3600, 60 * 2 ** min($a, 6)), $m['id']]);
        }
    }

    public static function mail(array $to, string $subject, string $body, ?string &$error = null): bool
    {
        require_once PSPM_APP . '/vendor/phpmailer/Exception.php';
        require_once PSPM_APP . '/vendor/phpmailer/PHPMailer.php';
        require_once PSPM_APP . '/vendor/phpmailer/SMTP.php';
        $s = self::smtp();
        try {
            $m = new PHPMailer\PHPMailer\PHPMailer(true);
            $m->isSMTP();
            $m->Host = $s['host'];
            $m->Port = (int)$s['port'];
            $m->Timeout = 20;
            $m->CharSet = 'UTF-8';
            if ($s['security'] === 'tls') $m->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
            elseif ($s['security'] === 'starttls') $m->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            else { $m->SMTPSecure = ''; $m->SMTPAutoTLS = false; }
            $m->SMTPOptions = ['ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false]];
            if ($s['user'] !== '' && $s['security'] !== 'none') {
                $m->SMTPAuth = true;
                $m->Username = $s['user'];
                $m->Password = $s['pass_enc'] ? Crypto::open($s['pass_enc']) : '';
            }
            $from = $s['from'] ?: 'pspm@' . (pspm_conf('BOX_FQDN', gethostname() ?: 'localhost'));
            $m->setFrom($from, 'PSPM');
            foreach ($to as $t) $m->addAddress($t);
            $m->Subject = $subject;
            $m->Body = $body;
            $m->isHTML(false);
            $m->send();
            return true;
        } catch (Throwable $e) {
            $error = $e->getMessage();
            return false;
        }
    }

    // ---------------------------------------------------------------- health (red tiles → mail, green again → resolved)

    public static function health(): void
    {
        $checks = [];
        foreach (Live::certs() as $c) {
            $d = (int)floor((strtotime($c['not_after']) - time()) / 86400);
            $checks["cert:{$c['name']}"] = $d < 7 ? ['red', "Certificate {$c['name']} expires in $d days; renewal is not working (sudo certbot renew --dry-run)."] : null;
        }
        $fw = Status::read('firewall');
        $age = Status::age('firewall');
        $checks['agent'] = $age === null || $age > 300 ? ['red', 'The PSPM agent has not reported for ' . ($age === null ? 'ever' : human_secs($age)) . ' (systemctl status pspm-agent).'] : null;
        $checks['firewall'] = ($p = Status::firewallProblem($fw)) ? ['red', $p] : null;
        $disk = Status::diskFree('/var');
        $checks['disk'] = $disk && $disk['pct_used'] > 90 ? ['red', "The disk is {$disk['pct_used']}% full."] : null;
        $drift = array_filter(Live::currentRelease() ? Live::drift() : [], fn($d) => in_array($d['level'], ['red', 'amber'], true) && $d['check'] !== 'loaded');
        $checks['drift'] = $drift ? ['red', implode(' ', array_column($drift, 'message'))] : null;
        $breaker = (Settings::get('scan', [])['breaker_tripped'] ?? false);
        $checks['breaker'] = $breaker ? ['red', 'The security scan switched itself to dry-run (circuit breaker). Check the blocks and switch back on the Security page.'] : null;
        foreach (DB::all("SELECT id, name, last_status FROM blocklists WHERE enabled") as $b) {
            $st = json_dec($b['last_status']) ?? [];
            $checks["blocklist:{$b['id']}"] = ($st['level'] ?? '') === 'red' ? ['red', "Blocklist {$b['name']}: " . ($st['message'] ?? 'failing')] : null;
        }
        foreach (Signin::providers() as $p) {
            if (!Signin::users($p['id'])) continue;
            $checks["signin:{$p['id']}"] = Signin::ready((int)$p['port']) === false ? ['red', "Sign-in {$p['name']} is not running; sites that require it answer 503."] : null;
        }
        $backups = glob(PSPM_VAR . '/backups/nightly-*', GLOB_ONLYDIR) ?: [];
        rsort($backups);
        $checks['backup'] = $backups && time() - filemtime($backups[0]) > 2 * 86400 ? ['red', 'The newest nightly backup is older than two days.'] : null;
        $failedMail = (int)DB::val("SELECT count(*) FROM notification_outbox WHERE status IN ('pending', 'failed') AND attempts > 2");
        $checks['mail'] = $failedMail > 0 ? ['red', "$failedMail mails could not be delivered (SMTP)."] : null;

        $cur = [];
        foreach (DB::all('SELECT * FROM health_state') as $r) $cur[$r['key']] = $r;
        foreach ($checks as $key => $c) {
            $was = $cur[$key]['level'] ?? 'green';
            if ($c && $was !== 'red') {
                DB::q("INSERT INTO health_state (key, level, message, since) VALUES (?, 'red', ?, now()) ON CONFLICT (key) DO UPDATE SET level = 'red', message = excluded.message, since = now()", [$key, $c[1]]);
                if ($key !== 'mail') self::event('health', 'Problem: ' . mb_substr($c[1], 0, 80), $c[1], "health:$key:red:" . date('YmdH'));
            } elseif (!$c && $was === 'red') {
                DB::q("UPDATE health_state SET level = 'green', message = 'resolved', since = now() WHERE key = ?", [$key]);
                self::event('health', 'Resolved: ' . mb_substr($cur[$key]['message'], 0, 80), 'Resolved: ' . $cur[$key]['message'], "health:$key:green:" . date('YmdH'));
            }
        }
    }
}
