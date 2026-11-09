<?php
// User administration for root's scripts (plan §9.5). Run as pspm with PSPM_ACTOR set.
//   user.php bootstrap                      first install: create "admin" if there is no user; prints the password
//   user.php create-admin <name>            prints a generated password
//   user.php reset-password <name> [--generate]   reads the new password from stdin unless --generate
//   user.php reset-otp <name>
//   user.php list
//   user.php unblock <address or network>
declare(strict_types=1);
require __DIR__ . '/../lib/bootstrap.php';
putenv('PSPM_ACTOR=' . (getenv('PSPM_ACTOR') ?: 'root (script)'));

function find_user(string $name): array
{
    $u = DB::one('SELECT * FROM users WHERE username = ?', [strtolower($name)]);
    if (!$u) { fwrite(STDERR, "no user '$name'. Existing: " . implode(', ', array_column(DB::all('SELECT username FROM users ORDER BY 1'), 'username')) . "\n"); exit(5); }
    return $u;
}

$cmd = $argv[1] ?? '';
$name = $argv[2] ?? '';
try {
    switch ($cmd) {
        case 'bootstrap':
            if ((int)DB::val('SELECT count(*) FROM users') > 0) { echo "users exist\n"; exit(0); }
            $pw = Crypto::password();
            DB::q("INSERT INTO users (username, role, password_hash, must_change_password) VALUES ('admin', 'admin', ?, true)", [password_hash($pw, PASSWORD_ARGON2ID)]);
            Audit::log('user.create', 'user:admin', ['role' => 'admin', 'bootstrap' => true]);
            echo "PASSWORD=$pw\n";
            break;
        case 'create-admin':
            if (!preg_match('/^[a-z0-9][a-z0-9._-]{1,31}$/', $name)) { fwrite(STDERR, "user name: 2–32 of a-z 0-9 . _ -\n"); exit(64); }
            $pw = Crypto::password();
            $exists = DB::one('SELECT id FROM users WHERE username = ?', [$name]);
            if ($exists) {
                DB::q("UPDATE users SET role = 'admin', disabled = false, password_hash = ?, must_change_password = true, failed_logins = 0, updated_at = now() WHERE id = ?",
                    [password_hash($pw, PASSWORD_ARGON2ID), $exists['id']]);
                Auth::endUserSessions((int)$exists['id']);
            } else {
                DB::q("INSERT INTO users (username, role, password_hash, must_change_password) VALUES (?, 'admin', ?, true)", [$name, password_hash($pw, PASSWORD_ARGON2ID)]);
            }
            Audit::log('user.create_admin', "user:$name");
            echo "PASSWORD=$pw\n";
            break;
        case 'reset-password':
            $u = find_user($name);
            if (in_array('--generate', $argv, true)) $pw = Crypto::password();
            else {
                $pw = rtrim((string)stream_get_contents(STDIN), "\r\n");
                if ($e = Auth::validPassword($pw, $u['username'])) { fwrite(STDERR, "$e\n"); exit(64); }
            }
            DB::q('UPDATE users SET password_hash = ?, must_change_password = true, failed_logins = 0, disabled = false, updated_at = now() WHERE id = ?',
                [password_hash($pw, PASSWORD_ARGON2ID), $u['id']]);
            $n = Auth::endUserSessions((int)$u['id']);
            Audit::log('user.reset_password', 'user:' . $u['username'], ['by_script' => true]);
            echo "sessions ended: $n\n";
            if (in_array('--generate', $argv, true)) echo "PASSWORD=$pw\n";
            break;
        case 'reset-otp':
            $u = find_user($name);
            DB::q('UPDATE users SET totp_secret_enc = NULL, totp_confirmed = false, totp_last_step = 0, failed_logins = 0, updated_at = now() WHERE id = ?', [$u['id']]);
            $n = Auth::endUserSessions((int)$u['id']);
            Audit::log('user.reset_otp', 'user:' . $u['username'], ['by_script' => true]);
            echo "OTP reset for {$u['username']}; sessions ended: $n. A new authenticator is enrolled at the next sign-in.\n";
            break;
        case 'list':
            foreach (DB::all('SELECT username, role, disabled, totp_confirmed, must_change_password, last_login_at FROM users ORDER BY username') as $u) {
                printf("%-20s %-9s %s%s%s last sign-in %s\n", $u['username'], $u['role'], $u['disabled'] ? 'disabled ' : '',
                    $u['totp_confirmed'] ? 'otp ' : 'no-otp ', $u['must_change_password'] ? 'pw-pending ' : '', $u['last_login_at'] ?? 'never');
            }
            break;
        case 'unblock':
            $c = IP::normCidr($name);
            if (!$c) { fwrite(STDERR, "not an address or network: $name\n"); exit(64); }
            $a = Access::unban($c); $b = Access::unblock($c);
            DB::q('UPDATE users SET failed_logins = 0');
            Audit::log('unblock', "ip:$c", ['by_script' => true]);
            $r = State::publish('banned', 'blocked');
            echo "lifted: $a login bans, $b blocks; nginx sync: " . ($r['ok'] ? 'ok' : 'not reachable (' . ($r['error'] ?? '') . '), applied at the next reload') . "\n";
            break;
        default:
            fwrite(STDERR, "usage: user.php bootstrap | create-admin <name> | reset-password <name> [--generate] | reset-otp <name> | list | unblock <ip>\n");
            exit(64);
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'error: ' . $e->getMessage() . "\n");
    exit(3);
}
