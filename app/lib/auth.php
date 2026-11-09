<?php
declare(strict_types=1);

/**
 * Users, sessions, CSRF. Sessions live in PostgreSQL (plan §9.4): cookie __Host-pspm,
 * 1 h idle, 12 h at most. A session passes the stages 'password' (signed in with the
 * password, further steps pending) and 'full'.
 */
final class Auth
{
    public const COOKIE = '__Host-pspm';
    public const IDLE = 3600;
    public const MAX = 43200;
    public const PENDING_MAX = 900;   // a session waiting for OTP or enrolment
    public const REAUTH = 300;
    public const ROLES = ['viewer' => 1, 'operator' => 2, 'admin' => 3];

    private static bool $loaded = false;
    private static ?array $session = null;
    private static ?array $user = null;

    public static function load(): void
    {
        if (self::$loaded) return;
        self::$loaded = true;
        $token = $_COOKIE[self::COOKIE] ?? '';
        if ($token === '' || strlen($token) > 100) return;
        $s = DB::one('SELECT s.*, extract(epoch FROM now() - s.created_at) AS age,
                             extract(epoch FROM now() - s.last_seen_at) AS idle
                      FROM sessions s WHERE id_hash = ?', [hash('sha256', $token)]);
        if (!$s) return;
        $max = $s['stage'] === 'full' ? self::MAX : self::PENDING_MAX;
        $u = DB::one('SELECT * FROM users WHERE id = ?', [$s['user_id']]);
        if (!$u || $u['disabled'] || $s['age'] > $max || $s['idle'] > self::IDLE) {
            DB::q('DELETE FROM sessions WHERE id_hash = ?', [$s['id_hash']]);
            return;
        }
        if ($s['idle'] > 60) DB::q('UPDATE sessions SET last_seen_at = now() WHERE id_hash = ?', [$s['id_hash']]);
        self::$session = $s;
        self::$user = $u;
    }

    public static function user(): ?array { self::load(); return self::$user; }

    /** Reload the signed-in user after changing their row. */
    public static function refresh(): void
    {
        self::$loaded = false; self::$session = null; self::$user = null;
        self::load();
    }
    public static function session(): ?array { self::load(); return self::$session; }
    public static function full(): bool { return (self::session()['stage'] ?? '') === 'full'; }

    public static function can(string $role): bool
    {
        $u = self::user();
        return $u && self::full() && self::ROLES[$u['role']] >= self::ROLES[$role];
    }

    /** Where a signed-in user has to go next before the UI opens. */
    public static function nextStep(): string
    {
        $u = self::user();
        if (!$u) return '/login';
        if (self::full()) return '/';
        if ($u['must_change_password']) return '/login/password';
        if (!$u['totp_confirmed']) return '/login/enrol';
        return '/login/otp';
    }

    /** Pages call this first. Viewers and up may read; writes ask for more. */
    public static function require(string $role = 'viewer'): array
    {
        if (!self::user()) redirect('/login?next=' . rawurlencode($_SERVER['REQUEST_URI'] ?? '/'));
        if (!self::full()) redirect(self::nextStep());
        if (!self::can($role)) { http_response_code(403); page_error(403, 'Your role does not allow this.'); }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') self::checkCsrf();
        return self::$user;
    }

    // ---- sign-in

    /** Returns [ok, message]. On success a 'password' stage session exists. */
    public static function attemptPassword(string $username, string $password): array
    {
        $ip = IP::remote();
        if (Access::isBanned($ip)) return [false, 'Sign-in from your address is blocked for now.'];
        $username = strtolower(trim($username));
        $u = DB::one('SELECT * FROM users WHERE username = ?', [$username]);
        if ($u && ($wait = self::delayLeft($u)) > 0) {
            return [false, "Too many failed attempts. Try again in $wait seconds."];
        }
        // Verify against a throwaway hash when the user does not exist, so timing reveals nothing.
        $hash = $u['password_hash'] ?? password_hash(random_bytes(8), PASSWORD_ARGON2ID);
        $ok = password_verify($password, $hash) && $u && !$u['disabled'];
        if (!$ok) {
            self::recordFailure($ip, $username, $u);
            return [false, 'Wrong user name or password.'];
        }
        if (password_needs_rehash($u['password_hash'], PASSWORD_ARGON2ID)) {
            DB::q('UPDATE users SET password_hash = ? WHERE id = ?', [password_hash($password, PASSWORD_ARGON2ID), $u['id']]);
        }
        self::startSession((int)$u['id'], 'password');
        return [true, ''];
    }

    public static function verifyOtp(string $code): bool
    {
        $u = self::user();
        if (!$u || !$u['totp_secret_enc']) return false;
        if (($wait = self::delayLeft($u)) > 0) return false;
        $secret = Crypto::open($u['totp_secret_enc']);
        $step = Totp::verify($secret, $code, (int)$u['totp_last_step']);
        if ($step === null) { self::recordFailure(IP::remote(), $u['username'], $u); return false; }
        DB::q('UPDATE users SET totp_last_step = ? WHERE id = ?', [$step, $u['id']]);
        return true;
    }

    /** Password and OTP both passed: the session becomes 'full' under a new id. */
    public static function completeLogin(): void
    {
        $u = self::user();
        DB::q('DELETE FROM sessions WHERE id_hash = ?', [self::$session['id_hash']]);
        DB::q('UPDATE users SET failed_logins = 0, last_login_at = now(), last_login_ip = ? WHERE id = ?',
            [IP::remote(), $u['id']]);
        self::startSession((int)$u['id'], 'full');
        Audit::log('login', 'user:' . $u['username']);
    }

    private static function delayLeft(array $u): int
    {
        $n = (int)$u['failed_logins'];
        if ($n < 3 || !$u['last_failed_at']) return 0;
        $delay = min(300, 2 ** min(9, $n - 3));               // 1 s, 2 s, 4 s … 5 min; never a permanent lock
        $since = time() - (new DateTimeImmutable($u['last_failed_at']))->getTimestamp();
        return max(0, $delay - $since);
    }

    private static function recordFailure(string $ip, string $username, ?array $u): void
    {
        DB::q('INSERT INTO login_failures (ip, username) VALUES (?, ?)', [$ip, substr($username, 0, 64)]);
        if ($u) DB::q('UPDATE users SET failed_logins = failed_logins + 1, last_failed_at = now() WHERE id = ?', [$u['id']]);
        $cfg = Settings::get('login');
        $n = (int)DB::val("SELECT count(*) FROM login_failures WHERE ip = ? AND at > now() - make_interval(secs => ?)",
            [$ip, (int)$cfg['window_secs']]);
        if ($n >= (int)$cfg['max_failures'] && !IP::neverBlocked($ip)) {
            Access::ban($ip, "$n failed sign-ins", (int)$cfg['ban_secs']);
        }
    }

    public static function startSession(int $userId, string $stage): void
    {
        $token = Crypto::token(32);
        DB::q('INSERT INTO sessions (id_hash, user_id, stage, csrf, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
            [hash('sha256', $token), $userId, $stage, Crypto::token(24), IP::remote(),
             substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200)]);
        setcookie(self::COOKIE, $token, ['expires' => 0, 'path' => '/', 'secure' => true,
            'httponly' => true, 'samesite' => 'Strict']);
        self::$loaded = false; self::$session = null; self::$user = null;
        $_COOKIE[self::COOKIE] = $token;
        self::load();
    }

    public static function logout(): void
    {
        if ($s = self::session()) DB::q('DELETE FROM sessions WHERE id_hash = ?', [$s['id_hash']]);
        setcookie(self::COOKIE, '', ['expires' => 1, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
        self::$session = self::$user = null;
    }

    public static function endUserSessions(int $userId): int
    {
        return DB::q('DELETE FROM sessions WHERE user_id = ?', [$userId])->rowCount();
    }

    // ---- CSRF and re-authentication

    public static function csrf(): string { return self::session()['csrf'] ?? ''; }

    public static function checkCsrf(): void
    {
        $t = $_POST['_csrf'] ?? '';
        if (!is_string($t) || !self::session() || !hash_equals(self::csrf(), $t)) {
            http_response_code(400);
            page_error(400, 'The form expired. Reload the page and try again.');
        }
    }

    public static function reauthFresh(): bool
    {
        $r = self::session()['reauth_at'] ?? null;
        return $r && time() - (new DateTimeImmutable($r))->getTimestamp() < self::REAUTH;
    }

    /** For import, export, user management, CAs: password + TOTP again within 5 minutes. */
    public static function requireReauth(): void
    {
        if (!self::reauthFresh()) redirect('/reauth?next=' . rawurlencode($_SERVER['REQUEST_URI'] ?? '/'));
    }

    public static function markReauth(): void
    {
        DB::q('UPDATE sessions SET reauth_at = now() WHERE id_hash = ?', [self::session()['id_hash']]);
    }

    public static function validPassword(string $pw, string $username): ?string
    {
        if (strlen($pw) < 12) return 'At least 12 characters.';
        if (strlen($pw) > 200) return 'At most 200 characters.';
        if (stripos($pw, $username) !== false) return 'The password must not contain the user name.';
        return null;
    }
}

function redirect(string $to, int $code = 303): never
{
    header('Location: ' . $to, true, $code);
    exit;
}
