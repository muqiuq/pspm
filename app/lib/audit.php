<?php
declare(strict_types=1);

final class Audit
{
    /** Who is acting: the signed-in user, or root through a script (PSPM_ACTOR). */
    public static function actor(): string
    {
        if ($a = getenv('PSPM_ACTOR')) return $a;
        return Auth::user()['username'] ?? 'system';
    }

    public static function log(string $action, ?string $object = null, array $details = []): void
    {
        $ip = PHP_SAPI === 'cli' ? null : IP::remote();
        DB::q('INSERT INTO audit_log (actor, ip, action, object, details) VALUES (?, ?, ?, ?, ?)',
            [self::actor(), $ip, $action, $object, $details]);
        if (class_exists('Notify', false)) Notify::fromAudit($action, $object, $details, self::actor());
    }
}
