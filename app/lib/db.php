<?php
declare(strict_types=1);

/** Thin PDO wrapper. PostgreSQL over the Unix socket shared with the container. */
final class DB
{
    private static ?PDO $pdo = null;

    public static function pdo(): PDO
    {
        if (self::$pdo) return self::$pdo;
        $env = self::env();
        $dsn = getenv('PSPM_DB_DSN') ?: sprintf('pgsql:host=%s;dbname=%s',
            pspm_conf('DB_SOCKET_DIR', '/run/pspm/postgres'), $env['POSTGRES_DB'] ?? 'pspm');
        self::$pdo = new PDO($dsn, $env['POSTGRES_USER'] ?? 'pspm', $env['POSTGRES_PASSWORD'] ?? '', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 5,
        ]);
        self::$pdo->exec("SET TIME ZONE 'UTC'");
        return self::$pdo;
    }

    /** The database credentials (KEY=value file shared with docker compose). */
    public static function env(): array
    {
        $env = [];
        $f = PSPM_ETC . '/db.env';
        if (is_readable($f)) {
            foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
                if ($l[0] !== '#' && str_contains($l, '=')) { [$k, $v] = explode('=', $l, 2); $env[trim($k)] = trim($v); }
            }
        }
        foreach (['POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_DB'] as $k) {
            if (($v = getenv("PSPM_$k")) !== false) $env[$k] = $v;
        }
        return $env;
    }

    public static function available(): bool
    {
        try { self::pdo()->query('SELECT 1'); return true; } catch (Throwable) { return false; }
    }

    public static function q(string $sql, array $params = []): PDOStatement
    {
        $st = self::pdo()->prepare($sql);
        foreach ($params as $k => $v) {
            $name = is_int($k) ? $k + 1 : (str_starts_with($k, ':') ? $k : ":$k");
            $type = match (true) { is_bool($v) => PDO::PARAM_BOOL, is_int($v) => PDO::PARAM_INT,
                $v === null => PDO::PARAM_NULL, default => PDO::PARAM_STR };
            $st->bindValue($name, is_array($v) ? json_enc($v) : $v, $type);
        }
        $st->execute();
        return $st;
    }

    public static function one(string $sql, array $p = []): ?array
    {
        $r = self::q($sql, $p)->fetch();
        return $r === false ? null : $r;
    }

    public static function all(string $sql, array $p = []): array
    {
        return self::q($sql, $p)->fetchAll();
    }

    public static function val(string $sql, array $p = []): mixed
    {
        $r = self::q($sql, $p)->fetchColumn();
        return $r === false ? null : $r;
    }

    /** Run $fn in a transaction; nested calls join the outer one. */
    public static function tx(callable $fn): mixed
    {
        $pdo = self::pdo();
        if ($pdo->inTransaction()) return $fn();
        $pdo->beginTransaction();
        try { $r = $fn(); $pdo->commit(); return $r; }
        catch (Throwable $e) { $pdo->rollBack(); throw $e; }
    }

    public static function schemaVersion(): int
    {
        try { return (int)self::val('SELECT coalesce(max(version), 0) FROM schema_migrations'); }
        catch (Throwable) { return 0; }
    }
}
