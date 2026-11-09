<?php
declare(strict_types=1);

/** Secrets at rest are sealed with /etc/pspm/app.key (libsodium secretbox). */
final class Crypto
{
    private static ?string $key = null;

    public static function key(): string
    {
        if (self::$key !== null) return self::$key;
        $f = PSPM_ETC . '/app.key';
        $raw = is_readable($f) ? trim((string)file_get_contents($f)) : '';
        $key = base64_decode($raw, true);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new RuntimeException('app.key is missing or invalid (' . $f . ')');
        }
        return self::$key = $key;
    }

    public static function seal(string $plain): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return 'v1:' . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, self::key()));
    }

    public static function open(string $sealed): string
    {
        if (!str_starts_with($sealed, 'v1:')) throw new RuntimeException('unknown sealed format');
        $raw = base64_decode(substr($sealed, 3), true);
        if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new RuntimeException('sealed value is damaged');
        }
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), self::key());
        if ($plain === false) throw new RuntimeException('sealed value cannot be opened (wrong app.key?)');
        return $plain;
    }

    /** URL-safe random token. */
    public static function token(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /** A readable generated password: four words and a number. */
    public static function password(): string
    {
        static $words = ['amber', 'birch', 'cobalt', 'delta', 'ember', 'fjord', 'glacier', 'harbor', 'island',
            'juniper', 'kestrel', 'lagoon', 'meadow', 'nickel', 'orchid', 'pepper', 'quartz', 'raven', 'saffron',
            'timber', 'umber', 'velvet', 'willow', 'yarrow', 'zephyr', 'basalt', 'cedar', 'dune', 'falcon',
            'granite', 'heron', 'iris', 'jasper', 'kelp', 'linden', 'marble', 'nova', 'onyx', 'pine', 'quill',
            'river', 'slate', 'tundra', 'violet', 'walnut', 'canyon', 'spruce', 'meteor', 'lantern', 'harvest'];
        $w = [];
        for ($i = 0; $i < 4; $i++) $w[] = $words[random_int(0, count($words) - 1)];
        return implode('-', $w) . '-' . random_int(10, 99);
    }
}
