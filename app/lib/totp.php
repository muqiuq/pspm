<?php
declare(strict_types=1);

/** RFC 6238 TOTP: SHA-1, 6 digits, 30 s steps, ±1 step tolerance. */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function newSecret(): string
    {
        return self::base32Encode(random_bytes(20)); // 160 bits
    }

    public static function base32Encode(string $bin): string
    {
        $bits = '';
        foreach (str_split($bin) as $c) $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        $out = '';
        foreach (str_split($bits, 5) as $chunk) $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0'))];
        return $out;
    }

    public static function base32Decode(string $b32): string
    {
        $b32 = strtoupper(preg_replace('/[\s=-]/', '', $b32) ?? '');
        $bits = '';
        foreach (str_split($b32) as $c) {
            $v = strpos(self::ALPHABET, $c);
            if ($v === false) throw new InvalidArgumentException('invalid base32');
            $bits .= str_pad(decbin($v), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) if (strlen($byte) === 8) $out .= chr(bindec($byte));
        return $out;
    }

    public static function code(string $secretB32, int $step, int $digits = 6): string
    {
        return self::hotp(self::base32Decode($secretB32), $step, $digits);
    }

    public static function hotp(string $key, int $counter, int $digits = 6, string $algo = 'sha1'): string
    {
        $msg = pack('J', $counter);
        $hash = hash_hmac($algo, $msg, $key, true);
        $off = ord($hash[strlen($hash) - 1]) & 0x0f;
        $bin = ((ord($hash[$off]) & 0x7f) << 24) | (ord($hash[$off + 1]) << 16)
             | (ord($hash[$off + 2]) << 8) | ord($hash[$off + 3]);
        return str_pad((string)($bin % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Check a code. Returns the matched time step, or null. A step at or below $lastStep
     * was already used and is refused (replay protection).
     */
    public static function verify(string $secretB32, string $code, int $lastStep, ?int $now = null): ?int
    {
        $code = preg_replace('/\D/', '', $code) ?? '';
        if (strlen($code) !== 6) return null;
        $step = intdiv($now ?? time(), 30);
        foreach ([0, -1, 1] as $d) {
            $s = $step + $d;
            if ($s > $lastStep && hash_equals(self::code($secretB32, $s), $code)) return $s;
        }
        return null;
    }

    public static function uri(string $secretB32, string $account, string $issuer): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account) . '?secret=' . $secretB32
            . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
    }
}
