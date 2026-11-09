<?php
declare(strict_types=1);

/**
 * OpenAI-compatible chat API (OpenRouter by default), plan §15.3. Only pseudonymised
 * evidence is sent: no addresses, certificates, link tokens or user names.
 */
final class AI
{
    public const DEFAULTS = ['base_url' => 'https://openrouter.ai/api/v1', 'model' => '', 'key_enc' => '', 'mode' => 'enforce',
        'daily_cap' => 200, 'min_interval_min' => 15, 'confidence' => 0.85, 'analyse_authorised' => true, 'reaction_hours' => 24];

    public static function settings(): array
    {
        $s = Settings::get('ai', []);
        return array_replace(self::DEFAULTS, is_array($s) ? $s : []);
    }

    public static function configured(): bool
    {
        $s = self::settings();
        return $s['model'] !== '' && $s['key_enc'] !== '';
    }

    /** AI calls allowed now: configured, not in collect mode, under the daily cap. */
    public static function available(): bool
    {
        $s = self::settings();
        return self::configured() && $s['mode'] !== 'collect' && self::callsToday() < (int)$s['daily_cap'];
    }

    public static function callsToday(): int
    {
        return (int)DB::val("SELECT count(*) FROM ai_verdicts WHERE created_at > now() - interval '24 hours' AND outcome IS DISTINCT FROM 'not sent'");
    }

    /**
     * One chat call that must answer a JSON object. Returns the decoded object.
     * @throws RuntimeException on transport or format errors
     */
    public static function json(string $system, array $payload): array
    {
        $s = self::settings();
        $key = Crypto::open($s['key_enc']);
        $body = json_enc(['model' => $s['model'], 'temperature' => 0, 'response_format' => ['type' => 'json_object'],
            'messages' => [['role' => 'system', 'content' => $system], ['role' => 'user', 'content' => json_enc($payload)]]]);
        $ch = curl_init(rtrim($s['base_url'], '/') . '/chat/completions');
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 90,
            CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_HTTPHEADER => ['Content-Type: application/json', "Authorization: Bearer $key",
                'X-Title: PSPM security scan', 'HTTP-Referer: https://pspm.local/'],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
        $res = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        sodium_memzero($key);
        if ($res === false || $code !== 200) throw new RuntimeException("AI API: HTTP $code " . ($err ?: substr((string)$res, 0, 300)));
        $d = json_decode((string)$res, true);
        $content = $d['choices'][0]['message']['content'] ?? '';
        if (preg_match('/\{.*\}/s', (string)$content, $m)) $content = $m[0];
        $out = json_decode((string)$content, true);
        if (!is_array($out)) throw new RuntimeException('AI API: the answer is not a JSON object');
        return $out;
    }

    /** Stable pseudonyms within one call: ip-1, cert-2, user-3 … (the map stays local). */
    public static function pseudonymiser(): object
    {
        return new class {
            private array $map = [];
            private array $n = [];
            public function of(string $kind, string $value): string
            {
                $k = "$kind\0$value";
                if (!isset($this->map[$k])) { $this->n[$kind] = ($this->n[$kind] ?? 0) + 1; $this->map[$k] = $kind . '-' . $this->n[$kind]; }
                return $this->map[$k];
            }
            public function reverse(string $p): ?string
            {
                foreach ($this->map as $k => $v) if ($v === $p) return explode("\0", $k, 2)[1];
                return null;
            }
        };
    }

    /** Remove query values and long ids from a path before it leaves the box. */
    public static function scrubPath(string $p): string
    {
        $p = preg_replace('/\?.*$/', '?…', $p) ?? $p;
        $p = preg_replace('#/[0-9a-f]{16,}#i', '/{hex}', $p) ?? $p;
        $p = preg_replace('#/\d{4,}#', '/{n}', $p) ?? $p;
        $p = preg_replace('#/\.pspm/access/[^/]+#', '/.pspm/access/{token}', $p) ?? $p;
        return substr($p, 0, 200);
    }
}
